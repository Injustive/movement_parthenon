from utils.utils import (retry, check_res_status, get_utc_now,
                         get_data_lines, sleep, Logger,
                         read_json, Contract, generate_random_hex_string,
                         get_utc_now, approve_asset, asset_balance, get_decimals, approve_if_insufficient_allowance,
                         generate_random, retry_js, JSException, ModernTask, get_session, get_gas_params, estimate_gas)
from decimal import Decimal, ROUND_DOWN
from ..task import Task
import random
from aptos_sdk.transactions import EntryFunction, TransactionArgument, Serializer
from aptos_sdk.type_tag import TypeTag, StructTag
from ..utils import FailedSimulatedTransaction, COINS
from aptos_sdk.account import AccountAddress
import base64
import json
from ..utils import retry as api_retry
from ..config import MAX_SWAP_TIMES


LPs = {
    "USDC": "0xe998ed2e3bb061a739b174b4b84099a85bc63748ff83136246a64cf3d62233b9",
    "USDT": "0x17efbc052ca2169dcc85e2540025ca4c2f17057976990c589daadc302345b014"
}

class YuzuTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    @api_retry
    async def get_token_out(self, routes, token_in, amount_in):
        pools_bytes = await self.aptos_client.view(function="0x46566b4a16a1261ab400ab5b9067de84ba152b5eb4016b217187f2a2ca980c5a::router::quote_swap_exact_in_multi_hops",
                                                   type_arguments=[],
                                                   arguments=[self.aptos_address,
                                                              [{"inner": route} for route in routes],
                                                              token_in,
                                                              str(amount_in)])
        return int(json.loads(pools_bytes.decode("utf-8"))[0])

    @retry()
    @check_res_status()
    async def get_routes(self, token_in, token_out):
        url = 'https://mainnet-api.yuzu.finance/v1/routes'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://app.yuzu.finance',
            'priority': 'u=1, i',
            'referer': 'https://app.yuzu.finance/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        params = {
            'tokenIn': token_in,
            'tokenOut': token_out
        }
        return await self.session.get(url, headers=headers, params=params)

    @staticmethod
    def find_routes(routes,
                    token_in,
                    token_out,
                    return_all=False):
        tin = token_in.lower()
        tout = token_out.lower()
        matches = []
        for candidate_route in routes:
            current = tin
            addresses = []
            valid = True
            for pool in candidate_route:
                t0 = str(pool["token0"]).lower()
                t1 = str(pool["token1"]).lower()
                if current not in (t0, t1):
                    valid = False
                    break
                addresses.append(pool["address"])
                current = t1 if current == t0 else t0
            if valid and current == tout:
                matches.append(addresses)
        if return_all:
            return matches
        return matches[0] if matches else None

    @staticmethod
    def normalize_addr(addr):
        h = addr[2:].lower()
        if len(h) % 2 == 1:
            h = "0" + h
        return "0x" + h.zfill(64)

    async def get_swap_payload(self, routes, token_in_addr, amount_in, amount_out):
        CONTRACT = "0x46566b4a16a1261ab400ab5b9067de84ba152b5eb4016b217187f2a2ca980c5a::scripts"
        FN_NAME = "swap_exact_fa_for_fa_multi_hops"
        ARGS = [TransactionArgument([AccountAddress.from_str(self.normalize_addr(route)) for route in routes], Serializer.sequence_serializer(Serializer.struct)),
                TransactionArgument(AccountAddress.from_str(self.normalize_addr(token_in_addr)), Serializer.struct),
                TransactionArgument(amount_in, Serializer.u64),
                TransactionArgument(amount_out, Serializer.u64),
                TransactionArgument(AccountAddress.from_str(self.aptos_address), Serializer.struct)]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_swap(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully swapped Yuzu!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def swap_all_to_move(self):
        self.logger.info("Swapping all to MOVE...")
        balance = await self.get_all_balance()
        for coin in balance:
            for coin_etalon in COINS:
                if coin_etalon in coin:
                    if coin != 'MOVE' and coin != 'cvMOVE' and balance[coin][0]['raw_amount']:
                        await self.swap(token_in=coin_etalon,
                                        token_out="MOVE",
                                        amount_in=balance[coin][0]['raw_amount'])
        await sleep(10, 30)

    async def swap_n(self, n_swaps=1, amounts=(1, 10), ensure_balance=5, check=0):
        if check:
            already_swapped = await self.db_manager.get_column(self.client.key, 'swaps_n')
            if already_swapped >= check:
                self.logger.info(f"Already swapped more than {MAX_SWAP_TIMES} times!")
                return
        await self.swap_all_to_move()
        await self.check_move_balance(min_balance=ensure_balance)
        swap_amount = int(round(random.uniform(*amounts), 2) * 10 ** 8)
        swap_from = "MOVE"
        swap_to = random.choice([coin for coin in COINS if coin != "MOVE"])
        for i in range(1, n_swaps + 1):
            if check:
                already_swapped = await self.db_manager.get_column(self.client.key, 'swaps_n')
                if already_swapped >= check:
                    self.logger.info(f"Already swapped more than {MAX_SWAP_TIMES} times!")
                    return
            self.logger.info(f"Yuzu swapping {i}/{n_swaps}...")
            swap_amount = await self.swap(token_in=swap_from,
                                          token_out=swap_to,
                                          amount_in=swap_amount)
            swap_from = swap_to
            swap_to = random.choice([coin for coin in COINS if coin != swap_from])
            await sleep(10, 30)

    async def swap(self, token_in, token_out, amount_in):
        amount_in_human = amount_in / 10 ** COINS[token_in]['decimals']
        token_in_addr = COINS[token_in].get("short_address", COINS[token_in]["address"])
        token_out_addr = COINS[token_out].get("short_address", COINS[token_out]["address"])
        routes = (await self.get_routes(token_in_addr, token_out_addr)).json()['data']
        routes = self.find_routes(routes, token_in_addr, token_out_addr, return_all=True)
        best = 0
        route_for_swap = None
        for route in routes:
            token_out_amount = await self.get_token_out(route, token_in_addr, amount_in)
            if token_out_amount > best:
                best = token_out_amount
                route_for_swap = route
        swap_payload = await self.get_swap_payload(route_for_swap, token_in_addr, amount_in, best)
        amount_out_human = best / 10 ** COINS[token_out]['decimals']
        self.logger.info(f"Swapping {amount_in_human} {token_in} - {amount_out_human} {token_out}...")
        await self.complete_swap(swap_payload, _raise=True)
        await self.db_manager.add_n_swaps(self.client.key)
        return best

    @retry()
    @check_res_status()
    async def prices(self):
        url = 'https://mainnet-api.yuzu.finance/v1/prices'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://app.yuzu.finance',
            'priority': 'u=1, i',
            'referer': 'https://app.yuzu.finance/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent'],
        }
        params = {
            'tokenIds': '0xa',
        }
        return await self.session.get(url, params=params, headers=headers)

    def get_add_liquidity_payload(self, token_in, move_amount, coin_amount):
        CONTRACT = "0x46566b4a16a1261ab400ab5b9067de84ba152b5eb4016b217187f2a2ca980c5a::scripts"
        FN_NAME = "add_liquidity_one_coin"
        ARGS = [TransactionArgument(AccountAddress.from_str(self.normalize_addr(LPs[token_in])), Serializer.struct),
                TransactionArgument(0, Serializer.u64),
                TransactionArgument(36, Serializer.u32),
                TransactionArgument(887236, Serializer.u32),
                TransactionArgument(move_amount, Serializer.u64),
                TransactionArgument(coin_amount, Serializer.u64),
                TransactionArgument((move_amount + 50) // 100, Serializer.u64),
                TransactionArgument((coin_amount + 50) // 100, Serializer.u64),]
        TYPE_ARGS = [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))]
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_add_liquidity(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully added liquidity to Yuzu!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    @retry()
    @check_res_status()
    async def get_positions(self):
        url = 'https://rpc.sentio.xyz/movement-indexer/v1/graphql'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'content-type': 'application/json',
            'origin': 'https://app.yuzu.finance',
            'priority': 'u=1, i',
            'referer': 'https://app.yuzu.finance/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.session.headers['User-Agent'],
            'x-aptos-client': 'aptos-typescript-sdk/1.33.1',
            'x-aptos-typescript-sdk-origin-method': 'queryIndexer',
        }
        json_data = {
            'query': '\n        query MyQuery {\n          current_token_ownerships_v2(\n            where: {current_token_data: {current_collection: {creator_address: {_in: ["0xe15aa41271ae4b7a2adb2cc2bbf3c4b0febd3f55526c27d3cdada9f1a54a14e7","0xe998ed2e3bb061a739b174b4b84099a85bc63748ff83136246a64cf3d62233b9","0x17efbc052ca2169dcc85e2540025ca4c2f17057976990c589daadc302345b014","0x05aac8966e6f70d7027d8d98663057072ddef93645959ad6a15377bc314e1ae1","0x70fb1f546f1593ba50408a05266723ce5fd19a6df6ba7e5e5bd805f969cfb07e","0x66e275944ab671128af9513e6b0c6de59ee980333b9c2e15d2fcbc98cd970eff","0x4b7a6a9262432f8b2fab68dcdc0392b2d0a487a35f3a966479a8755ad02426c1","0xee90e858b84816234fbdf8fba2a19f9447cd98593665f6662967b61fc17a0ab2","0xec070f01848c020b84bdc5711cfbb70f99265c23378a53730ee7335e4e7099e6","0x83cd9589d6b35dc678d5693fc88f222a1da9439bda647cce1aacced58c2852df","0x8c4c674cb602a70f1f1c307c48b0c8afb0c1a8d909763a32ac06e8dbd6e7d978","0x00d2a84012ac9bec8a87ad2986f5268569355be4ca7445f367465ea45da76632","0x80509d698bc712fc1ab4490431459e31dd1686c38b0b6b3d76a901b0e32d891f","0x8282f3de9b458db67f6c6f405d70a0098657247383f3c43e330fcfeaedb0fca7","0xde2db227d599d9446a76283ff63df30e3a02c8d1acc5cde86fda667e5bdc1595","0xbc4a95cddaaf1f9598a73a979ff6315e0d0ea52b2f1dc994b73680e547e56812","0x6138a452416e2dce9db44f2cb92bbac1dd32698c32d609acaf7f4340735b1b09","0xf024e2a0ff59e12dddb38fbec2c46df29ef3446417447411452329863b3136ba","0x0dde10cfa502cc69ad43f6007083c0792f0fc4e16e28aa02ee711cdad12b6c31","0xbebdfc330ac3b3653700cca6d5b5eb1dd11496fe2b8fad7969875fa8540e3095","0xc7693133722fec606ee341a49ead2ccecf72b5f15cee3daa4973415e7251f90f","0xde6f37817c224ca856fb149710795be188bbcc5b5c1da910963c4dca6d42a7d6","0xa051fbba9746c55559dabbc0063374dde8f5c34b85fc85a6db09cb528aa3198f","0xe64f885196123b61e209995a206aac0ac3e318a99ab003122500625947b3f495","0xb40db3ebd13522f7136d2d2350d435d971b29692d3ce77c510b0d64a1bc500d7","0x57457d31d3a8badc09fe46ac3f429acbeab163b080c6c2ff6edd251e55eaeba5","0x0ed5ff4946b0174c8a831f5a8d60fb0aa1ec37fe2af432edbfbc21d7946afc6d","0x651de74b17b2c0c9eeb19760bec0d21010dd8d1ab8a98275ee3c8ed809270877","0x330bc47d169aabd7ba401e62c193dd2b01e06ae9d83ef429a1aefcdbb0373da3","0x6d2ea482da597b1942ab9b7baa2b6af09e85bb554eb2efd30872b5ab58430034","0x225b8951d50a7d25a82a1f28000122cb42007729233a4ec1f9e2d2ea97e0f649","0x634e19ff4c3c36c8400aa3a5d6a4415f16ef856c54119dd8feac6b1e17d6a113","0x21463e6ca18fb6ed6c7a123fb9ead2691d6f6e5d16b4c2621c97f63da7b10d89","0xfd1fd7a6794f293dcf47de8eeb87ec89c76cdaf2c2993bf358d0af601bb389ee","0xe273ca36cb8dcc77ff0509a28a8afb48a5d5acaee2193e8536bf67d40d1185fb","0x59b77d6c92f8d6a5c5cc5caf08676f20c5e58367523dbda36a47364787265ed4","0x988bde1b8065f038517cc3dd4b4f28687e7daa1c057eebe10710999360986eb6","0xbcc6ffe323b3d95472b7130909c87423e7431a18569c04d8384bdcefe2b83ece","0x0fb2594c8732e66f246c6229e3d6bd29018b8b1ce526daeca494c02330e0d5bd","0x4e701e48f55920b1f99fe7b174cec4302e1f806b084f0062144e4f9aa43adbdf","0x68720af97807da11f359eb9e9413a32dd23814ffc881018f5e3b06f008c23901","0xf89d0d7e7d4bc5ac1ea5f706f6621badf75aae000c17661d5692b9e122f2820d","0xb4bfa72bdd75cb490d3476859feefef368b3aebbd6e7fa6d587479dd8cd574e3","0x4b344cab0c77626dcbc289bcd00cf4d516c6f033afbddf6b11bd3c27124341f0","0xd0573991bb61890c4a24e9782c14884965a52ff7161e2ec5aed37e3d590da796","0xcef320a1891d05a50626e67dead6f7c58d7f658c3c5e28725754b6bdb541b842","0x7fd15e69980a043bbfc74c03c090299de5a6d3ea24b256833e86b9f448f470cb","0x57a5ae01722c145d00abfbe8e406da8f986adb30c023b31d0966a924df78a46c","0x688e783359967f14c310bc4c2375a2cb9f2e06f7888c3aeb7200cc839c47c30d","0x9b1f1a9f9314bce75e9fbb4f34ed93d02f3c9059efd7ef81bb0fc74d47992137","0x1ac80dcb668ba6e806f91fc1a5080a8e651038efc7d3ffaa72afbcccb399ab26","0x6dec41abf7f99fe28e6cf4ea796047ffa344c468277fb39199a575a41549dbf0","0xe22186651095adc0cab78cf596403e27a86cc3d4b0245d7be31639716450f07b","0x342d3812dc75596f146572e54ddb7266e9c2ed8c08af035a5a9932e74bf32ba9","0x260a54ea3e85df65783023cd2477a32f0f47d1250490df9763c16632f67b6ab0","0xdf0911b9ba4ffdfca4343adcc520784b74521c3c275ed31e7fb2f2ce9d5bc70b","0x4947312b806df863d44a06a3dbe8b9b089a31583e92f0347e758f8f07d1bc2b2","0x0693800dc310d1601b6663bf4bbbd07426e7d3baf4362131d3b48d9439228e37","0x8f8a846801226bb8e98248611fd74bc4b2ef9ffe8b6c5d3ad011df6d14e7ceba","0xa4502635a714dc1d2cbd53aa14c1d0960e4c443cfa83ecd6c7553062b6c8eb15","0x9b139bb46996b6d33dcff11b3d6da8d5fd46f206779fa15722f2995e21718c8f","0xe9a4e37536832372bc3d04e9c8937ac20eb7a0d5baf910dcc4a46c94cb6fbee6","0x6fbb14cb0779599001866f6559650430fa8b8d74862b82aacff0e22408a63b8c","0xc1b3f8a052dc08bdedbd58872707fe2a850408cb8330a624ef00dab32fac55cc","0x805425722a2c1d2683b6c1332e7e247ac81a1c2db58e149f651f84f8ba583111","0x712455256f61c12d19ad4c5887ffd3f9da827402dba1fc9c4cc270b77fd8550b","0x528654148bee17a398cb261872da50212094df601ff389c2201e210cea20decf","0x83414a52f6fcca56b22800465ffa6daa3675f30e8795d095ad1cd6a782a8e569","0xe5d5950b50d1c62d78ab791d390b358156d1bd0f4ea40bb25e9aed2b4f85715b","0x0c4d59eec121371e4149e89f5892a9cbdcf4d243142c06c3d5323ccda73ef517","0x720ec03b507870fb352f88993ce28952b415c236396809717d61e1372f5580b8","0x997412ec61223ff058e2b51504f2e522ea7fa0e48059603b2a19c48837866c00","0x9ced770fe18003f4458d2652b5f76710bfbbbe782cae56f939c22aab26500168","0x826f49a38da656d6cac26fea4ddcac29e5943fc37a738f6e7b93cffc026518ec","0x5f2793eeec8b75242d00396e4aed0a0e0609a0434b08ae7f4cba8f0aed2d5656","0xb3f558656f116c541a40d9b8462f7f155c401ccc85cf970d65c7d952f7a36632","0x6185d225902450e3d021d056fc986a66f066a500ceb625edf47c3b15bc696370","0xcde3c1408a48bf059bdf1102d49e6758dbad1fa8f73215345cb73977337013cd","0x5ca354a852ea85a8bf2feb2b1467d935b0031cafb6261738cbfb819a3d897e55","0xee0ffcfe1678ebf4a04d3cb6a98e4edc4745d51d1ec55cdda91cdf2dae55aec3","0x4f42cc280e7208d4cfaa4a0525c569e5fbd7a99891635ace66af330c4f5575aa","0xe07141b3e54c29c6876351822ef04a5d9f291e834dbb5ad46353bf3cb388d23c","0x092618edefbc88633d7ce629f05d037ef7cc0c73ea6df704f8c37bcd0e465abf","0x38a82ee045a48ae84b7bd0dde11bcf8f8c7fa988407d55302fa0d523f0768560","0xdfd7e214a3f24a3cd5723fb20e40e72df6e55dd7281506718d90c60f58e7f25d","0x16fd27cfee8da23e9201d84cbd4b3edca578c539962a413da1b121d1e021e481","0x2b2bf245189f75450e2b6ad02904d1c5a0b60cf8c7ad816f75fcd2091661ca69","0x80375ccf0c2dafdbc15678233f5b6a7a20dde713795b4f9f315f40d7c691de91"]}}}, owner_address: {_eq: ' + f'"{self.aptos_address}"' + '}, amount: {_gt: "0"}}\n          ) {\n            current_token_data {\n              token_name\n              current_collection {\n                creator_address\n                collection_name\n              }\n            }\n          }\n        }\n        ',
        }
        return await self.session.post(url, headers=headers, json=json_data)

    @api_retry
    async def get_amount_in_pool(self, position_id, pool):
        pools_bytes = await self.aptos_client.view(function="0x46566b4a16a1261ab400ab5b9067de84ba152b5eb4016b217187f2a2ca980c5a::position_nft_manager::get_positions",
                                                   type_arguments=[],
                                                   arguments=[[pool],
                                                               [position_id]])
        return json.loads(pools_bytes.decode("utf-8"))

    def get_remove_liquidity_payload(self, pool, position_id, amount):
        CONTRACT = "0x46566b4a16a1261ab400ab5b9067de84ba152b5eb4016b217187f2a2ca980c5a::scripts"
        FN_NAME = "remove_liquidity"
        ARGS = [TransactionArgument(AccountAddress.from_str(self.normalize_addr(pool)), Serializer.struct),
                TransactionArgument(position_id, Serializer.u64),
                TransactionArgument(amount, Serializer.u128),
                TransactionArgument(0, Serializer.u64),
                TransactionArgument(0, Serializer.u64)]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_remove_liquidity(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully removed liquidity from Yuzu!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    def get_close_position_payload(self, pool, position_id):
        CONTRACT = "0x46566b4a16a1261ab400ab5b9067de84ba152b5eb4016b217187f2a2ca980c5a::scripts"
        FN_NAME = "burn_position"
        ARGS = [TransactionArgument(AccountAddress.from_str(self.normalize_addr(pool)), Serializer.struct),
                TransactionArgument(position_id, Serializer.u64),
                TransactionArgument(AccountAddress.from_str(self.aptos_address), Serializer.struct)]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_close_position(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully closed position on Yuzu!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def remove_liquidity(self):
        positions = (await self.get_positions()).json()['data']['current_token_ownerships_v2']
        if not positions:
            return
        self.logger.info("Withdrawing liquidity from Yuzu...")
        for position in positions:
            position_id = position['current_token_data']['token_name']
            pool = position['current_token_data']['current_collection']['creator_address']
            amount_in_pool = (await self.get_amount_in_pool(position_id, pool))[0][0]['vec'][0]['liquidity']
            if int(amount_in_pool):
                remove_liquidity_payload = self.get_remove_liquidity_payload(pool, int(position_id), int(amount_in_pool))
                await self.complete_remove_liquidity(remove_liquidity_payload, _raise=True)
            get_close_position_payload = self.get_close_position_payload(pool, int(position_id))
            await self.complete_close_position(get_close_position_payload)
        await sleep(10, 30)

    async def add_liquidity(self):
        await self.remove_liquidity()
        await self.check_move_balance()
        while True:
            amount_move_to_add_liquidity = random.randint(101, 103) * 10 ** 8
            amount_move_to_add_liquidity_human = amount_move_to_add_liquidity / 10 ** 8
            balance = await self.get_all_balance()
            await self.check_move_balance()
            coins_to_deposit = []
            for coin in balance:
                if coin != "MOVE":
                    for coin_etalon in COINS:
                        if coin_etalon in coin:
                            move_price = (await self.prices()).json()['data']['prices'][0]['price']
                            amount_out = int((amount_move_to_add_liquidity_human * move_price) * 10 ** 6)
                            if balance[coin][0]['raw_amount'] >= amount_out:
                                coins_to_deposit.append([coin_etalon, amount_out])

            if not coins_to_deposit:
                self.logger.error("No coins to deposit. Trying to swap...")
                await self.swap_n(n_swaps=1, amounts=(106, 110), ensure_balance=110)
                await sleep(10, 30)
                continue
            break

        random_coin = random.choice(coins_to_deposit)
        random_coin_ticket, random_coin_amount_out = random_coin
        random_coin_amount_out_human = random_coin_amount_out / 10 ** COINS[random_coin_ticket]['decimals']
        add_liquidity_payload = self.get_add_liquidity_payload(random_coin_ticket,
                                                               amount_move_to_add_liquidity,
                                                               random_coin_amount_out)
        self.logger.info(f"Adding liquidity to Yuzu - {amount_move_to_add_liquidity_human} MOVE - "
                         f"{random_coin_amount_out_human} {random_coin_ticket}")
        await self.complete_add_liquidity(add_liquidity_payload)

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.remove_liquidity()
        await self.swap_all_to_move()
