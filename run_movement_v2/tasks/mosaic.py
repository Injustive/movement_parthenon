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
import json
from ..utils import NotEnoughMOVEException
from ..utils import retry as api_retry
from ..config import MAX_SWAP_TIMES


LPs = {
    "USDT": "0x2e5656461c6c9728e887dea8041928f37d41a08057f78a61b2a446d91dd4ebd",
    "USDC": "0xbcbf55e1004687d412f05856ef7c17dcaacc1be632ba2d67b71073d25b425c3b",
}

class MosaicTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    async def get_swap_quote_request(self, src, dst, amount):
        url = 'https://bff.mosaic.ag/api/v1/quote'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://app.mosaic.ag',
            'priority': 'u=1, i',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        params = {
            'srcAsset': src,
            'dstAsset': dst,
            'amount': str(amount),
            'excludeSources': '',
            'sender': self.aptos_address,
            'recipient': self.aptos_address,
            'slippage': '5',
        }
        return await self.session.get(url, headers=headers, params=params)

    async def get_swap_quote(self, src, dst, amount):
        while True:
            swap_quotes_response = await self.get_swap_quote_request(src, dst, amount)
            if 'SESSION_ERROR' in swap_quotes_response.text or swap_quotes_response.status_code not in [200, 201]:
                await sleep(5, 10)
                await self.login()
                continue
            break
        return swap_quotes_response

    @retry()
    @check_res_status()
    async def login(self):
        url = 'https://bff.mosaic.ag/api/v1/init'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://app.mosaic.ag',
            'priority': 'u=1, i',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        return await self.session.post(url, headers=headers)

    def normalize_addr(self, addr):
        h = addr[2:].lower()
        if len(h) % 2 == 1:
            h = "0" + h
        return "0x" + h.zfill(64)

    def is_addr_like(self, x):
        return isinstance(x, str) and x.startswith("0x")

    def auto_serialize(self, arg):
        if isinstance(arg, bool):
            return TransactionArgument(arg, Serializer.bool)
        if self.is_addr_like(arg):
            return TransactionArgument(AccountAddress.from_str(self.normalize_addr(arg)),
                                       Serializer.struct)
        if isinstance(arg, list) and arg:
            if all(self.is_addr_like(x) for x in arg):
                addrs = [AccountAddress.from_str(self.normalize_addr(x)) for x in arg]
                return TransactionArgument(addrs, Serializer.sequence_serializer(Serializer.struct))
            if all(isinstance(x, (int, str)) and str(x).isdigit() for x in arg):
                nums = [int(x) for x in arg]
                return TransactionArgument(nums, Serializer.sequence_serializer(Serializer.u64))
        if isinstance(arg, str) and arg.isdigit():
            return TransactionArgument(int(arg), Serializer.u64)
        if isinstance(arg, int):
            return TransactionArgument(arg, Serializer.u64)
        if isinstance(arg, str):
            return TransactionArgument(arg, Serializer.str)
        if isinstance(arg, dict):
            return TransactionArgument(json.dumps(arg), Serializer.str)
        if isinstance(arg, list) and not arg:
            return TransactionArgument([], Serializer.sequence_serializer(Serializer.u64))

    async def swap_all_to_move(self):
        await self.login()
        self.logger.info("Swapping all to MOVE...")
        balance = await self.get_all_balance()
        for coin in balance:
            for coin_etalon in COINS:
                if coin_etalon in coin:
                    if coin != 'MOVE' and coin != 'cvMOVE' and balance[coin][0]['raw_amount']:
                        await self.swap(swap_from=coin_etalon, swap_to='MOVE', amount=balance[coin][0]['raw_amount'])

    async def swap_n(self, n_swaps=5, amounts=(1, 10), ensure_balance=5, check=0):
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
        for i in range(1, n_swaps+1):
            if check:
                already_swapped = await self.db_manager.get_column(self.client.key, 'swaps_n')
                if already_swapped >= check:
                    self.logger.info(f"Already swapped more than {MAX_SWAP_TIMES} times!")
                    return
            self.logger.info(f"Mosaic swapping {i}/{n_swaps}...")
            swap_amount = await self.swap(swap_from=swap_from,
                                          swap_to=swap_to,
                                          amount=swap_amount,
                                          _raise=True)
            swap_from = swap_to
            swap_to = random.choice([coin for coin in COINS if coin != swap_from])
            await sleep(10, 30)

    async def swap(self, swap_from, swap_to, amount, _raise=False):
        swap_data = (await self.get_swap_quote(COINS[swap_from].get('short_address', COINS[swap_from]['address']),
                                               COINS[swap_to].get('short_address', COINS[swap_to]['address']),
                                               amount)).json()['data']
        dst_amount = int(swap_data['dstAmount'])
        dst_amount_human = dst_amount / 10 ** COINS[swap_to]['decimals']
        src_amount_human = amount / 10 ** COINS[swap_from]['decimals']
        contract = "0x03f7399a0d3d646ce94ee0badf16c4c3f3c656fe3a5e142e83b5ebc011aa8b3d::router"
        fn_name = "swap"
        fn_args = [self.auto_serialize(fn_arg) for fn_arg in swap_data['tx']['functionArguments']]
        type_args = [TypeTag(StructTag.from_str(type_arg)) for type_arg in swap_data['tx']['typeArguments']]
        payload = EntryFunction.natural(
            module=contract,
            function=fn_name,
            ty_args=type_args,
            args=fn_args
        )
        self.logger.info(f"Mosaic swapping {src_amount_human} {swap_from} - {dst_amount_human} {swap_to}...")
        await self.mosaic_swap(payload, _raise=_raise)
        await self.db_manager.add_n_swaps(self.client.key)
        return dst_amount

    async def mosaic_swap(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully swapped mosaic tokens')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    @api_retry
    async def get_pool_out(self, pool_addr, move_amount):
        pools_bytes = await self.aptos_client.view(function="0x26a95d4bd7d7fc3debf6469ff94837e03e887088bef3a3f2d08d1131141830d3::router::quote_add_liquidity_one_side",
                                                   type_arguments=[],
                                                   arguments=[pool_addr, str(move_amount), True])
        return int(json.loads(pools_bytes.decode("utf-8"))[0])

    def get_add_liquidity_payload(self, lp_addr, coin_addr, move_in, coin_in):
        ADD_LIQUIDITY_CONTRACT = "0x26a95d4bd7d7fc3debf6469ff94837e03e887088bef3a3f2d08d1131141830d3::scripts"
        ADD_LIQUIDITY_FN_NAME = "add_liquidity_one_coin"
        ADD_LIQUIDITY_ARGS = [
            TransactionArgument(AccountAddress.from_str(lp_addr), Serializer.struct),
            TransactionArgument(AccountAddress.from_str(coin_addr), Serializer.struct),
            TransactionArgument(move_in, Serializer.u64),
            TransactionArgument(int(move_in - (move_in * 0.0005)), Serializer.u64),
            TransactionArgument(coin_in, Serializer.u64),
            TransactionArgument(int(coin_in - (coin_in * 0.0005)), Serializer.u64),
        ]
        ADD_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))]
        payload = EntryFunction.natural(
            module=ADD_LIQUIDITY_CONTRACT,
            function=ADD_LIQUIDITY_FN_NAME,
            ty_args=ADD_LIQUIDITY_TYPE_ARGS,
            args=ADD_LIQUIDITY_ARGS,
        )
        return payload

    async def mosaic_add_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully added liquidity to mosaic!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def add_liquidity(self):
        while True:
            await self.remove_liquidity()
            amount_move_to_add_liquidity = random.randint(101, 105) * 10 ** 8
            amount_move_to_add_liquidity_human = amount_move_to_add_liquidity / 10 ** 8
            balance = await self.get_all_balance()
            await self.check_move_balance()
            coins_to_deposit = []
            for coin in balance:
                if "MOVE" not in coin:
                    for coin_etalon in COINS:
                        if coin_etalon in coin:
                            coin_amount_to_add_liquidity = await self.get_pool_out(LPs[coin_etalon],
                                                                                   amount_move_to_add_liquidity)
                            coin_amount_to_add_liquidity_human = coin_amount_to_add_liquidity / 10 ** COINS[coin_etalon]['decimals']
                            if balance[coin][0]['amount'] >= coin_amount_to_add_liquidity_human:
                                coins_to_deposit.append([coin_etalon, coin_amount_to_add_liquidity])

            if not coins_to_deposit:
                self.logger.error("No coins to deposit. Trying to swap...")
                await self.swap_n(n_swaps=1, amounts=(106, 110), ensure_balance=110)
                continue
            break

        random_coin = random.choice(coins_to_deposit)
        random_coin_ticket, random_coin_amount_out = random_coin
        random_coin_amount_out_human = random_coin_amount_out / 10 ** COINS[random_coin_ticket]['decimals']
        add_liquidity_payload = self.get_add_liquidity_payload(self.normalize_addr(LPs[random_coin_ticket]),
                                                               self.normalize_addr(COINS[random_coin_ticket]['address']),
                                                               amount_move_to_add_liquidity,
                                                               random_coin_amount_out)
        self.logger.info(f"Adding liquidity to Mosaic with {amount_move_to_add_liquidity_human} MOVE - {random_coin_amount_out_human} {random_coin_ticket}...")
        await self.mosaic_add_liquidity(add_liquidity_payload)

    @api_retry
    async def get_coins_out(self, lp_addr, lp_amount):
        pools_bytes = await self.aptos_client.view(function="0x26a95d4bd7d7fc3debf6469ff94837e03e887088bef3a3f2d08d1131141830d3::router::quote_remove_liquidity",
                                                   type_arguments=[],
                                                   arguments=[lp_addr, str(lp_amount)])
        return json.loads(pools_bytes.decode("utf-8"))

    def get_remove_liquidity_payload(self, pool_addr,
                                           pool_token_y_addr,
                                           lp_to_burn,
                                           move_out_amount,
                                           coin_out_amount):
        REMOVE_LIQUIDITY_CONTRACT = "0x26a95d4bd7d7fc3debf6469ff94837e03e887088bef3a3f2d08d1131141830d3::scripts"
        REMOVE_LIQUIDITY_FN_NAME = "remove_liquidity_one_coin"
        REMOVE_LIQUIDITY_ARGS = [
            TransactionArgument(AccountAddress.from_str(self.normalize_addr(pool_addr)), Serializer.struct),
            TransactionArgument(AccountAddress.from_str(self.normalize_addr(pool_token_y_addr)), Serializer.struct),
            TransactionArgument(lp_to_burn, Serializer.u64),
            TransactionArgument(int(move_out_amount - (move_out_amount * 0.0005)), Serializer.u64),
            TransactionArgument(int(coin_out_amount - (coin_out_amount * 0.0005)), Serializer.u64),
            TransactionArgument(AccountAddress.from_str(self.aptos_address), Serializer.struct),
        ]
        REMOVE_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))]
        payload = EntryFunction.natural(
            module=REMOVE_LIQUIDITY_CONTRACT,
            function=REMOVE_LIQUIDITY_FN_NAME,
            ty_args=REMOVE_LIQUIDITY_TYPE_ARGS,
            args=REMOVE_LIQUIDITY_ARGS,
        )
        return payload

    @retry()
    @check_res_status()
    async def get_pools(self):
        url = 'https://stats.mosaic.ag/v1/public/pools'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://app.mosaic.ag',
            'priority': 'u=1, i',
            'referer': 'https://app.mosaic.ag/earn',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        return await self.session.get(url, headers=headers)

    async def mosaic_remove_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully removed liquidity from mosaic!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def remove_liquidity(self):
        balance = await self.get_all_balance()
        if not any(lpt in balance for lpt in ["MOVE-USDTU", "MOVE-USDCU"]):
            return
        self.logger.info("You already have Mosaic LP! Withdrawing...")
        balance = await self.get_all_balance()
        for coin in balance:
            if coin in ["MOVE-USDTU", "MOVE-USDCU"]:
                lp_to_burn = int(balance[coin][0]['raw_amount'])
                lp_addr = balance[coin][0]['contract']
                move_out_amount, coin_out_amount = await self.get_coins_out(lp_addr, lp_to_burn)
                pools = (await self.get_pools()).json()['data']['pools']
                for pool in pools:
                    if self.normalize_addr(pool['pool_address']) == self.normalize_addr(lp_addr):
                        pool_token_y = pool['metadata']['token_y']
                        break
                remove_liquidity_payload = self.get_remove_liquidity_payload(lp_addr,
                                                                             pool_token_y,
                                                                             lp_to_burn,
                                                                             int(move_out_amount),
                                                                             int(coin_out_amount))
                await self.mosaic_remove_liquidity(remove_liquidity_payload, _raise=True)

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.remove_liquidity()
        await self.swap_all_to_move()
