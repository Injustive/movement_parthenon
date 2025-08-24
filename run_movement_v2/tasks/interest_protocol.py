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
from .meridian import MeridianTask
from ..utils import retry as api_retry

LPs = {
    "USDC": "0x691877d4f5d4c1177d02f6ca3d399df4624af265533d305c008f6cb15d1567bc",
    "USDT": "0x12061cb8e5a17ae7d34dd3371479f7cec323e4ad16b8991792fb496d739e87af"
}


class InterestProtocolTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)
        self.meridian_task = MeridianTask(session, client, db_manager)

    async def get_user_balance(self):
        url = 'https://indexer.mainnet.movementnetwork.xyz/v1/graphql'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'content-type': 'application/json',
            'origin': 'https://www.interest.xyz',
            'priority': 'u=1, i',
            'referer': 'https://www.interest.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.session.headers['User-Agent'],
            'x-aptos-client': 'aptos-typescript-sdk/1.33.0',
            'x-aptos-typescript-sdk-origin-method': 'getAccountCoinsData'
        }
        json_data = {
            'query': '\n    query getAccountCoinsData($where_condition: current_fungible_asset_balances_bool_exp!, $offset: Int, $limit: Int, $order_by: [current_fungible_asset_balances_order_by!]) {\n  current_fungible_asset_balances(\n    where: $where_condition\n    offset: $offset\n    limit: $limit\n    order_by: $order_by\n  ) {\n    amount\n    asset_type\n    is_frozen\n    is_primary\n    last_transaction_timestamp\n    last_transaction_version\n    owner_address\n    storage_id\n    token_standard\n    metadata {\n      token_standard\n      symbol\n      supply_aggregator_table_key_v1\n      supply_aggregator_table_handle_v1\n      project_uri\n      name\n      last_transaction_version\n      last_transaction_timestamp\n      icon_uri\n      decimals\n      creator_address\n      asset_type\n    }\n  }\n}\n    ',
            'variables': {
                'where_condition': {
                    'owner_address': {
                        '_eq': self.aptos_address
                    },
                },
            },
        }
        return await self.session.post(url=url, headers=headers, json=json_data)

    @api_retry
    async def quote_add_liquidity(self, lp_addr, amount_move, amount_coin):
        payload = {
            "function": "0x373aab3f20ef3c31fc4caa287b0f18170f4a0b4a28c80f7ee79434458f70f241::interest_curve_router::quote_add_liquidity",
            "type_arguments": [],
            "arguments": [lp_addr, [str(amount_move), str(amount_coin)]]
        }
        info_bytes = await self.aptos_client.view(**payload)
        info = int(json.loads(info_bytes.decode("utf-8"))[0])
        return info

    def get_add_liquidity_payload(self, coin, amount_coin, amount_move, ipx):
        ADD_LIQUIDITY_CONTRACT = "0x373aab3f20ef3c31fc4caa287b0f18170f4a0b4a28c80f7ee79434458f70f241::interest_curve_entry"
        ADD_LIQUIDITY_FN_NAME = "add_liquidity"
        ADD_LIQUIDITY_ARGS = [TransactionArgument(AccountAddress.from_str(LPs[coin]), Serializer.struct),
                              TransactionArgument([AccountAddress.from_str(addr) for addr in [COINS[coin]["address"],
                                                                                              COINS["MOVE"]["address"]]],
                                                  Serializer.sequence_serializer(Serializer.struct)),
                              TransactionArgument([amount_coin, amount_move], Serializer.sequence_serializer(Serializer.u64)),
                              TransactionArgument(ipx, Serializer.u64),
                              TransactionArgument(AccountAddress.from_str(self.aptos_address), Serializer.struct)]
        ADD_LIQUIDITY_TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=ADD_LIQUIDITY_CONTRACT,
            function=ADD_LIQUIDITY_FN_NAME,
            ty_args=ADD_LIQUIDITY_TYPE_ARGS,
            args=ADD_LIQUIDITY_ARGS,
        )
        return payload

    async def interest_protocol_add_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully added liquidity to Interest Protocol!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    def get_withdraw_liquidity_payload(self, lp_coin, amount):
        REMOVE_LIQUIDITY_CONTRACT = "0x373aab3f20ef3c31fc4caa287b0f18170f4a0b4a28c80f7ee79434458f70f241::interest_curve_entry"
        REMOVE_LIQUIDITY_FN_NAME = "remove_liquidity"
        REMOVE_LIQUIDITY_ARGS = [TransactionArgument(AccountAddress.from_str(LPs[lp_coin]), Serializer.struct),
                                 TransactionArgument(amount, Serializer.u64),
                                 TransactionArgument([0, 0], Serializer.sequence_serializer(Serializer.u64)),
                                 TransactionArgument(AccountAddress.from_str(self.aptos_address), Serializer.struct)]
        REMOVE_LIQUIDITY_TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=REMOVE_LIQUIDITY_CONTRACT,
            function=REMOVE_LIQUIDITY_FN_NAME,
            ty_args=REMOVE_LIQUIDITY_TYPE_ARGS,
            args=REMOVE_LIQUIDITY_ARGS,
        )
        return payload

    async def interest_protocol_remove_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully removed liquidity from Interest Protocol!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def remove_liquidity(self):
        balance = (await self.get_user_balance()).json()
        balance = balance['data']['current_fungible_asset_balances']
        for coin in balance:
            for lp_coin in LPs:
                if LPs[lp_coin] == coin['asset_type'] and coin['amount'] and coin['amount'] and coin['token_standard'] == 'v2':
                    self.logger.info("Already have liquidity in Interest protocol. Withdrawing...")
                    lp_amount = coin['amount']
                    remove_liquidity_payload = self.get_withdraw_liquidity_payload(lp_coin, lp_amount)
                    await self.interest_protocol_remove_liquidity(remove_liquidity_payload)
                    await sleep(10, 30)

    async def add_liquidity(self):
        await self.remove_liquidity()
        await self.check_move_balance()
        amount_move_to_add_liquidity = random.randint(101, 105) * 10 ** 8
        amount_move_to_add_liquidity_human = amount_move_to_add_liquidity / 10 ** 8
        while True:
            balance = (await self.get_user_balance()).json()['data']['current_fungible_asset_balances']
            coins_to_add_liquidity = []
            for coin in balance:
                for coin_etalon in [coin for coin in COINS if coin != 'MOVE']:
                    if coin['token_standard'] == 'v2' and COINS[coin_etalon]['address'] == coin['asset_type'] and coin['amount']:
                        coins_to_add_liquidity.append([coin_etalon, coin['amount']])
            if not coins_to_add_liquidity:
                self.logger.error("No coins to deposit. Trying to swap...")
                await self.meridian_task.swap_n(n_swaps=1, amounts=(106, 110), ensure_balance=110)
                await sleep(10, 30)
                continue
            break
        random_coin_to_add_liquidity = random.choice(coins_to_add_liquidity)
        coin, coin_amount = random_coin_to_add_liquidity
        ipx = await self.quote_add_liquidity(LPs[coin], coin_amount, amount_move_to_add_liquidity)
        add_liquidity_payload = self.get_add_liquidity_payload(coin, coin_amount, amount_move_to_add_liquidity, ipx)
        self.logger.info(f"Adding liquidity to Interest Protocol with {amount_move_to_add_liquidity_human} MOVE - "
                         f"{coin_amount / 10 ** COINS[coin]['decimals']} {coin}...")
        await self.interest_protocol_add_liquidity(add_liquidity_payload)

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.remove_liquidity()
        await self.meridian_task.swap_all_to_move()
