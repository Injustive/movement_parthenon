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
import base64
import json
from ..utils import retry as api_retry

class JouleTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    @staticmethod
    def get_withdraw_liquidity_payload(packet, amount):
        REMOVE_LIQUIDITY_CONTRACT = "0x6a164188af7bb6a8268339343a5afe0242292713709af8801dafba3a054dc2f2::pool"
        REMOVE_LIQUIDITY_FN_NAME = "withdraw"
        REMOVE_LIQUIDITY_ARGS = [TransactionArgument(1, Serializer.u64),
                                 TransactionArgument(amount, Serializer.u64),
                                 TransactionArgument([packet], Serializer.sequence_serializer(Serializer.to_bytes))]
        REMOVE_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str('0x1::aptos_coin::AptosCoin'))]
        payload = EntryFunction.natural(
            module=REMOVE_LIQUIDITY_CONTRACT,
            function=REMOVE_LIQUIDITY_FN_NAME,
            ty_args=REMOVE_LIQUIDITY_TYPE_ARGS,
            args=REMOVE_LIQUIDITY_ARGS,
        )
        return payload

    async def joule_remove_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully removed liquidity from joule!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    @retry()
    @check_res_status()
    async def data_for_withdraw(self):
        url = 'https://hermes.pyth.network/api/latest_vaas?ids[]=0x6bf748c908767baa762a1563d454ebec2d5108f8ee36d806aadacc8f0a075b6d&ids[]=0xeaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a&ids[]=0x2b89b9dc8fdf9f34709a5b106b472f0f39bb6ca9ce04b0fd7f2e971688e2e53b&ids[]=0xc9d8b075a5c69303365ae23633d4e085199bf5c520a3b90fed1322a0342ffc33&ids[]=0x9d4294bbcd1174d6f2003ec365831e64cc31d9f6f15a2b85399db8d5000960f6'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://movement.joule.finance',
            'priority': 'u=1, i',
            'referer': 'https://movement.joule.finance/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.session.headers['User-Agent']
        }
        return await self.session.get(url, headers=headers)

    @api_retry
    async def get_pool_info(self):
        payload = {
            "function": "0x6a164188af7bb6a8268339343a5afe0242292713709af8801dafba3a054dc2f2::pool::user_lend_position",
            "type_arguments": [],
            "arguments": [self.aptos_address, str(1), "0x1::aptos_coin::AptosCoin"]
        }
        pool_info_bytes = await self.aptos_client.view(**payload)
        pool_info = int(json.loads(pool_info_bytes.decode("utf-8"))[0])
        return pool_info

    async def withdraw_liquidity(self):
        portfolio = (await self.get_portfolio()).json()
        portfolio = portfolio.get('data', [])
        for position in portfolio:
            for supplied_asset in position['suppliedAssets']:
                if supplied_asset['asset'] == "MOVE" and supplied_asset['supply_quantity']:
                    self.logger.info("Already have liquidity in joule. Withdrawing...")
                    amount_to_withdraw = await self.get_pool_info()
                    packet_base_64 = (await self.data_for_withdraw()).json()[0]
                    packet = base64.b64decode(packet_base_64)
                    await self.joule_remove_liquidity(self.get_withdraw_liquidity_payload(packet, amount_to_withdraw))
                    await sleep(10, 30)

    @retry()
    @check_res_status()
    async def get_portfolio(self):
        url = 'https://price-api.joule.finance/api/movement/portfolio'
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://movement.joule.finance',
            'priority': 'u=1, i',
            'referer': 'https://movement.joule.finance/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        params = {
            'address': self.aptos_address,
            'pageIndex': '0',
            'pageSize': '5',
        }
        return await self.session.get(url, headers=headers, params=params)

    @staticmethod
    def get_add_liquidity_payload(amount):
        ADD_LIQUIDITY_CONTRACT = "0x6a164188af7bb6a8268339343a5afe0242292713709af8801dafba3a054dc2f2::pool"
        ADD_LIQUIDITY_FN_NAME = "lend"
        ADD_LIQUIDITY_ARGS = [TransactionArgument(1, Serializer.u64),
                              TransactionArgument(amount, Serializer.u64),
                              TransactionArgument(False, Serializer.bool)]
        ADD_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str('0x1::aptos_coin::AptosCoin'))]
        payload = EntryFunction.natural(
            module=ADD_LIQUIDITY_CONTRACT,
            function=ADD_LIQUIDITY_FN_NAME,
            ty_args=ADD_LIQUIDITY_TYPE_ARGS,
            args=ADD_LIQUIDITY_ARGS,
        )
        return payload

    async def joule_add_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully added liquidity to Joule!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def add_liquidity(self):
        await self.withdraw_liquidity()
        await self.check_move_balance()
        amount_move_to_add_liquidity = random.randint(101, 105) * 10 ** 8
        amount_move_to_add_liquidity_human = amount_move_to_add_liquidity / 10 ** 8
        add_liquidity_payload = self.get_add_liquidity_payload(amount_move_to_add_liquidity)
        self.logger.info(f"Adding liquidity to Joule with {amount_move_to_add_liquidity_human} MOVE...")
        await self.joule_add_liquidity(add_liquidity_payload)

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.withdraw_liquidity()
