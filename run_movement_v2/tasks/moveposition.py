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


class MovepositionTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    @retry()
    @check_res_status()
    async def get_add_liquidity_payload_hex(self, amount):
        url = 'https://api.moveposition.xyz/brokers/lend/v2'
        headers = {
            'accept': 'application/json',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'content-type': 'application/json',
            'origin': 'https://app.moveposition.xyz',
            'priority': 'u=1, i',
            'referer': 'https://app.moveposition.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        json_data = {
            'brokerName': 'movement-move-fa',
            'amount': str(amount),
            'network': 'aptos',
            'signerPubkey': self.aptos_address,
            'currentPortfolioState': {
                # 'collaterals': [{
                #     "amount": "0",
                #     "instrumentId": "movement-move-fa-super-aptos-deposit-note"
                # }],
                'collaterals': [],
                'liabilities': [],
            },
        }
        return await self.session.post(url, headers=headers, json=json_data)

    @retry()
    @check_res_status()
    async def get_withdraw_liquidity_payload_hex(self, amount):
        url = 'https://api.moveposition.xyz/brokers/redeem/v2'
        headers = {
            'accept': 'application/json',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'content-type': 'application/json',
            'origin': 'https://app.moveposition.xyz',
            'priority': 'u=1, i',
            'referer': 'https://app.moveposition.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        json_data = {
            'brokerName': 'movement-move-fa',
            'amount': str(amount),
            'network': 'aptos',
            'signerPubkey': self.aptos_address,
            'currentPortfolioState': {
                'collaterals': [{
                    "amount": str(amount),
                    "instrumentId": "movement-move-fa-super-aptos-deposit-note"
                }],
                'liabilities': [],
            },
        }
        return await self.session.post(url, headers=headers, json=json_data)

    @staticmethod
    def get_add_liquidity_payload(packet):
        ADD_LIQUIDITY_CONTRACT = "0xccd2621d2897d407e06d18e6ebe3be0e6d9b61f1e809dd49360522b9105812cf::entry_public"
        ADD_LIQUIDITY_FN_NAME = "lend_v2"
        ADD_LIQUIDITY_ARGS = [TransactionArgument(list(packet), Serializer.sequence_serializer(Serializer.u8))]
        ADD_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str('0xccd2621d2897d407e06d18e6ebe3be0e6d9b61f1e809dd49360522b9105812cf::coins::MOVE'))]
        payload = EntryFunction.natural(
            module=ADD_LIQUIDITY_CONTRACT,
            function=ADD_LIQUIDITY_FN_NAME,
            ty_args=ADD_LIQUIDITY_TYPE_ARGS,
            args=ADD_LIQUIDITY_ARGS,
        )
        return payload

    async def moveposition_add_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully added liquidity to moveposition!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    @retry()
    @check_res_status(expected_statuses=[200, 201, 304])
    async def get_portfolio(self):
        url = f"https://api.moveposition.xyz/portfolios/{self.aptos_address}"
        headers = {
            'accept': 'application/json',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://app.moveposition.xyz',
            'priority': 'u=1, i',
            'referer': 'https://app.moveposition.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        return await self.session.get(url, headers=headers, allow_redirects=False)

    @staticmethod
    def get_withdraw_liquidity_payload(packet):
        REMOVE_LIQUIDITY_CONTRACT = "0xccd2621d2897d407e06d18e6ebe3be0e6d9b61f1e809dd49360522b9105812cf::entry_public"
        REMOVE_LIQUIDITY_FN_NAME = "redeem_v2"
        REMOVE_LIQUIDITY_ARGS = [TransactionArgument(list(packet), Serializer.sequence_serializer(Serializer.u8))]
        REMOVE_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str('0xccd2621d2897d407e06d18e6ebe3be0e6d9b61f1e809dd49360522b9105812cf::coins::MOVE'))]
        payload = EntryFunction.natural(
            module=REMOVE_LIQUIDITY_CONTRACT,
            function=REMOVE_LIQUIDITY_FN_NAME,
            ty_args=REMOVE_LIQUIDITY_TYPE_ARGS,
            args=REMOVE_LIQUIDITY_ARGS,
        )
        return payload

    async def moveposition_remove_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully removed liquidity from moveposition!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def withdraw_liquidity(self):
        user_portfolio = (await self.get_portfolio()).json().get('collaterals', [])
        for collateral in user_portfolio:
            addr = collateral['instrument']['networkAddress']
            amount = collateral['amount']
            if '0xccd2621d2897d407e06d18e6ebe3be0e6d9b61f1e809dd49360522b9105812cf::coins::MOVE' in addr and int(amount):
                self.logger.info("You already have liquidity in moveposition. Withdrawing...")
                withdraw_liquidity_payload_hex = (await self.get_withdraw_liquidity_payload_hex(amount)).json()['packet']
                packet = bytes.fromhex(withdraw_liquidity_payload_hex)
                remove_liquidity_payload = self.get_withdraw_liquidity_payload(packet)
                await self.moveposition_remove_liquidity(remove_liquidity_payload)

    async def add_liquidity(self):
        await self.withdraw_liquidity()
        await self.check_move_balance()
        amount_move_to_add_liquidity = random.randint(101, 105) * 10 ** 8
        amount_move_to_add_liquidity_human = amount_move_to_add_liquidity / 10 ** 8
        add_liquidity_payload_hex = (await self.get_add_liquidity_payload_hex(amount_move_to_add_liquidity)).json()['packet']
        packet = bytes.fromhex(add_liquidity_payload_hex)
        add_liquidity_payload = self.get_add_liquidity_payload(packet)
        self.logger.info(f"Adding liquidity to Moveposition with {amount_move_to_add_liquidity_human} MOVE...")
        await self.moveposition_add_liquidity(add_liquidity_payload)

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.withdraw_liquidity()