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


class EchelonTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    @staticmethod
    def get_add_liquidity_payload(amount):
        ADD_LIQUIDITY_CONTRACT = "0x6a01d5761d43a5b5a0ccbfc42edf2d02c0611464aae99a2ea0e0d4819f0550b5::scripts"
        ADD_LIQUIDITY_FN_NAME = "supply"
        ADD_LIQUIDITY_ARGS = [TransactionArgument(AccountAddress.from_str("0x568f96c4ed010869d810abcf348f4ff6b66d14ff09672fb7b5872e4881a25db7"),Serializer.struct),
                              TransactionArgument(amount, Serializer.u64)]
        ADD_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str('0x1::aptos_coin::AptosCoin'))]
        payload = EntryFunction.natural(
            module=ADD_LIQUIDITY_CONTRACT,
            function=ADD_LIQUIDITY_FN_NAME,
            ty_args=ADD_LIQUIDITY_TYPE_ARGS,
            args=ADD_LIQUIDITY_ARGS,
        )
        return payload

    async def echelon_add_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully added liquidity to Echelon!')
        except FailedSimulatedTransaction as e:
            if 'Failed to borrow global resource from' in str(e):
                return
            self.logger.error(e.message)
            if _raise:
                raise

    @staticmethod
    def get_withdraw_liquidity_payload():
        REMOVE_LIQUIDITY_CONTRACT = "0x6a01d5761d43a5b5a0ccbfc42edf2d02c0611464aae99a2ea0e0d4819f0550b5::scripts"
        REMOVE_LIQUIDITY_FN_NAME = "withdraw_all"
        REMOVE_LIQUIDITY_ARGS = [TransactionArgument(AccountAddress.from_str("0x568f96c4ed010869d810abcf348f4ff6b66d14ff09672fb7b5872e4881a25db7"),Serializer.struct)]
        REMOVE_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str('0x1::aptos_coin::AptosCoin'))]
        payload = EntryFunction.natural(
            module=REMOVE_LIQUIDITY_CONTRACT,
            function=REMOVE_LIQUIDITY_FN_NAME,
            ty_args=REMOVE_LIQUIDITY_TYPE_ARGS,
            args=REMOVE_LIQUIDITY_ARGS,
        )
        return payload

    async def echelon_remove_liquidity(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully removed liquidity from Echelon!')
        except FailedSimulatedTransaction as e:
            if 'Map key is not found' in e.message:
                return
            self.logger.error(e.message)
            if _raise:
                raise

    async def add_liquidity(self):
        await self.echelon_remove_liquidity(self.get_withdraw_liquidity_payload())
        await self.check_move_balance()
        amount_move_to_add_liquidity = random.randint(101, 105) * 10 ** 8
        amount_move_to_add_liquidity_human = amount_move_to_add_liquidity / 10 ** 8
        self.logger.info(f"Adding liquidity to Echelon with {amount_move_to_add_liquidity_human} MOVE...")
        await self.echelon_add_liquidity(self.get_add_liquidity_payload(amount_move_to_add_liquidity))

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.echelon_remove_liquidity(self.get_withdraw_liquidity_payload())
