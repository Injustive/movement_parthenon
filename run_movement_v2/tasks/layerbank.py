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


class LayerBankTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    def add_liquidity_payload(self, move_addr, amount):
        CONTRACT = "0xf257d40859456809be19dfee7f4c55c4d033680096aeeb4228b7a15749ab68ea::supply_logic"
        FN_NAME = "supply"
        ARGS = [TransactionArgument(AccountAddress.from_str(move_addr), Serializer.struct),
                TransactionArgument(amount, Serializer.u256),
                TransactionArgument(AccountAddress.from_str(self.aptos_address), Serializer.struct),
                TransactionArgument(0, Serializer.u16)]
        TYPE_ARGS = []
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
            self.logger.success('Successfully added liquidity to LayerBank!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    def get_remove_liquidity_payload(self):
        CONTRACT = "0xf257d40859456809be19dfee7f4c55c4d033680096aeeb4228b7a15749ab68ea::supply_logic"
        FN_NAME = "withdraw"
        ARGS = [TransactionArgument(AccountAddress.from_str("0xa"), Serializer.struct),
                TransactionArgument(115792089237316195423570985008687907853269984665640564039457584007913129639935, Serializer.u256),
                TransactionArgument(AccountAddress.from_str(self.aptos_address), Serializer.struct)]
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
            self.logger.success('Successfully removed liquidity from LayerBank!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def remove_liquidity(self):
        balance = await self.get_all_balance()
        for coin in balance:
            if coin == 'lMOVE':
                self.logger.info("Withdrawing liquidity...")
                remove_liquidity_payload = self.get_remove_liquidity_payload()
                await self.complete_remove_liquidity(remove_liquidity_payload)

    async def add_liquidity(self):
        await self.remove_liquidity()
        await self.check_move_balance()
        amount_move_to_add_liquidity = random.randint(101, 103) * 10 ** 8
        amount_move_to_add_liquidity_human = amount_move_to_add_liquidity / 10 ** 8
        add_liquidity_payload = self.add_liquidity_payload("0xa", amount_move_to_add_liquidity)
        self.logger.info(f"Adding liquidity to LayerBank - {amount_move_to_add_liquidity_human} MOVE")
        await self.complete_add_liquidity(add_liquidity_payload)

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.remove_liquidity()