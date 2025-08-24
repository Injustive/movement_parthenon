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

class CanopyTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    def get_deposit_payload_moveposition(self, packet, amount):
        ADD_LIQUIDITY_CONTRACT = "0x717b417949cd5bfa6dc02822eacb727d820de2741f6ea90bf16be6c0ed46ff4b::router"
        ADD_LIQUIDITY_FN_NAME = "deposit_fa_with_coin_type"
        ADD_LIQUIDITY_ARGS = [TransactionArgument(AccountAddress.from_str("0x31d0a30ae53e2ae852fcbdd1fce75a4ea6ad81417739ef96883eba9574ffe31e"), Serializer.struct),
                              TransactionArgument([(AccountAddress.from_str("0x2cf46516a53a123dfa632cd1c921450e664216a3fe44ab74a04db156bbe51ef9"))], Serializer.sequence_serializer(Serializer.struct)),
                              TransactionArgument([list(packet)],Serializer.sequence_serializer(Serializer.sequence_serializer(Serializer.u8))),                           TransactionArgument(amount, Serializer.u64),
                              TransactionArgument(0, Serializer.u8)]
        ADD_LIQUIDITY_TYPE_ARGS = [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))]
        payload = EntryFunction.natural(
            module=ADD_LIQUIDITY_CONTRACT,
            function=ADD_LIQUIDITY_FN_NAME,
            ty_args=ADD_LIQUIDITY_TYPE_ARGS,
            args=ADD_LIQUIDITY_ARGS,
        )
        return payload

    @retry()
    @check_res_status()
    async def get_pool_amount(self):
        url = 'https://api.moveposition.xyz/portfolios/0x2cf46516a53a123dfa632cd1c921450e664216a3fe44ab74a04db156bbe51ef9'
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://app.canopyhub.xyz',
            'priority': 'u=1, i',
            'referer': 'https://app.canopyhub.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.session.headers['User-Agent']
        }
        return await self.session.get(url, headers=headers)

    @retry()
    @check_res_status()
    async def get_deposit_liquidity_payload_hex(self, amount, pool_amount):
        url = 'https://api.moveposition.xyz/brokers/lend/v2'
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'content-type': 'application/json',
            'origin': 'https://app.canopyhub.xyz',
            'priority': 'u=1, i',
            'referer': 'https://app.canopyhub.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.session.headers['User-Agent']
        }
        json_data = {
            'amount': str(amount),
            'network': 'aptos',
            'signerPubkey': '0x2cf46516a53a123dfa632cd1c921450e664216a3fe44ab74a04db156bbe51ef9',
            'currentPortfolioState': {
                'collaterals': [
                    {
                        'instrumentId': 'movement-move-fa-super-aptos-deposit-note',
                        'amount': pool_amount,
                    },
                ],
                'liabilities': [],
            },
            'brokerName': 'movement-move-fa',
        }
        return await self.session.post(url, headers=headers, json=json_data)

    async def get_pool_info_moveposition(self, amount):
        pool_amount = (await self.get_pool_amount()).json()['collaterals'][0]['amount']
        packet_hex = (await self.get_deposit_liquidity_payload_hex(amount, pool_amount)).json()['packet']
        packet = bytes.fromhex(packet_hex)
        return packet

    async def complete_deposit_moveposition(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully deposited to Canopy Moveposition pool!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def complete_stake_moveposition(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully staked to Canopy Moveposition pool!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    @retry()
    @check_res_status()
    async def get_transaction_by_hash(self, tx_hash):
        url = f'https://rpc.sentio.xyz/movement/v1/transactions/by_hash/{tx_hash}'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'cache-control': 'max-age=3',
            'origin': 'https://app.canopyhub.xyz',
            'prefer': 'respond-async',
            'priority': 'u=1, i',
            'referer': 'https://app.canopyhub.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-storage-access': 'active',
            'user-agent': self.session.headers['User-Agent'],
            'x-aptos-client': 'aptos-typescript-sdk/1.33.1',
            'x-aptos-typescript-sdk-origin-method': 'getTransactionByHash',
            'x-client-name': 'web-client',
        }
        return await self.session.get(url, headers=headers)

    def get_stake_payload_moveposition(self, amount):
        CONTRACT = "0x113a1769acc5ce21b5ece6f9533eef6dd34c758911fa5235124c87ff1298633b::multi_rewards"
        FN_NAME = "stake"
        ARGS = [TransactionArgument(AccountAddress.from_str("0x3d871f7475a839376b5567de59807db876203c628f71c75dbeefdb60139a10f8"), Serializer.struct),
                TransactionArgument(int(amount), Serializer.u64)]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def add_liquidity_moveposition(self, amount):
        deposit_payload = self.get_deposit_payload_moveposition(await self.get_pool_info_moveposition(amount),
                                                                amount)
        tx_hash = await self.complete_deposit_moveposition(deposit_payload, _raise=True)
        await sleep(5, 10)
        cv_move_balance = (await self.get_transaction_by_hash(tx_hash)).json()['changes']
        for balance in cv_move_balance:
            if (balance['address'] == "0x29b78d043a9cf427c27e12bf511bde97cf0651dc137fdccde37c423c48052c2e"
                    and balance['data']['type'] == "0x1::fungible_asset::FungibleStore"):
                cv_move_balance = balance['data']['data']['balance']
                break
        stake_payload = self.get_stake_payload_moveposition(cv_move_balance)
        await self.complete_stake_moveposition(stake_payload)

    @api_retry
    async def get_user_staked_balance(self):
        payload = {
            "function": "0x113a1769acc5ce21b5ece6f9533eef6dd34c758911fa5235124c87ff1298633b::multi_rewards::get_user_staked_balance",
            "type_arguments": [],
            "arguments": [self.aptos_address, "0x3d871f7475a839376b5567de59807db876203c628f71c75dbeefdb60139a10f8"]
        }
        info_bytes = await self.aptos_client.view(**payload)
        info = int(json.loads(info_bytes.decode("utf-8"))[0])
        return info

    def get_unstake_payload_moveposition(self, amount):
        CONTRACT = "0x113a1769acc5ce21b5ece6f9533eef6dd34c758911fa5235124c87ff1298633b::multi_rewards"
        FN_NAME = "withdraw"
        ARGS = [TransactionArgument(AccountAddress.from_str("0x3d871f7475a839376b5567de59807db876203c628f71c75dbeefdb60139a10f8"), Serializer.struct),
                TransactionArgument(int(amount), Serializer.u64)]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_unstake_moveposition(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully unstaked from Canopy Moveposition pool!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    @api_retry
    async def get_withdrawal_map_view(self, amount):
        payload = {
            "function": "0x717b417949cd5bfa6dc02822eacb727d820de2741f6ea90bf16be6c0ed46ff4b::withdraw::get_withdrawal_map_view",
            "type_arguments": [],
            "arguments": ["0x31d0a30ae53e2ae852fcbdd1fce75a4ea6ad81417739ef96883eba9574ffe31e",
                          str(amount)]
        }
        info_bytes = await self.aptos_client.view(**payload)
        info = json.loads(info_bytes.decode("utf-8"))[0]['data'][0]['value']
        return info

    @api_retry
    async def get_withdrawal_amount_moveposition(self, amount):
        payload = {
            "function": "0xd7c7b27e361434e18d2410fd02f7140a8c10d174c9be0efd5324578d243953bd::strategy::withdrawal_amount_view",
            "type_arguments": ["0xccd2621d2897d407e06d18e6ebe3be0e6d9b61f1e809dd49360522b9105812cf::coins::MOVE"],
            "arguments": ["0x2cf46516a53a123dfa632cd1c921450e664216a3fe44ab74a04db156bbe51ef9",
                          str(amount)]
        }
        info_bytes = await self.aptos_client.view(**payload)
        info = int(json.loads(info_bytes.decode("utf-8"))[0])
        return info

    @retry()
    @check_res_status()
    async def get_withdrawal_hex_data(self, amount, pool_amount):
        url = 'https://api.moveposition.xyz/brokers/redeem/v2'
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'content-type': 'application/json',
            'origin': 'https://app.canopyhub.xyz',
            'priority': 'u=1, i',
            'referer': 'https://app.canopyhub.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.session.headers['User-Agent'],
        }
        json_data = {
            'amount': str(amount),
            'network': 'aptos',
            'signerPubkey': '0x2cf46516a53a123dfa632cd1c921450e664216a3fe44ab74a04db156bbe51ef9',
            'currentPortfolioState': {
                'collaterals': [
                    {
                        'instrumentId': 'movement-move-fa-super-aptos-deposit-note',
                        'amount': pool_amount,
                    },
                ],
                'liabilities': [],
            },
            'brokerName': 'movement-move-fa',
        }
        return await self.session.post(url, headers=headers, json=json_data)

    @staticmethod
    def option_u64(s, val):
        if val is None:
            s.bool(False)
        else:
            s.bool(True)
            s.u64(int(val))

    def get_withdraw_payload_moveposition(self, packet, amount):
        CONTRACT = "0x717b417949cd5bfa6dc02822eacb727d820de2741f6ea90bf16be6c0ed46ff4b::router"
        FN_NAME = "withdraw_fa_with_coin_type"
        ARGS = [TransactionArgument(AccountAddress.from_str("0x31d0a30ae53e2ae852fcbdd1fce75a4ea6ad81417739ef96883eba9574ffe31e"), Serializer.struct),
                TransactionArgument([(AccountAddress.from_str("0x2cf46516a53a123dfa632cd1c921450e664216a3fe44ab74a04db156bbe51ef9"))],Serializer.sequence_serializer(Serializer.struct)),
                TransactionArgument([list(packet)],Serializer.sequence_serializer(Serializer.sequence_serializer(Serializer.u8))),
                TransactionArgument(amount, Serializer.u64),
                TransactionArgument(1, self.option_u64),
                TransactionArgument(0, self.option_u64)]
        TYPE_ARGS = [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))]
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_withdraw_moveposition(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully withdrawn from Canopy Moveposition pool!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def remove_liquidity_moveposition(self):
        staked_balance = await self.get_user_staked_balance()
        if staked_balance:
            self.logger.info("Withdrawing liquidity from moveposition...")
            unstake_payload = self.get_unstake_payload_moveposition(staked_balance)
            await self.complete_unstake_moveposition(unstake_payload)
            await sleep(10, 30)
        balance = await self.get_all_balance()
        for coin in balance:
            amount = balance[coin][0]['raw_amount']
            contract = balance[coin][0]['contract']
            if coin == 'cvMOVE' and amount and contract == "0x3d871f7475a839376b5567de59807db876203c628f71c75dbeefdb60139a10f8":
                withdrawal_map_amount = await self.get_withdrawal_map_view(amount)
                withdrawal_amount = await self.get_withdrawal_amount_moveposition(withdrawal_map_amount)
                pool_amount = (await self.get_pool_amount()).json()['collaterals'][0]['amount']
                packet_hex = (await self.get_withdrawal_hex_data(withdrawal_amount, pool_amount)).json()['packet']
                packet = bytes.fromhex(packet_hex)
                withdrawal_payload = self.get_withdraw_payload_moveposition(packet, amount)
                await self.complete_withdraw_moveposition(withdrawal_payload)

    def get_deposit_payload_echelon(self, amount):
        CONTRACT = "0x717b417949cd5bfa6dc02822eacb727d820de2741f6ea90bf16be6c0ed46ff4b::router"
        FN_NAME = "deposit_coin"
        ARGS = [TransactionArgument(AccountAddress.from_str("0x58739edcac2f86e62342466f20809b268430aedf32937eba32eaac7e0bbf5233"), Serializer.struct),
                TransactionArgument([], Serializer.sequence_serializer(Serializer.u64)),
                TransactionArgument([], Serializer.sequence_serializer(Serializer.u64)),
                TransactionArgument(amount, Serializer.u64),
                TransactionArgument(0, Serializer.u8)]
        TYPE_ARGS = [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin")),
                     TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))]
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_deposit_echelon(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully deposited to Echelon pool!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    def get_stake_payload_echelon(self, amount):
        CONTRACT = "0x113a1769acc5ce21b5ece6f9533eef6dd34c758911fa5235124c87ff1298633b::multi_rewards"
        FN_NAME = "stake"
        ARGS = [TransactionArgument(AccountAddress.from_str("0xe005014fbdd053aebf97b9a36dfeed790d337f571fa9d37690f527acb3015e02"), Serializer.struct),
                TransactionArgument(amount, Serializer.u64)]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_stake_echelon(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully staked to Echelon pool!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    @api_retry
    async def get_user_staked_balance_echelon(self):
        payload = {
            "function": "0x113a1769acc5ce21b5ece6f9533eef6dd34c758911fa5235124c87ff1298633b::multi_rewards::get_user_staked_balance",
            "type_arguments": [],
            "arguments": [self.aptos_address,
                          "0xe005014fbdd053aebf97b9a36dfeed790d337f571fa9d37690f527acb3015e02"]
        }
        info_bytes = await self.aptos_client.view(**payload)
        info = int(json.loads(info_bytes.decode("utf-8"))[0])
        return info

    def get_unstake_payload_echelon(self, amount):
        CONTRACT = "0x113a1769acc5ce21b5ece6f9533eef6dd34c758911fa5235124c87ff1298633b::multi_rewards"
        FN_NAME = "withdraw"
        ARGS = [TransactionArgument(AccountAddress.from_str("0xe005014fbdd053aebf97b9a36dfeed790d337f571fa9d37690f527acb3015e02"), Serializer.struct),
                TransactionArgument(amount, Serializer.u64)]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_unstake_echelon(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully unstaked from Echelon pool!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    def get_withdraw_payload_echelon(self, amount):
        CONTRACT = "0x717b417949cd5bfa6dc02822eacb727d820de2741f6ea90bf16be6c0ed46ff4b::router"
        FN_NAME = "withdraw_coin"
        ARGS = [TransactionArgument(AccountAddress.from_str("0x58739edcac2f86e62342466f20809b268430aedf32937eba32eaac7e0bbf5233"), Serializer.struct),
                TransactionArgument([], Serializer.sequence_serializer(Serializer.u64)),
                TransactionArgument([], Serializer.sequence_serializer(Serializer.u64)),
                TransactionArgument(amount, Serializer.u64),
                TransactionArgument(1, self.option_u64),
                TransactionArgument(0, self.option_u64)]
        TYPE_ARGS = [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin")),
                     TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))]
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def complete_withdraw_echelon(self, payload, _raise=False):
        try:
            tx_hash = await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully withdrawn from Echelon pool!')
            return tx_hash
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def remove_liquidity_echelon(self):
        staked_balance = await self.get_user_staked_balance_echelon()
        if staked_balance:
            unstake_payload = self.get_unstake_payload_echelon(staked_balance)
            await self.complete_unstake_echelon(unstake_payload)
            await sleep(10, 30)
        balance = await self.get_all_balance()
        for coin in balance:
            cv_move_amount = balance[coin][0]['raw_amount']
            contract = balance[coin][0]['contract']
            if coin == 'cvMOVE' and cv_move_amount and contract == "0xe005014fbdd053aebf97b9a36dfeed790d337f571fa9d37690f527acb3015e02":
                withdraw_payload = self.get_withdraw_payload_echelon(cv_move_amount)
                await self.complete_withdraw_echelon(withdraw_payload)

    async def add_liquidity_echelon(self, amount):
        await self.remove_liquidity_echelon()
        deposit_payload_echelon = self.get_deposit_payload_echelon(amount)
        await self.complete_deposit_echelon(deposit_payload_echelon, _raise=True)
        await sleep(10, 30)
        balance = await self.get_all_balance()
        for coin in balance:
            cv_move_amount = balance[coin][0]['raw_amount']
            contract = balance[coin][0]['contract']
            if coin == 'cvMOVE' and cv_move_amount and contract == "0xe005014fbdd053aebf97b9a36dfeed790d337f571fa9d37690f527acb3015e02":
                stake_payload = self.get_stake_payload_echelon(cv_move_amount)
                await self.complete_stake_echelon(stake_payload)

    async def add_liquidity(self):
        await self.remove_liquidity_moveposition()
        await self.remove_liquidity_echelon()
        await sleep(10, 30)
        await self.check_move_balance()
        amount_move_to_add_liquidity = random.randint(101, 105) * 10 ** 8
        amount_move_to_add_liquidity_human = amount_move_to_add_liquidity / 10 ** 8
        random_pool = random.choice(["Echelon", "Moveposition"])
        if random_pool == "Moveposition":
            self.logger.info(f"Adding liquidity to Moveposition Canory pool - {amount_move_to_add_liquidity_human} MOVE")
            await self.add_liquidity_moveposition(amount_move_to_add_liquidity)
        elif random_pool == "Echelon":
            self.logger.info(f"Adding liquidity to Echelon Canory pool - {amount_move_to_add_liquidity_human} MOVE")
            await self.add_liquidity_echelon(amount_move_to_add_liquidity)

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.remove_liquidity_moveposition()
        await self.remove_liquidity_echelon()