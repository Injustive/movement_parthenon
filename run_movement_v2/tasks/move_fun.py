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
import uuid
import secrets


class MoveFunTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    @api_retry
    async def get_token_out(self, token_addr, amount):
        pools_bytes = await self.aptos_client.view(function="0x4c5058bc4cd77fe207b8b9990e8af91e1055b814073f0596068e3b95a7ccd31a::fungible_asset_router::quote_buy_exact_move",
                                                   type_arguments=[],
                                                   arguments=[token_addr, str(amount)])
        return int(json.loads(pools_bytes.decode("utf-8"))[0])
    
    @api_retry
    async def get_token_out_sell(self, token_addr, amount):
        pools_bytes = await self.aptos_client.view(function="0x4c5058bc4cd77fe207b8b9990e8af91e1055b814073f0596068e3b95a7ccd31a::fungible_asset_router::quote_sell_exact_in",
                                                   type_arguments=[],
                                                   arguments=[token_addr, str(amount)])
        return int(json.loads(pools_bytes.decode("utf-8"))[0])

    @api_retry
    async def get_token_balance(self, token_addr):
        balance = await self.aptos_client.view(function="0x4c5058bc4cd77fe207b8b9990e8af91e1055b814073f0596068e3b95a7ccd31a::fungible_asset::virtual_balances",
                                               type_arguments=[],
                                               arguments=[token_addr, [self.aptos_address]])
        return int(json.loads(balance.decode("utf-8"))[0][0]['vec'][0])

    @retry()
    @check_res_status()
    async def get_token_list(self):
        url = 'https://mainnet-api.move.fun/api/v1/tokens-list'
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://www.move.fun',
            'priority': 'u=1, i',
            'referer': 'https://www.move.fun/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        params = {
            'page': str(random.randint(1, 30)),
            'sortBy': 'updatedAt',
            'sortDirection': 'desc',
            'showMigrated': 'true',
            'showUnmigrated': 'true',
        }
        return await self.session.get(url=url, headers=headers, params=params)

    @staticmethod
    def normalize_addr(addr):
        h = addr[2:].lower()
        if len(h) % 2 == 1:
            h = "0" + h
        return "0x" + h.zfill(64)
    
    async def get_swap_payload(self, token_addr, amount_in, amount_out):
        CONTRACT = "0x4c5058bc4cd77fe207b8b9990e8af91e1055b814073f0596068e3b95a7ccd31a::fungible_asset_router"
        FN_NAME = "buy_exact_move"
        ARGS = [TransactionArgument(AccountAddress.from_str(self.normalize_addr(token_addr)), Serializer.struct),
                TransactionArgument(amount_in, Serializer.u64),
                TransactionArgument(amount_out, Serializer.u64)]
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
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully swapped on MoveFun!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    async def n_swaps(self, n_swaps):
        for i in range(1, n_swaps + 1):
            self.logger.info(f"MoveFun swapping {i}/{n_swaps}...")
            await self.swap()
            
    async def get_sell_payload(self, token_addr, amount_in, amount_out):
        CONTRACT = "0x4c5058bc4cd77fe207b8b9990e8af91e1055b814073f0596068e3b95a7ccd31a::fungible_asset_router"
        FN_NAME = "sell_exact_in"
        ARGS = [TransactionArgument(AccountAddress.from_str(self.normalize_addr(token_addr)), Serializer.struct),
                TransactionArgument(amount_in, Serializer.u64),
                TransactionArgument(amount_out, Serializer.u64)]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        return payload

    async def swap(self):
        token_list = (await self.get_token_list()).json()['tokens']
        random_token = random.choice(token_list)
        random_token_address = random_token['address']
        random_token_name = random_token['symbol']
        random_amount_human = round(random.uniform(0, 0.6), 2)
        random_amount = int(random_amount_human * 10 ** 8)
        amount_out = await self.get_token_out(random_token_address, random_amount)
        amount_out_human = amount_out / 10 ** 6
        swap_payload = await self.get_swap_payload(random_token_address, random_amount, amount_out)
        self.logger.info(f"Swapping {random_amount_human} MOVE to {amount_out_human} {random_token_name}...")
        await self.complete_swap(swap_payload, _raise=True)
        await sleep(2, 5)
        token_balance = await self.get_token_balance(random_token_address)
        token_balance_human = token_balance / 10 ** 6
        amount_move_out = await self.get_token_out_sell(random_token_address, token_balance)
        amount_move_out_human = amount_move_out / 10 ** 8
        sell_payload = await self.get_sell_payload(random_token_address, token_balance, amount_move_out)
        self.logger.info(f"Selling {token_balance_human} {random_token_name} to {amount_move_out_human} MOVE...")
        await self.complete_swap(sell_payload)

    async def login(self, installation_id):
        url = 'https://saturn.move.fun/server/functions/verifyMessageAptos'
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'content-type': 'text/plain',
            'origin': 'https://www.move.fun',
            'priority': 'u=1, i',
            'referer': 'https://www.move.fun/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        msg_to_sign = "APTOS\\nmessage: Sign this message to connect your wallet to Move.Fun | #50032\\nnonce: 0"
        data = {"pubkey": str(self.aptos_account.aptos_public_key),
                "address": self.aptos_address,
                "expectedSigner": self.aptos_address,
                "signature": str(self.aptos_account.get_signed_code(msg_to_sign)),
                "message":msg_to_sign,
                "_ApplicationId":"890a119d5c72a47412ee0837221270a147b3d0c5",
                "_ClientVersion":"js1.12.0",
                "_InstallationId":installation_id}
        return await self.session.post(url, headers=headers, data=json.dumps(data))
    
    @retry()
    @check_res_status()
    async def create_comment_request(self):
        url = 'https://saturn.move.fun/server/functions/createComment'
        token_list = (await self.get_token_list()).json()['tokens']
        random_token = random.choice(token_list)
        random_token_address = random_token['address']
        headers = {
        'accept': '*/*',
        'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
        'content-type': 'text/plain',
        'origin': 'https://www.move.fun',
        'priority': 'u=1, i',
        'referer': 'https://www.move.fun/',
        'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': self.session.headers['User-Agent']
        }
        
        installation_id = str(uuid.uuid4())
        session_token = (await self.login(installation_id)).json()['result']['sessionToken']
        data = {"coinAddress":random_token_address,
                "comment":random.choice(["Awesome!", "Fantastic!", "Incredible!", "Outstanding!", "Brilliant!", "Superb!", "Magnificent!", "Remarkable!", "Stunning!", "Impressive!", "Love it!", "Keep it up!", "So cool!", "Well done!", "Nice work!", "Top tier!", "Next level!", "Super clean!", "Mind-blowing!", "Legendary!", "Absolutely brilliant!", "This is fire!", "Killer move!", "Great job!", "Fantastic work!", "Epic!", "So impressive!", "Beautiful design!", "Amazing project!", "Incredible performance!"]),
                "_ApplicationId": "890a119d5c72a47412ee0837221270a147b3d0c5",
                "_ClientVersion":"js1.12.0",
                "_InstallationId": installation_id,
                "_SessionToken": session_token}
        return await self.session.post(url, headers=headers, data=json.dumps(data))
    
    async def create_comment(self):
        create_comment_response = await self.create_comment_request()
        if create_comment_response.json().get('result'):
            self.logger.success('Successfully created comment on MoveFun!')
            