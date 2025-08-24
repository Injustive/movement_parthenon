from aptos_sdk.transactions import RawTransaction, SignedTransaction, TransactionPayload, EntryFunction
from aptos_sdk.authenticator import Authenticator, Ed25519Authenticator
import time
from ..utils import FailedSimulatedTransaction, retry
from .client import CustomRestClient
from utils.utils import sleep


class AptosTransactionService:
    def __init__(self, account, client: CustomRestClient, explorer_url, logger=None):
        self.client = client
        self.account = account.account
        self.explorer_url = explorer_url
        self.logger = logger

    async def get_nonce(self):
        return await self.client.account_sequence_number(self.account.account_address)

    def send_transaction(self, payload):
        try:
            transaction = self.client.submit_transaction(self.account, payload)
            self.client.wait_for_transaction(transaction)
            self.logger.success(f"Transaction successfully sent. {self.explorer_url.format(transaction)}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")

    @retry
    async def get_raw_txn(self, payload: EntryFunction) -> RawTransaction | None:
        est = await self.client.estimate_gas_price()
        gas_price = int(est.get("prioritized_gas_estimate") or est["gas_estimate"])
        raw_txn = RawTransaction(
            self.account.account_address,
            await self.client.account_sequence_number(self.account.account_address),
            TransactionPayload(payload),
            1_000_000,
            gas_price,
            int(time.time()) + 120,
            126,
        )
        sim = (await self.client.simulate_transaction(
            raw_txn, self.account, True
        ))[0]
        if sim["vm_status"] != "Executed successfully":
            raise FailedSimulatedTransaction(sim["vm_status"])
        gas_used = int(sim.get("gas_used", 0))
        raw_txn.max_gas_amount = max(int(gas_used * 1.2), gas_used + 20_000, 100_000)
        if "gas_unit_price" in sim:
            raw_txn.gas_unit_price = max(raw_txn.gas_unit_price, int(sim["gas_unit_price"]))
        return raw_txn

    @retry
    async def send_txn(self, payload: EntryFunction, silent=False):
        raw_txn = await self.get_raw_txn(payload)
        if not raw_txn:
            return
        signature = self.account.sign(raw_txn.keyed())
        auth = Authenticator(Ed25519Authenticator(self.account.public_key(), signature))
        transaction = await self.client.submit_bcs_transaction(SignedTransaction(raw_txn, auth))
        attempts = 10
        while attempts:
            try:
                tx_result = await self.client.wait_for_transaction(transaction)
                if not silent:
                    self.logger.info(self.explorer_url.format(transaction))
                return transaction
            except AssertionError:
                await sleep(10, 20)
                attempts -= 1

    async def get_token_balance(self, coin_type):
        resources = await self.client.account_resources(
            self.account.account_address
        )
        for resource in resources:
            if coin_type in resource['type']:
                return int(resource['data']['coin']['value'])
