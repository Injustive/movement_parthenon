from aptos_sdk.async_client import RestClient, ApiError
from aptos_sdk.async_client import ClientConfig
from aptos_sdk.transactions import RawTransaction, SignedTransaction, TransactionPayload, EntryFunction, AccountAuthenticator
import pyuseragents
import httpx
import time
import base64

class AptosClient:
    def __init__(self, rest_api_url):
        self.rest_api_url = rest_api_url
        self.client = CustomRestClient(rest_api_url)


class CustomRestClient(RestClient):
    def __init__(self, base_url: str, client_config: ClientConfig = ClientConfig()):
        super().__init__(base_url, client_config)
        limits = httpx.Limits()
        timeout = httpx.Timeout(60.0, pool=None)
        self.client = httpx.AsyncClient(
            http2=client_config.http2,
            limits=limits,
            timeout=timeout,
            headers=get_aptos_headers(),
        )

    async def estimate_gas_price(self) -> dict:
        resp = await self.client.get(f"{self.base_url}/estimate_gas_price")
        if resp.status_code >= 400:
            raise ApiError(resp.text, resp.status_code)
        return resp.json()

    async def suggested_gas_unit_price(self) -> int:
        try:
            est = await self.estimate_gas_price()
            for k in ("prioritized_gas_estimate", "gas_estimate", "deprioritized_gas_estimate"):
                if k in est and est[k] is not None:
                    return int(est[k])
        except Exception:
            pass
        return 100

    async def simulate_raw_transaction(self, payload: dict, sender, estimate_gas_usage: bool = False):
        txn_request = {
            "sender": f"{sender.address()}",
            "sequence_number": str(
                await self.account_sequence_number(sender.address())
            ),
            "max_gas_amount": str(1000),
            "gas_unit_price": str(100),
            "expiration_timestamp_secs": str(
                int(time.time()) + 60
            ),
            "payload": payload,
        }

        response = await self.client.post(
            f"{self.base_url}/transactions/encode_submission", json=txn_request
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        to_sign = bytes.fromhex(response.json()[2:])
        signature = sender.sign(to_sign)
        txn_request["signature"] = {
            "type": "ed25519_signature",
            "public_key": f"{sender.public_key()}",
            "signature": f"{signature}",
        }

        headers = {"Content-Type": "application/json"}
        params = {}
        if estimate_gas_usage:
            params = {
                "estimate_gas_unit_price": "true",
                "estimate_max_gas_amount": "true",
            }

        response = await self.client.post(
            f"{self.base_url}/transactions/simulate",
            params=params,
            headers=headers,
            json=txn_request,
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def submit_raw_transaction(self, payload: dict, sender, max_gas_amount=None, gas_unit_price=None):
        max_gas_amount = max_gas_amount or 1000
        gas_unit_price = gas_unit_price or 100
        txn_request = {
            "sender": f"{sender.address()}",
            "sequence_number": str(
                await self.account_sequence_number(sender.address())
            ),
            "max_gas_amount": str(max_gas_amount),
            "gas_unit_price": str(gas_unit_price),
            "expiration_timestamp_secs": str(
                int(time.time()) + 60
            ),
            "payload": payload,
        }
        response = await self.client.post(
            f"{self.base_url}/transactions/encode_submission", json=txn_request
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        to_sign = bytes.fromhex(response.json()[2:])
        signature = sender.sign(to_sign)
        txn_request["signature"] = {
            "type": "ed25519_signature",
            "public_key": f"{sender.public_key()}",
            "signature": f"{signature}",
        }
        headers = {"Content-Type": "application/json"}
        response = await self.client.post(
            f"{self.base_url}/transactions", headers=headers, json=txn_request
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()["hash"]


def get_aptos_headers():
    return {
        'accept': '*/*',
        'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
        'cache-control': 'max-age=0',
        'priority': 'u=0, i',
        'sec-ch-ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
        'sec-ch-ua-mobile': '?0',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': pyuseragents.random(),
    }