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
import math
from .mosaic import MosaicTask
from ..utils import retry as api_retry
from ..config import MAX_SWAP_TIMES


LPs = {
    "USDT": "0xc24fd6702b84b2524b3c708a48524297294ed022d9c2f30222a743ef3773b2b9",
    "USDC": "0xa0454b18a94f9d0276176ba3ceba900fb28d179aa9bc276c07b2116b5e6d962a",
}

class MeridianTask(Task):
    def __init__(self, session, client, db_manager):
        super().__init__(session, client, db_manager)

    @staticmethod
    def swap_quote_from_prices(
            amount_in,
            price_in,
            price_out,
            price_impact_pct=0.01,
            swap_fee_pct=0.3,
            slippage_pct=1,
            out_decimals=6
    ):
        D = Decimal
        amount_in = D(str(amount_in))
        price_in = D(str(price_in))
        price_out = D(str(price_out))
        price_impact_pct = D(str(price_impact_pct))
        swap_fee_pct = D(str(swap_fee_pct))
        slippage_pct = D(str(slippage_pct))

        rate_out_per_in = price_in / price_out
        gross_out = amount_in * rate_out_per_in
        after_impact = gross_out * (D(1) - price_impact_pct / D(100))
        quote_out = after_impact * (D(1) - swap_fee_pct / D(100))
        min_out = quote_out * (D(1) - slippage_pct / D(100))

        scale = D(10) ** out_decimals
        min_out_int = int((min_out * scale).to_integral_value(rounding=ROUND_DOWN))
        return min_out_int

    @retry()
    @check_res_status()
    async def get_coin_prices(self, coins):
        url = 'https://app.meridian.money/api/coin-prices'
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'priority': 'u=1, i',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.session.headers['User-Agent'],
        }
        params = {
            'coins': coins
        }
        return await self.session.get(url, headers=headers, params=params)

    @staticmethod
    def amount_out_weighted_cp(X, Y, dx, fee_bps, w_in=50, w_out=50):
        D = Decimal
        dx_net = D(dx) * (D(1) - D(fee_bps) / D(10_000))
        return (D(Y) * (1 - (D(X) / (D(X) + dx_net)) ** (D(w_in) / D(w_out))))

    def pick_best_pool_move_usdc(self, pools, coin_in, coin_out, amount_in):
        best = None
        for p in pools:
            assets = [a["inner"] for a in p["assets_metadata"]]
            if coin_in in assets and coin_out in assets and p["pool_type"] == 101:
                i, j = assets.index(coin_in), assets.index(coin_out)
                X = int(p["balances"][i])
                Y = int(p["balances"][j])
                fee_bps = int(p["swap_fee_bps"])
                if p.get("weights_opt", {}).get("vec"):
                    w = [int(x) for x in p["weights_opt"]["vec"][0]]
                    w_in, w_out = w[i], w[j]
                else:
                    w_in = w_out = 50
                out = self.amount_out_weighted_cp(X, Y, amount_in, fee_bps, w_in, w_out)
                if not best or out > best["out"]:
                    best = {"pool_id": p["lp_token_metadata"]["inner"], "out": out}
        return best

    def get_swap_payload(self, pool, coin_in_addr, coin_out_addr, amount_in, amount_out):
        SWAP_MERIDIAN_CONTRACT = "0xc36ceb6d7b137cea4897d4bc82d8e4d8be5f964c4217dbc96b0ba03cc64070f4::router"
        SWAP_MERIDIAN_FN_NAME = "swap_exact_in_router_entry"
        SWAP_MERIDIAN_ARGS = [TransactionArgument([AccountAddress.from_str(pool)], Serializer.sequence_serializer(Serializer.struct)),
                              TransactionArgument([AccountAddress.from_str(coin_out_addr)], Serializer.sequence_serializer(Serializer.struct)),
                              TransactionArgument(amount_in, Serializer.u64),
                              TransactionArgument(AccountAddress.from_str(coin_in_addr), Serializer.struct),
                              TransactionArgument(amount_out, Serializer.u64)]
        SWAP_MERIDIAN_TYPE_ARGS = [
            TypeTag(StructTag.from_str("0xc36ceb6d7b137cea4897d4bc82d8e4d8be5f964c4217dbc96b0ba03cc64070f4::router::Notacoin"))
            if (coin_out_addr == '0xa' or all('0xa' != addr for addr in [coin_in_addr, coin_out_addr])) else TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))
        ]
        payload = EntryFunction.natural(
            module=SWAP_MERIDIAN_CONTRACT,
            function=SWAP_MERIDIAN_FN_NAME,
            ty_args=SWAP_MERIDIAN_TYPE_ARGS,
            args=SWAP_MERIDIAN_ARGS,
        )
        return payload

    async def swap_all_to_move(self):
        self.logger.info("Swapping all to MOVE...")
        balance = await self.get_all_balance()
        for coin in balance:
            for coin_etalon in COINS:
                if coin_etalon in coin:
                    if coin != 'MOVE' and balance[coin][0]['raw_amount']:
                        coins = f'{COINS[coin_etalon]["meridian_ticket"]},{COINS["MOVE"]["meridian_ticket"]}'
                        coin_prices = (await self.get_coin_prices(coins)).json()['data']
                        coin_price, move_price = coin_prices
                        amount_out = self.swap_quote_from_prices(balance[coin][0]["amount"],
                                                                 coin_price,
                                                                 move_price,
                                                                 out_decimals=8)
                        amount_out_human = amount_out / 10 ** COINS["MOVE"]["decimals"]
                        pools = await self.get_pool_paginated()
                        coin_in_addr = COINS[coin_etalon].get("short_address", COINS[coin_etalon]["address"])
                        coin_out_addr = COINS["MOVE"]["short_address"]
                        amount_in = balance[coin][0]['raw_amount']
                        amount_in_human = amount_in / 10 ** COINS[coin_etalon]["decimals"]
                        pool = self.pick_best_pool_move_usdc(pools,
                                                             coin_in=coin_in_addr,
                                                             coin_out=coin_out_addr,
                                                             amount_in=amount_in)
                        pool_id = pool['pool_id']
                        swap_payload = self.get_swap_payload(pool=pool_id,
                                                             coin_in_addr=coin_in_addr,
                                                             coin_out_addr=coin_out_addr,
                                                             amount_in=amount_in,
                                                             amount_out=amount_out)
                        self.logger.info(
                            f"Starting swapping {amount_in_human} {coin_etalon} -> {amount_out_human} MOVE...")
                        await self.meridian_swap(swap_payload)
                        await sleep(10, 30)

    async def meridian_swap(self, payload, _raise=False):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully swapped meridian tokens')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)
            if _raise:
                raise

    @api_retry
    async def get_pool_paginated(self):
        LENS_ADDR = "0xf501748b0da7a1bde3e040566f1ea0eea1540a28264078a9ee596c0a5fa7bd94"
        payload = {
            "function": f"{LENS_ADDR}::lens::get_pools_paginated",
            "type_arguments": [],
            "arguments": ["0", "200"]
        }
        pools_bytes = await self.aptos_client.view(**payload)
        return json.loads(pools_bytes.decode("utf-8"))[0]

    async def swap_n(self, n_swaps=1, amounts=(1, 10), ensure_balance=5, check=0):
        if check:
            already_swapped = await self.db_manager.get_column(self.client.key, 'swaps_n')
            if already_swapped >= check:
                self.logger.info(f"Already swapped more than {MAX_SWAP_TIMES} times!")
                return
        await self.check_move_balance(min_balance=ensure_balance)
        await self.swap_all_to_move()
        for i in range(1, n_swaps+1):
            if check:
                already_swapped = await self.db_manager.get_column(self.client.key, 'swaps_n')
                if already_swapped >= check:
                    self.logger.info(f"Already swapped more than {MAX_SWAP_TIMES} times!")
                    return
            swap_amount = int(round(random.uniform(*amounts), 2) * 10 ** 8)
            swap_from = "MOVE"
            swap_to = random.choice([coin for coin in COINS if coin != "MOVE"])
            self.logger.info(f"Meridian swapping {i}/{n_swaps}...")
            swap_amount = await self.swap(token_in=swap_from,
                                          token_out=swap_to,
                                          amount=swap_amount)
            if n_swaps > 1:
                await self.swap(token_in=swap_to,
                                token_out=swap_from,
                                amount=swap_amount)
                await sleep(10, 30)

    async def swap(self, token_in, token_out, amount):
        self.logger.info(f"Got pair {token_in}-{token_out}")
        coins = f'{COINS[token_in]["meridian_ticket"]},{COINS[token_out]["meridian_ticket"]}'
        coin_prices = (await self.get_coin_prices(coins)).json()['data']
        move_price, coin_price = coin_prices
        amount_human = amount / 10 ** COINS[token_in]["decimals"]
        if token_in != 'MOVE' and token_out != 'MOVE':
            amount_out = self.swap_quote_from_prices(amount_human,
                                                     move_price,
                                                     coin_price,
                                                     swap_fee_pct=0.01,
                                                     out_decimals=COINS[token_out]["decimals"])
        else:
            amount_out = self.swap_quote_from_prices(amount_human,
                                                     move_price,
                                                     coin_price,
                                                     out_decimals=COINS[token_out]["decimals"])
        amount_out_human = amount_out / 10 ** COINS[token_out]["decimals"]
        pools = await self.get_pool_paginated()
        coin_in_addr = COINS[token_in].get("short_address", COINS[token_in]["address"])
        coin_out_addr = COINS[token_out].get("short_address", COINS[token_out]["address"])
        pool = self.pick_best_pool_move_usdc(pools,
                                             coin_in=coin_in_addr,
                                             coin_out=coin_out_addr,
                                             amount_in=amount)
        pool_id = pool['pool_id']
        swap_payload = self.get_swap_payload(pool=pool_id,
                                             coin_in_addr=coin_in_addr,
                                             coin_out_addr=coin_out_addr,
                                             amount_in=amount,
                                             amount_out=amount_out)
        self.logger.info(f"Starting swapping {amount_human} {token_in} -> {amount_out_human} {token_out}...")
        await self.meridian_swap(swap_payload, _raise=True)
        await self.db_manager.add_n_swaps(self.client.key)
        return amount_out

    @staticmethod
    def estimate_lp_from_meridian_weighted(pool_data,
                                           move_in,
                                           coin_in,
                                           lp_supply_raw,
                                           lp_decimals=8,
                                           slippage=0.05):
        data = pool_data["data"]
        meta = data["metadata"]
        balances = list(map(float, data["balances"]))
        weights = list(map(float, meta["weights"]))
        fee = float(meta.get("swapFee", 0.0))
        coins = meta["coinAddresses"]
        addr_move = "0xa"
        addr_usdt = [a for a in coins if a != addr_move][0]
        amounts_map = {
            addr_move: float(move_in),
            addr_usdt: float(coin_in),
        }
        amounts_in = [amounts_map[a] for a in coins]
        r = min(a / b if b > 0 else 0.0 for a, b in zip(amounts_in, balances))
        amounts_after_fee = []
        for a, b in zip(amounts_in, balances):
            non_taxable = r * b
            excess = max(0.0, a - non_taxable)
            a_fee = non_taxable + excess * (1.0 - fee)
            amounts_after_fee.append(a_fee)
        R = 1.0
        for a_fee, b, w in zip(amounts_after_fee, balances, weights):
            R *= (1.0 + (a_fee / b)) ** w
        L = lp_supply_raw / (10 ** lp_decimals)
        lp_out = L * (R - 1.0)
        min_lp_out = lp_out * (1.0 - slippage)
        min_lp_u64 = int(math.floor(min_lp_out * (10 ** lp_decimals)))
        return {
            "coin_order": coins,
            "balances": balances,
            "weights": weights,
            "swap_fee": fee,
            "amounts_in_ordered": amounts_in,
            "r_proportional": r,
            "amounts_after_fee": amounts_after_fee,
            "invariant_ratio": R,
            "lp_out": lp_out,
            "min_lp_out": min_lp_out,
            "min_lp_u64": min_lp_u64,
        }

    @retry()
    @check_res_status()
    async def get_lp_data(self, pool_type):
        url = 'https://app.meridian.money/api/liquidity-pool'
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'priority': 'u=1, i',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.session.headers['User-Agent']
        }
        params = {
            'pool-type': pool_type
        }
        return await self.session.get(url, headers=headers, params=params)

    @api_retry
    async def get_pool_supply(self, pool_addr):
        pools_bytes = await self.aptos_client.view(function="0x1::fungible_asset::supply",
                                                   type_arguments=["0x1::fungible_asset::Metadata"],
                                                   arguments=[pool_addr])
        return json.loads(pools_bytes.decode("utf-8"))[0]

    def get_add_liquidity_payload(self, lp_addr, f_amount, s_amount, min_lp_out):
        ADD_LIQUIDITY_CONTRACT = "0xfbdb3da73efcfa742d542f152d65fc6da7b55dee864cd66475213e4be18c9d54::pool"
        ADD_LIQUIDITY_FN_NAME = "add_liquidity_weighted_entry"
        ADD_LIQUIDITY_ARGS = [
            TransactionArgument(AccountAddress.from_str(lp_addr), Serializer.struct),
            TransactionArgument([f_amount, s_amount], Serializer.sequence_serializer(Serializer.u64)),
            TransactionArgument(min_lp_out, Serializer.u64)]
        ADD_LIQUIDITY_TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=ADD_LIQUIDITY_CONTRACT,
            function=ADD_LIQUIDITY_FN_NAME,
            ty_args=ADD_LIQUIDITY_TYPE_ARGS,
            args=ADD_LIQUIDITY_ARGS,
        )
        return payload

    async def meridian_add_liquidity(self, payload):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully added liquidity to Meridian pool!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)

    async def add_liquidity(self):
        await self.remove_liquidity()
        while True:
            amount_move_to_add_liquidity = random.randint(101, 105)
            balance = await self.get_all_balance()
            await self.check_move_balance()
            coins_to_deposit = []
            for coin in balance:
                if coin != "MOVE":
                    for coin_etalon in COINS:
                        if coin_etalon in coin:
                            coins = f'{COINS["MOVE"]["meridian_ticket"]},{COINS[coin_etalon]["meridian_ticket"]}'
                            coin_prices = (await self.get_coin_prices(coins)).json()['data']
                            move_price, coin_price = coin_prices
                            amount_out = self.swap_quote_from_prices(amount_move_to_add_liquidity,
                                                                     move_price,
                                                                     coin_price,
                                                                     price_impact_pct=0,
                                                                     slippage_pct=0)
                            amount_out_human = amount_out / 10 ** COINS[coin_etalon]["decimals"]
                            if balance[coin][0]['amount'] >= amount_out_human:
                                coins_to_deposit.append([coin_etalon, amount_out])

            if not coins_to_deposit:
                self.logger.error("No coins to deposit. Trying to swap...")
                await self.swap_n(n_swaps=1, amounts=(106, 110), ensure_balance=111)
                await sleep(10, 30)
                continue
            break

        random_coin = random.choice(coins_to_deposit)
        random_coin_ticket, random_coin_amount_out = random_coin
        random_coin_amount_out_human = random_coin_amount_out / 10 ** COINS[random_coin_ticket]["decimals"]
        pool_data = (await self.get_lp_data(LPs[random_coin_ticket])).json()
        pool_supply = int((await self.get_pool_supply(LPs[random_coin_ticket]))['vec'][0])
        min_lp_out = self.estimate_lp_from_meridian_weighted(pool_data,
                                                             amount_move_to_add_liquidity,
                                                             random_coin_amount_out_human,
                                                             pool_supply)['min_lp_u64']
        add_liquidity_payload = self.get_add_liquidity_payload(LPs[random_coin_ticket],
                                                               amount_move_to_add_liquidity * 10 ** 8,
                                                               random_coin_amount_out,
                                                               min_lp_out)
        self.logger.info(f"Adding liquidity to MOVE-{random_coin_ticket} LP. "
                         f"{amount_move_to_add_liquidity} MOVE-{random_coin_amount_out_human} {random_coin_ticket}")
        await self.meridian_add_liquidity(add_liquidity_payload)

    async def remove_liquidity(self):
        balance = await self.get_all_balance()
        if not 'MER-LP' in balance:
            return
        self.logger.info("You already have Meridian LP! Withdrawing...")
        pools = await self.get_account_lpts()
        balance = await self.get_all_balance()
        pools = [pool for pool in pools if pool in LPs.values() and pool in
                 [pool['contract'] for pool in balance['MER-LP']]]
        for pool in pools:
            pool_info = await self.get_pool_info(pool)
            balances = [int(x) for x in pool_info["balances"]]
            lp_supply = int(pool_info["lp_token_supply"])
            lp_to_burn = next(balance_pool['raw_amount'] for balance_pool in balance['MER-LP']
                              if balance_pool['contract'] == pool)
            _, min_amounts = self.remove_amounts_proportional(balances, lp_supply, lp_to_burn, slippage_bps=100)
            remove_liquidity_payload = self.get_remove_liquidity_payload(pool, lp_to_burn, min_amounts)
            self.logger.info(f"Removing liquidity from MOVE-{next(k for k, v in LPs.items() if v == pool)} pool...")
            await self.meridian_remove_liquidity(remove_liquidity_payload)
            await sleep(10, 15)

    async def meridian_remove_liquidity(self, payload):
        try:
            await self.aptos_transaction_service.send_txn(payload=payload)
            self.logger.success('Successfully removed liquidity from Meridian pool!')
        except FailedSimulatedTransaction as e:
            self.logger.error(e.message)

    def get_remove_liquidity_payload(self, lp_addr, lp_amount, min_received):
        REMOVE_LIQUIDITY_CONTRACT = "0xfbdb3da73efcfa742d542f152d65fc6da7b55dee864cd66475213e4be18c9d54::pool"
        REMOVE_LIQUIDITY_FN_NAME = "remove_liquidity_entry"
        REMOVE_LIQUIDITY_ARGS = [
            TransactionArgument(AccountAddress.from_str(lp_addr), Serializer.struct),
            TransactionArgument(AccountAddress.from_str(lp_addr), Serializer.struct),
            TransactionArgument(lp_amount, Serializer.u64),
            TransactionArgument(min_received, Serializer.sequence_serializer(Serializer.u64))]
        REMOVE_LIQUIDITY_TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=REMOVE_LIQUIDITY_CONTRACT,
            function=REMOVE_LIQUIDITY_FN_NAME,
            ty_args=REMOVE_LIQUIDITY_TYPE_ARGS,
            args=REMOVE_LIQUIDITY_ARGS,
        )
        return payload

    @staticmethod
    def remove_amounts_proportional(balances, lp_supply, lp_to_burn, slippage_bps, fee_bps=0):
        expected = [(b * lp_to_burn) // lp_supply for b in balances]
        if fee_bps and fee_bps > 0:
            expected = [(e * (10_000 - fee_bps)) // 10_000 for e in expected]
        mins = [(e * (10_000 - slippage_bps)) // 10_000 for e in expected]
        return expected, mins

    @api_retry
    async def get_pool_info(self, pool_addr):
        LENS = "0xf501748b0da7a1bde3e040566f1ea0eea1540a28264078a9ee596c0a5fa7bd94::lens"
        payload = {
            "function": f"{LENS}::get_pool_info",
            "type_arguments": [],
            "arguments": [pool_addr]
        }
        pool_info_bytes = await self.aptos_client.view(**payload)
        pool_info = json.loads(pool_info_bytes.decode("utf-8"))
        return pool_info[0] if isinstance(pool_info, list) and pool_info else pool_info

    async def get_account_lpts(self):
        LENS = "0xf501748b0da7a1bde3e040566f1ea0eea1540a28264078a9ee596c0a5fa7bd94::lens"
        payload = {
            "function": f"{LENS}::account_lpts",
            "type_arguments": [],
            "arguments": [self.aptos_address]
        }
        pools_bytes = await self.aptos_client.view(**payload)
        pools = json.loads(pools_bytes.decode("utf-8"))
        items = pools[0] if len(pools) == 1 else pools
        lp_metas = [(x["inner"] if isinstance(x, dict) else x) for x in items]
        return lp_metas

    async def start(self):
        await self.add_liquidity()

    async def finish(self):
        await self.remove_liquidity()
        await self.swap_all_to_move()