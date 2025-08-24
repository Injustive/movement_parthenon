import base64
import uuid

import faker
from utils.client import Client
from utils.utils import (retry, check_res_status, get_utc_now,
                         get_data_lines, sleep, Logger,
                         read_json, Contract, generate_random_hex_string,
                         get_utc_now, approve_asset, asset_balance, get_decimals, approve_if_insufficient_allowance,
                         generate_random, retry_js, JSException, ModernTask, get_session, get_gas_params, estimate_gas,
                         BadTwitterTokenException, LockedTwitterTokenException, SuspendedTwitterTokenException, TwitterException)
from .aptos.account import AptosAccount
from .aptos.client import AptosClient
from .aptos.transactions import AptosTransactionService
from .config import *
import time
import random
from .utils import COINS, NotEnoughMOVEException, retry as api_retry, InvalidAccessToken, FailedSimulatedTransaction
from utils.models import RpcProviders
import json
from collections import defaultdict
from .twitter_task import TwitterTask
from .discord_task import DiscordTask
import curl_cffi
from .utils import get_random_avatar, generate_additional_wallet
from aptos_sdk.transactions import EntryFunction, TransactionArgument, Serializer
from aptos_sdk.type_tag import TypeTag, StructTag
from aptos_sdk.account import AccountAddress
from datetime import datetime, timedelta, timezone


class Task(Logger, ModernTask):
    def __init__(self,
                 session,
                 client: Client,
                 db_manager,
                 twitter_token=None,
                 discord_token=None,
                 jwt_token=None,
                 pair=None):
        self.session = session
        self.client = client
        self.db_manager = db_manager
        self.aptos_account = AptosAccount(self.client.key)
        self.aptos_address = str(self.aptos_account.aptos_address)
        self.aptos_client = AptosClient(rest_api_url=RpcProviders.MOVEMENT_MAINNET.value).client
        self.jwt = jwt_token
        self.pair = pair
        super().__init__(f'APTOS {self.aptos_address}', additional={'pk': self.client.key,
                                                                    'proxy': self.session.proxies.get('http')})
        self.aptos_transaction_service = AptosTransactionService(account=self.aptos_account,
                                                                 client=self.aptos_client,
                                                                 explorer_url='https://blue.explorer.movementlabs.xyz/txn/{}/?network=mainnet',
                                                                 logger=self.logger)
        self.twitter_task = TwitterTask(token=twitter_token,
                                session=self.session,
                                client=self.client,
                                logger=self.logger,
                                db_manager=self.db_manager)
        self.discord_task = DiscordTask(token=discord_token,
                                        session=self.session,
                                        client=self.client,
                                        logger=self.logger,
                                        db_manager=self.db_manager)

    async def login(self):
        self.session.headers.update({'authorization': f'Bearer {self.jwt}'})

    @staticmethod
    def seconds_until_next_day(min_delay, max_delay):
        now = datetime.now(timezone.utc)
        next_day = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_left = (next_day - now).total_seconds()
        random_delay = random.randint(min_delay, max_delay)
        return int(seconds_left + random_delay)

    @retry()
    @check_res_status()
    async def get_all_coins_request(self):
        url = 'https://rpc.sentio.xyz/movement-indexer/v1/graphql'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'content-type': 'application/json',
            'origin': 'https://app.meridian.money',
            'priority': 'u=1, i',
            'referer': 'https://app.meridian.money/',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.session.headers['User-Agent'],
            'x-aptos-client': 'aptos-typescript-sdk/1.35.0',
            'x-aptos-typescript-sdk-origin-method': 'getAccountCoinsData',
        }
        json_data = {
            'query': '\n    query getAccountCoinsData($where_condition: current_fungible_asset_balances_bool_exp!, $offset: Int, $limit: Int, $order_by: [current_fungible_asset_balances_order_by!]) {\n  current_fungible_asset_balances(\n    where: $where_condition\n    offset: $offset\n    limit: $limit\n    order_by: $order_by\n  ) {\n    amount\n    asset_type\n    is_frozen\n    is_primary\n    last_transaction_timestamp\n    last_transaction_version\n    owner_address\n    storage_id\n    token_standard\n    metadata {\n      token_standard\n      symbol\n      supply_aggregator_table_key_v1\n      supply_aggregator_table_handle_v1\n      project_uri\n      name\n      last_transaction_version\n      last_transaction_timestamp\n      icon_uri\n      decimals\n      creator_address\n      asset_type\n    }\n  }\n}\n    ',
            'variables': {
                'where_condition': {
                    'owner_address': {
                        '_eq': self.aptos_address,
                    },
                },
                'offset': 0,
                'limit': 100,
            },
        }
        return await self.session.post(url, headers=headers, json=json_data)

    async def get_all_balance(self):
        balances = (await self.get_all_coins_request()).json()['data']
        balances = balances['current_fungible_asset_balances']
        coin_with_balances = defaultdict(list)
        for coin in balances:
            if coin['amount']:
                decimals = coin['metadata']['decimals']
                symbol = coin['metadata']['symbol']
                amount = coin['amount']
                contract_address = coin['asset_type']
                coin_with_balances[symbol].append({
                    'decimals': decimals,
                    'raw_amount': amount,
                    'amount': amount / 10 ** decimals,
                    'contract': contract_address
                })
        return coin_with_balances

    @property
    @api_retry
    async def move_balance(self):
        balance_bytes = await self.aptos_client.view(
            function="0x1::coin::balance",
            type_arguments=["0x1::aptos_coin::AptosCoin"],
            arguments=[self.aptos_address])
        balance = int(json.loads(balance_bytes.decode("utf-8"))[0])
        return balance, balance / 10 ** 8

    async def convert_coin_to_fa(self):
        balance = await self.get_all_balance()
        if len(balance['MOVE']) == 1:
            return
        CONTRACT = "0x1::coin"
        FN_NAME = "migrate_to_fungible_store"
        ARGS = []
        TYPE_ARGS = [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))]
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        await self.aptos_transaction_service.send_txn(payload=payload, silent=True)

    async def check_move_balance(self, min_balance=110):
        move_balance = (await self.move_balance)[1]
        if  move_balance < min_balance:
            err_msg = (f"Not enough MOVE balance. "
                        f"Need: {min_balance}. You have: {move_balance}.")
            self.logger.error(err_msg)
            await self.write_move_balance()
            raise NotEnoughMOVEException(err_msg)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 401])
    async def get_all_quests(self):
        url = 'https://parthenon-api.movementlabs.xyz/api/quests'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'authorization': self.session.headers['authorization'],
            'if-none-match': 'W/"21a09-5VNLscoSr5WGIKoKcmTvhws1OGE"',
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['user-agent']
        }
        params = {
            'limit': '1000',
            'offset': '0',
            'search': '',
        }
        return await self.session.get(url, params=params, headers=headers)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 400, 401])
    async def verify_task_request(self, task_id):
        url = f'https://parthenon-api.movementlabs.xyz/api/quests/{task_id}/verify'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'authorization': self.session.headers['authorization'],
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['user-agent']
        }
        json_data = {}
        return await self.session.post(url, headers=headers, json=json_data)

    async def verify_task(self, task_id, description):
        verify_task_response = await self.verify_task_request(task_id)
        if verify_task_response.status_code == 401:
            self.logger.info("Need to get new access token...")
            raise InvalidAccessToken("Need to get new access token")
        if 'Recurrent exceed' in verify_task_response.text:
            self.logger.info(f"Seems like task `{description}` already completed")
            return True
        verify_task_response = verify_task_response.json()
        if verify_task_response.get("data"):
            self.logger.success(f"Task `{description}` completed successfully!")
            return True
        else:
            self.logger.error(f"Task `{description}` failed. {verify_task_response}")

    async def swap_n_times(self):
        await self.check_move_balance(min_balance=5)
        from .tasks.yuzu import YuzuTask
        from .tasks.meridian import MeridianTask
        from .tasks.mosaic import MosaicTask
        def split_int(total):
            c1, c2 = sorted(random.sample(range(1, total), 2))
            return [c1, c2 - c1, total - c2]
        while True:
            total = random.randint(MAX_SWAP_TIMES, MAX_SWAP_TIMES + 10)
            already_swapped = await self.db_manager.get_column(self.client.key, 'swaps_n')
            if already_swapped >= MAX_SWAP_TIMES:
                self.logger.info("Already swapped more than 500 times!")
                return
            need_to_swap = total - already_swapped
            self.logger.info(f"Swapping {need_to_swap} times...")
            randoms_swaps = split_int(need_to_swap)
            tasks = [YuzuTask, MeridianTask, MosaicTask]
            random.shuffle(tasks)
            self.logger.info(", ".join(f"{task.__name__} - {n_swaps} swaps" for task, n_swaps in zip(tasks, randoms_swaps)))
            for task_cls, n_swaps in zip(tasks, randoms_swaps):
                already_swapped = await self.db_manager.get_column(self.client.key, 'swaps_n')
                if already_swapped >= total:
                    self.logger.info(f"Already swapped more than {MAX_SWAP_TIMES} times!")
                    return
                self.logger.info(f"Starting swapping {n_swaps} times {task_cls.__name__} task...")
                task = task_cls(session=self.session,
                                client=self.client,
                                db_manager=self.db_manager)
                for attempt in range(1, 3):
                    self.logger.info(f"Swapping {task_cls.__name__}. Attempt {attempt}/3")
                    try:
                        await task.swap_n(n_swaps=n_swaps, amounts=(0.1, 0.5), ensure_balance=5, check=total)
                        break
                    except NotEnoughMOVEException:
                        raise
                    except Exception as e:
                        self.logger.error(e)
                else:
                    for attempt in range(1, 3):
                        self.logger.info(f"Swapping {task_cls.__name__} ALL to MOVE. Attempt {attempt}/3")
                        try:
                            await task.swap_all_to_move()
                            break
                        except NotEnoughMOVEException:
                            raise
                        except Exception as e:
                            self.logger.error(e)

    async def teardown(self):
        from .tasks.meridian import MeridianTask
        from .tasks.mosaic import MosaicTask
        from .tasks.moveposition import MovepositionTask
        from .tasks.joule import JouleTask
        from .tasks.echelon import EchelonTask
        from .tasks.interest_protocol import InterestProtocolTask
        from .tasks.canopy import CanopyTask
        from .tasks.yuzu import YuzuTask
        from .tasks.layerbank import LayerBankTask
        tasks = [MeridianTask,
                 MosaicTask,
                 MovepositionTask,
                 EchelonTask,
                 CanopyTask,
                 InterestProtocolTask,
                 JouleTask,
                 YuzuTask,
                 LayerBankTask]
        random.shuffle(tasks)
        jwt = self.session.headers.pop("Authorization")
        for task_cls in tasks:
            task = task_cls(session=self.session,
                            client=self.client,
                            db_manager=self.db_manager)
            for attempt in range(1, 4):
                self.logger.info(f"Completing {task_cls.__name__} teardown...Attempt {attempt}/3")
                try:
                    await task.finish()
                    await sleep(10, 30)
                    break
                except Exception as e:
                    if 'Operation timed out after' in str(e):
                        self.logger.error("Seems like problem on website or proxy")
                        break
                    self.logger.error(e)
        self.session.headers['Authorization'] = jwt

    @retry()
    @check_res_status()
    async def wallet_connected(self):
        url = 'https://parthenon-api.movementlabs.xyz/api/users/wallet-connected'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': self.session.headers['Authorization'],
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        return await self.session.post(url, headers=headers)

    @retry()
    @check_res_status()
    async def view_individual_quest(self, quest_id):
        url = 'https://parthenon-api.movementlabs.xyz/api/tracking/view-individual-quests'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': self.session.headers['Authorization'],
            'content-type': 'application/json',
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        json_data = {
            'questId': quest_id,
        }
        return await self.session.post(url, headers=headers, json=json_data)

    async def main(self):
        await self.login()
        await self.wallet_connected()
        from .tasks.meridian import MeridianTask
        from .tasks.mosaic import MosaicTask
        from .tasks.moveposition import MovepositionTask
        from .tasks.joule import JouleTask
        from .tasks.echelon import EchelonTask
        from .tasks.interest_protocol import InterestProtocolTask
        from .tasks.canopy import CanopyTask
        from .tasks.yuzu import YuzuTask
        from .tasks.layerbank import LayerBankTask

        TASKS_MAP = {
            "cmcx05wi7000107k351s6c0ye": MeridianTask,
            "cmcwvjvw0000007l798fn5wpf": MovepositionTask,
            "cmcwx5ev3000b07l1gl2k2iz6": JouleTask,
            "cmcwwpppu000607l1946t68bz": EchelonTask,
            "cmcx027eu000007k3373hcrm6": InterestProtocolTask,
            "cmcwy5ils000407ld9fu2fd7x": CanopyTask,
            "cmcwyyov6000007jph7eaabiu": YuzuTask,
            "cmcwzrk9f000307l545x80i0s": MosaicTask,
            "cmcwwvzef000807l120bz4t8l": LayerBankTask
        }

        SWAPS_TASKS = {
            "cm8h4ewah000408l4en5t3iwb": 500,
            "cm8h4eq9o000308l470e0181c": 250,
            "cm8h4ekqt000208l4hogw17ga": 100,
            "cm8h4eex5000108l4gpo20gpr": 50,
            "cm8h4e89p000008l496lo8512": 25,
            "cm92kgk0000053b8ja7kkz3cj": 5,
            "cm92kdsn200003b8jcvkdg68q": 2
        }

        OTHER_QUESTS = ["cm80z6uga00000cjr6jve6wgt", "cm80zd0tv00020cjre6lg4ji9"]

        at_least_one_task_completed = False
        while True:
            jwt = self.session.headers.pop("Authorization")
            self.session.headers["Authorization"] = jwt
            twitter_completed = False
            tasks_to_after_complete = []
            daily_quests = await self.get_all_quests()
            if daily_quests.status_code == 401:
                self.logger.info("Need to get new access token...")
                raise InvalidAccessToken("Need to get new access token")
            daily_quests = daily_quests.json()['data']
            random.shuffle(daily_quests)
            mandatory_tasks = [*TASKS_MAP.keys()] + [task for task in SWAPS_TASKS if
                                                     SWAPS_TASKS[task] <= MAX_SWAP_TIMES]
            for quest in daily_quests:
                if quest['id'] == 'cm80yep6400020cl755l93pkt' and quest['status'] == "ACTIVE":
                    if quest['isCompleted']:
                        await self.db_manager.insert_column(self.client.key, 'discord_connected', True)
                        continue
                    self.logger.info("Need to bind Discord...")
                    status = await self.connect_discord()
                    if status:
                        await self.db_manager.insert_column(self.client.key, 'discord_connected', True)
                    else:
                        await self.db_manager.insert_column(self.client.key, 'bad_discord', True)
                    await sleep(10, 30)
                    await self.verify_task(quest['id'], quest['description'])
                elif quest['id'] == 'cm81r0x8500020cl4dcts2uyd' and quest['status'] == "ACTIVE":
                    if quest['isCompleted']:
                        await self.db_manager.insert_column(self.client.key, 'twitter_connected', True)
                        twitter_completed = True
                        continue
                    self.logger.info("Need to bind Twitter...")
                    try:
                        status = await self.connect_twitter()
                        if status:
                            await sleep(30, 60)
                            await self.verify_task(quest['id'], quest['description'])
                            await self.db_manager.insert_column(self.client.key, 'twitter_connected', True)
                            twitter_completed = True
                        else:
                            await self.db_manager.insert_column(self.client.key, 'bad_twitter', True)
                    except (BadTwitterTokenException,
                            LockedTwitterTokenException,
                            SuspendedTwitterTokenException) as e:
                        self.logger.error(e)
                        await self.db_manager.insert_column(self.client.key, 'bad_twitter', True)
                    except TwitterException as e:
                        self.logger.error(f"{e}. Try again later.")
                elif quest['id'] == 'cm80y8cwh00010cl7d6tn0fp9' and not quest['isCompleted'] and quest['status'] == "ACTIVE":
                    await self.complete_profile()
                    await sleep(10, 30)
                    await self.verify_task(quest['id'], quest['description'])
                elif quest['id'] == 'cm845hq8u00000cl4b4pp7iaj' and not quest['isCompleted'] and quest['status'] == "ACTIVE":
                    if not twitter_completed:
                        tasks_to_after_complete.append(quest)
                    try:
                        await self.twitter_task.complete_follow_task("@moveindustries")
                        await sleep(30, 60)
                        await self.view_individual_quest(quest['id'])
                        await self.verify_task(quest['id'], quest['description'])
                        continue
                    except (BadTwitterTokenException,
                            LockedTwitterTokenException,
                            SuspendedTwitterTokenException) as e:
                        self.logger.error(e)
                        await self.db_manager.insert_column(self.client.key, 'bad_twitter', True)
                    except TwitterException as e:
                        self.logger.error(f"{e}. Try again later.")
                    await self.verify_task(quest['id'], quest['description'])
                elif quest['id'] == 'cm7x5kdia00040cjvefqrcvhg' and not quest['isCompleted'] and quest['status'] == "ACTIVE":
                    await self.connect_additional_wallet()
                    await sleep(10, 30)
                    await self.verify_task(quest['id'], quest['description'])
                elif quest['id'] in TASKS_MAP and not quest['isCompleted'] and quest['status'] == "ACTIVE":
                    await self.convert_coin_to_fa()
                    jwt = self.session.headers.pop("Authorization")
                    task_cls = TASKS_MAP[quest['id']]
                    task = task_cls(self.session, self.client, self.db_manager)
                    for attempt in range(1, 4):
                        self.logger.info(f"Completing {task_cls.__name__} setup...Attempt {attempt}/3")
                        try:
                            await task.start()
                            await sleep(10, 30)
                            break
                        except Exception as e:
                            if 'Operation timed out after' in str(e):
                                self.logger.error("Seems like problem on website or proxy")
                                break
                            self.logger.error(e)

                    for attempt in range(1, 4):
                        self.logger.info(f"Completing {task_cls.__name__} teardown...Attempt {attempt}/3")
                        try:
                            await task.finish()
                            await sleep(30, 60)
                            break
                        except Exception as e:
                            if 'Operation timed out after' in str(e):
                                self.logger.error("Seems like problem on website or proxy")
                                break
                            self.logger.error(e)
                    self.session.headers["Authorization"] = jwt
                    await self.verify_task(quest['id'], quest['description'])
                    at_least_one_task_completed = True
                elif quest["id"] in OTHER_QUESTS and quest['status'] == "ACTIVE":
                    await self.verify_task(quest['id'], quest['description'])
            await self.swap_n_times()
            for quest in daily_quests:
                if quest['id'] in [task for task in SWAPS_TASKS if SWAPS_TASKS[task] <= MAX_SWAP_TIMES]:
                    await self.verify_task(quest['id'], quest['description'])

            for task in tasks_to_after_complete:
                if task['id'] == 'cm845hq8u00000cl4b4pp7iaj' and not task['isCompleted'] and task['status'] == "ACTIVE":
                    try:
                        await self.twitter_task.complete_follow_task("@moveindustries")
                        await sleep(30, 60)
                        await self.view_individual_quest(quest['id'])
                        await self.verify_task(task['id'], task['description'])
                        continue
                    except (BadTwitterTokenException,
                            LockedTwitterTokenException,
                            SuspendedTwitterTokenException) as e:
                        self.logger.error(e)
                        await self.db_manager.insert_column(self.client.key, 'bad_twitter', True)
                    except TwitterException as e:
                        self.logger.error(f"{e}. Try again later.")
                    await self.verify_task(task['id'], task['description'])

            if DONT_GO_NEXT_UNTIL_FULL_COMPLETE:
                daily_quests = await self.get_all_quests()
                if daily_quests.status_code == 401:
                    self.logger.info("Need to get new access token...")
                    raise InvalidAccessToken("Need to get new access token")
                daily_quests = daily_quests.json()['data']
                for task in list(mandatory_tasks):
                    for quest in daily_quests:
                        if task == quest['id']:
                            if quest['isCompleted']:
                                mandatory_tasks.remove(task)
                if not mandatory_tasks:
                    self.logger.success("All tasks completed successfully!")
                    await self.db_manager.insert_column(self.client.key, 'mandatory_tasks_completed', True)
                    if at_least_one_task_completed:
                        await self.teardown()
                    await self.write_move_balance()
                    await self.write_user_points()
                    return True
                await self.teardown()
                self.logger.error("Need to complete all tasks in mandatory tasks...")
                continue
            if at_least_one_task_completed:
                await self.teardown()
            await self.write_move_balance()
            await self.write_user_points()
            return

    @retry()
    @check_res_status()
    async def verify_username_request(self, username):
        url = 'https://parthenon-api.movementlabs.xyz/api/users/verify-username'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'authorization': self.session.headers['authorization'],
            'content-type': 'application/json',
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['user-agent']
        }
        json_data = {
            'username': username,
        }
        return await self.session.post(url, headers=headers, json=json_data)

    @retry()
    @check_res_status()
    async def set_username_request(self, username):
        url = 'https://parthenon-api.movementlabs.xyz/api/auth/username'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'authorization': self.session.headers['authorization'],
            'content-type': 'application/json',
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['user-agent']
        }
        json_data = {
            'username': username
        }
        return await self.session.put(url, headers=headers, json=json_data)

    async def change_username(self):
        while True:
            username = faker.Faker().word() + faker.Faker().word() + str(random.randint(1000, 9999))
            verify_username_response = (await self.verify_username_request(username)).json().get("data")
            if verify_username_response:
                self.logger.info(f"Username {username} is available")
                break
            else:
                self.logger.info(f"Username {username} is not available. Trying new one...")
                await sleep(5, 10)
        await self.set_username_request(username)
        self.logger.success(f"Username {username} set successfully!")

    async def change_avatar_request(self):
        url = "https://parthenon-api.movementlabs.xyz/api/users/upload-avatar"
        headers = {
            'authorization': self.session.headers['authorization'],
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['user-agent']
        }
        mp = curl_cffi.CurlMime()
        mp.addpart(
            name="file",
            content_type="image/png",
            filename=f"{faker.Faker().word()}.png",
            data=get_random_avatar(),
        )
        return await self.session.put(url, headers=headers, multipart=mp)

    async def change_avatar(self):
        change_avatar_response = (await self.change_avatar_request()).json().get("data")
        if change_avatar_response:
            self.logger.success(f"Avatar changed successfully!")
        else:
            self.logger.error(f"Avatar changed failed!")

    async def complete_profile(self):
        await self.change_username()
        await self.change_avatar_request()

    async def connect_discord(self):
        return await self.discord_task.connect()

    async def connect_twitter(self):
        return await self.twitter_task.connect()

    @retry()
    @check_res_status(expected_statuses=[200, 201, 400])
    async def connect_wallet_request(self, aptos_account):
        url = 'https://parthenon-api.movementlabs.xyz/api/auth/users/connect-wallet'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'authorization': self.session.headers['authorization'],
            'content-type': 'application/json',
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['user-agent']
        }
        start_time = int(time.time() * 1000)
        msg_to_sign = f'APTOS\nmessage: Sign nonce\nstartTime:{start_time}\nendTime:{start_time+60*60*4}\nnonce: {str(uuid.uuid4())}'
        public_key = str(aptos_account.aptos_public_key)
        signature =  str(aptos_account.get_signed_code(msg_to_sign))
        json_data = {
            'publicKey': public_key,
            'fullMessage': msg_to_sign,
            'signature': signature
        }
        return await self.session.post(url, headers=headers, json=json_data)

    async def connect_additional_wallet(self):
        additional_wallet_pk = generate_additional_wallet(self.client.key)
        additional_aptos_account = AptosAccount(additional_wallet_pk)
        additional_aptos_address = str(additional_aptos_account.aptos_address)
        self.logger.info(f"Generated additional wallet: {additional_aptos_address}. Connecting...")
        connect_wallet_response = await self.connect_wallet_request(additional_aptos_account)
        connect_wallet_response_json = connect_wallet_response.json()
        if connect_wallet_response_json.get("data") == 'success':
            self.logger.success(f"Wallet connected successfully!")
            await self.db_manager.insert_column(self.client.key, 'additional_wallet_pk', additional_wallet_pk)
        elif 'This wallet is already linked to your profile' in connect_wallet_response.text:
            self.logger.info("This wallet is already linked to your profile!")
            await self.db_manager.insert_column(self.client.key, 'additional_wallet_pk', additional_wallet_pk)
        else:
            self.logger.error(f"Wallet connect failed! {connect_wallet_response.text}")

    async def transfer_move(self, transfer_to, amount):
        CONTRACT = "0x1::aptos_account"
        FN_NAME = "transfer"
        ARGS = [TransactionArgument(AccountAddress.from_str(transfer_to), Serializer.struct),
                TransactionArgument(amount, Serializer.u64),
        ]
        TYPE_ARGS = []
        payload = EntryFunction.natural(
            module=CONTRACT,
            function=FN_NAME,
            ty_args=TYPE_ARGS,
            args=ARGS,
        )
        await self.aptos_transaction_service.send_txn(payload=payload, silent=True)

    async def send_to_next_wallet(self):
        move_balance = await self.move_balance
        human_balance = move_balance[1]
        remain_on_wallet = round(random.uniform(*REMAIN_ON_WALLET_FOR_DAILY_TASKS), 2)
        amount_to_send = human_balance - remain_on_wallet
        if amount_to_send < 0 or amount_to_send > human_balance:
            self.logger.error(f"You have only {human_balance} MOVE")
            return False
        send_to = str(AptosAccount(self.pair['client'].key).aptos_address) if self.pair else None
        if not send_to:
            return
        await self.transfer_move(send_to, int(amount_to_send * 10 ** 8))
        self.logger.success(f"Successfully sent {amount_to_send} MOVE to {send_to}!")

    async def chain(self):
        await self.check_move_balance(min_balance=110)
        status = await self.main()
        if DONT_GO_NEXT_UNTIL_FULL_COMPLETE:
            if status:
                await self.send_to_next_wallet()
        else:
            await self.send_to_next_wallet()

    @retry()
    @check_res_status(expected_statuses=[200, 201, 401, 304])
    async def check_daily_progress(self):
        url = 'https://parthenon-api.movementlabs.xyz/api/quests/daily-progress'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': self.session.headers['authorization'],
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['user-agent']
        }
        return await self.session.get(url, headers=headers, allow_redirects=False)

    async def daily_tasks(self):
        while True:
            await self.login()
            await self.verify_task(task_id='cm7x8ky7m00000cjr5mrk3kch', description="Daily checkin")
            await self.check_move_balance(min_balance=1)
            from .tasks.yuzu import YuzuTask
            from .tasks.meridian import MeridianTask
            from .tasks.mosaic import MosaicTask
            tasks = [YuzuTask, MeridianTask, MosaicTask]
            random.shuffle(tasks)
            for task_cls in tasks:
                task = task_cls(session=self.session,
                                client=self.client,
                                db_manager=self.db_manager)
                await task.swap_n(n_swaps=1, amounts=(0.1, 0.5), ensure_balance=1)
            for task_cls in tasks:
                task = task_cls(session=self.session,
                                client=self.client,
                                db_manager=self.db_manager)
                await task.finish()
            DAILY_TASKS = {
                "cm7eumc550000l1034sa51opb": "Complete 1 transaction on movement",
                "cm7euoorb0001l103afq8c15v": "Complete a transaction on 2 different apps"
            }
            for quest in DAILY_TASKS:
                await self.verify_task(quest, DAILY_TASKS[quest])
            await self.write_move_balance()
            await self.write_user_points()
            random_sleep_daily_time = self.seconds_until_next_day(*SLEEP_FROM_TO)
            self.logger.info(f"Sleeping for {random_sleep_daily_time}s before next day...")
            await sleep(random_sleep_daily_time)

    async def write_move_balance(self):
        move_balance = await self.move_balance
        self.logger.info(f"Your MOVE balance: {move_balance[1]} MOVE")
        await self.db_manager.insert_column(self.client.key, 'move_balance', move_balance[1])

    @retry()
    @check_res_status(expected_statuses=[200, 201, 401, 304])
    async def get_user_progress(self):
        url = 'https://parthenon-api.movementlabs.xyz/api/users/progress'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'authorization': self.session.headers['authorization'],
            'origin': 'https://parthenon.movementlabs.xyz',
            'priority': 'u=1, i',
            'referer': 'https://parthenon.movementlabs.xyz/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['user-agent']
        }
        return await self.session.get(url, headers=headers, allow_redirects=False)

    async def write_user_points(self):
        user_progress = await self.get_user_progress()
        if user_progress.status_code == 401:
            self.logger.info("Need to get new access token...")
            raise InvalidAccessToken("Need to get new access token")
        xp = user_progress.json()['data']['accumulatedXP']
        self.logger.info(f"Your XP: {xp}")
        await self.db_manager.insert_column(self.client.key, 'points_n', xp)
