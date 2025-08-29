from .router import MovementRouter
from utils.runner import ModernRunner
from utils.utils import get_session, sleep, get_data_lines, get_new_db_path_name, build_db_path, MaxLenException, Logger
from .task import Task
from .database.engine import MovementDbManager
from .database.models import MovementBaseModel
from .config import *
import os
from .paths import TWITTER_TOKENS, DISCORD_TOKENS
from patchright.async_api import async_playwright
from .task_ui import TaskUi
from .utils import InvalidAccessToken, NotEnoughMOVEException
from loguru import logger
import traceback
import asyncio
import random
from curl_cffi.requests.errors import RequestsError
from aiohttp.client_exceptions import ClientResponseError
from utils.models import Proxy


class MovementRunner(ModernRunner):
    def __init__(self):
        self.Router = MovementRouter
        super().__init__()

    async def run_task(self, data, pair, need_to_sleep=True):
        import warnings
        warnings.filterwarnings(
            "ignore",
            message="It is recommended that private keys are AIP-80 compliant",
        )
        async with MovementDbManager(build_db_path(self.db_name), MovementBaseModel) as db_manager:
            proxy = data['proxy']
            client = data['client']
            twitter_token = data['twitter_token']
            discord_token = data['discord_token']
            semaphore = self.global_data['semaphore']
            while True:
                session = get_session('https://parthenon.movementlabs.xyz', proxy.session_proxy)
                try:
                    jwt = await db_manager.get_column(client.key, 'jwt_token')
                    if self.action != "Check balance":
                        if not jwt:
                            raise InvalidAccessToken("Invalid access token")
                    async with Task(session=session,
                                    client=client,
                                    db_manager=db_manager,
                                    twitter_token=twitter_token,
                                    discord_token=discord_token,
                                    jwt_token=jwt,
                                    pair=pair) as task:
                        if not await db_manager.get_column(client.key, 'aptos_address'):
                            await db_manager.insert_column(client.key, 'aptos_address', task.aptos_address)
                        if need_to_sleep:
                            await sleep(*SLEEP_BETWEEN_WALLETS)
                        await self.Router().route(task=task, action=self.action)()
                        break
                except InvalidAccessToken:
                    async with semaphore:
                        await self.run_task_ui(session, client, db_manager)
                except NotEnoughMOVEException:
                    return

    async def task_runner_ui(self, data):
        async with MovementDbManager(build_db_path(self.db_name), MovementBaseModel) as db_manager:
            proxy = data['proxy']
            client = data['client']
            while True:
                session = get_session('https://parthenon.movementlabs.xyz', proxy.session_proxy)
                semaphore = self.global_data['semaphore']
                async with semaphore:
                    jwt = await db_manager.get_column(client.key, 'jwt_token')
                    if not jwt:
                        await self.run_task_ui(session, client, db_manager)
                        continue
                    break

    async def handle_db(self):
        if self.db_name == 'new':
            new_db = get_new_db_path_name()
            async with MovementDbManager(new_db, MovementBaseModel) as db_manager:
                await db_manager.create_tables()
                async with db_manager.session.begin():
                    try:
                        for curr in range(len(self.prepared_data['clients'])):
                                data = {key: value[curr] for key, value in self.prepared_data.items()}
                                pk = data['clients'].key
                                proxy = data['proxies'].proxy
                                twitter_token = data['twitter_tokens']
                                discord_token = data['discord_tokens']
                                await db_manager.create_base_note(pk,
                                                                  proxy,
                                                                  twitter_token=twitter_token,
                                                                  discord_token=discord_token)
                    except Exception:
                        os.remove(new_db)
                        raise
            self.db_name = new_db
        async with MovementDbManager(build_db_path(self.db_name), MovementBaseModel) as db_manager:
            return await db_manager.get_run_data()

    async def run_task_ui(self, session, client, db_manager):
        proxy = session.proxies.get('http')
        credentials, ip_port = proxy.split('@')
        username, password = credentials[7:].split(':')
        extensions = ",".join(EXTENTIONS_PATH)
        async with async_playwright() as playwright:
            chromium = playwright.chromium
            context_args = [f"--load-extension={extensions}"]
            if HIDEN_RUN:
                context_args += ["--headless=new"]
            context = await chromium.launch_persistent_context('',
                                                               headless=False,
                                                               no_viewport=True,
                                                               args=context_args,
                                                               proxy={
                                                                   'server': f'http://{ip_port}',
                                                                   'username': username,
                                                                   'password': password
                                                               },
                                                               slow_mo=600)
            task = TaskUi(client=client,
                          session=session,
                          db_manager=db_manager,
                          context=context)
            if MANUAL_SOLVE_HCAPTCHA:
                await task.manual_run()
            else:
                await task.run()

    def prepare_data(self):
        prepared_data = super().prepare_data()
        twitter_tokens = self.justify_data(prepared_data['clients'], list(get_data_lines(TWITTER_TOKENS)))
        discord_tokens = self.justify_data(prepared_data['clients'], list(get_data_lines(DISCORD_TOKENS)))
        prepared_data.update({'twitter_tokens': twitter_tokens, 'discord_tokens': discord_tokens})
        return prepared_data

    async def prepare_db_run(self):
        self.prepared_data = self.prepare_data()
        try:
            data_list = await self.handle_db()
            self.data_list = data_list
        except Exception as e:
            logger.error(f'Error while handling database: {e}\n[{traceback.format_exc()}]')
            return
        await self.initialize()
        logger.info(f'Running {len(data_list)} accounts...')
        if 'chain' in self.action:
            data = self.chain_edges(data_list, chain_len=CHAIN_LENGTH)
            ui_tasks = [asyncio.create_task(self.run_task_with_retry_ui(data)) for data in data_list]
            for pair in data:
                tasks = []
                for prev, _next in zip(*pair):
                    if prev is None:
                        continue
                    tasks.append(asyncio.create_task(self.run_task_with_retry(prev, _next)))
                results, _ = await asyncio.wait(tasks)
            await asyncio.wait(ui_tasks)
        else:
            for i, data in enumerate(data_list):
                pair = data_list[i + CHAIN_LENGTH] if i + CHAIN_LENGTH < len(data_list) else None
                tasks.append(asyncio.create_task(self.run_task_with_retry(data, pair)))
            results, _ = await asyncio.wait(tasks)
            await self.after_run(results)

    async def run_task_with_retry_ui(self, data):
        client = data['client']
        proxy = data['proxy']
        proxy = proxy.session_proxy.get('http') if proxy.session_proxy else None
        logger = Logger(client.address, additional={'pk': client.key,
                                                    'proxy': proxy}).logger
        extra_proxies = self.global_data['extra_proxies']
        while True:
            try:
                return await self.task_runner_ui(data)
            except MaxLenException:
                logger.error(f"Task failed with exception: Cloudflare. Retrying...")
                await sleep(5, 30)
            except (RequestsError, ClientResponseError) as e:
                if not extra_proxies:
                    logger.error('There is no extra proxy available!')
                    break
                logger.error(f"Task failed with exception: {type(e)}: {e}. Trying to get extra proxy...")
                random_proxy_index = random.randint(0, len(extra_proxies) - 1)
                random_proxy = extra_proxies.pop(random_proxy_index)
                logger.info(f'GOT PROXY {random_proxy}! Reconnecting...')
                proxy = Proxy(proxy=random_proxy)
                data['proxy'] = proxy
                client.reconnect_with_new_proxy(proxy.w3_proxy)
            except Exception as e:
                if 'Page.goto: net::ERR_TIMED_OUT' in str(e):
                    if not extra_proxies:
                        logger.error('There is no extra proxy available!')
                        break
                    logger.error(f"Task failed with exception: {type(e)}: {e}. Trying to get extra proxy...")
                    random_proxy_index = random.randint(0, len(extra_proxies) - 1)
                    random_proxy = extra_proxies.pop(random_proxy_index)
                    logger.info(f'GOT PROXY {random_proxy}! Reconnecting...')
                    proxy = Proxy(proxy=random_proxy)
                    data['proxy'] = proxy
                    client.reconnect_with_new_proxy(proxy.w3_proxy)
                    continue
                logger.error(f"Task failed with exception: {type(e)}: {e}|[{traceback.format_exc()}]. Retrying...")
                await sleep(5, 30)

    async def run_task_with_retry(self, data, pair):
        client = data['client']
        proxy = data['proxy']
        proxy = proxy.session_proxy.get('http') if proxy.session_proxy else None
        logger = Logger(client.address, additional={'pk': client.key,
                                                    'proxy': proxy}).logger
        extra_proxies = self.global_data['extra_proxies']
        need_to_sleep = True
        while True:
            try:
                return await self.run_task(data, pair, need_to_sleep=need_to_sleep)
            except MaxLenException:
                logger.error(f"Task failed with exception: Cloudflare. Retrying...")
                await sleep(5, 30)
                need_to_sleep = False
            except (RequestsError, ClientResponseError) as e:
                if not extra_proxies:
                    logger.error('There is no extra proxy available!')
                    break
                logger.error(f"Task failed with exception: {type(e)}: {e}. Trying to get extra proxy...")
                random_proxy_index = random.randint(0, len(extra_proxies) - 1)
                random_proxy = extra_proxies.pop(random_proxy_index)
                logger.info(f'GOT PROXY {random_proxy}! Reconnecting...')
                proxy = Proxy(proxy=random_proxy)
                data['proxy'] = proxy
                client.reconnect_with_new_proxy(proxy.w3_proxy)
                need_to_sleep = False
            except Exception as e:
                if 'Page.goto: net::ERR_TIMED_OUT' in str(e):
                    if not extra_proxies:
                        logger.error('There is no extra proxy available!')
                        break
                    logger.error(f"Task failed with exception: {type(e)}: {e}. Trying to get extra proxy...")
                    random_proxy_index = random.randint(0, len(extra_proxies) - 1)
                    random_proxy = extra_proxies.pop(random_proxy_index)
                    logger.info(f'GOT PROXY {random_proxy}! Reconnecting...')
                    proxy = Proxy(proxy=random_proxy)
                    data['proxy'] = proxy
                    client.reconnect_with_new_proxy(proxy.w3_proxy)
                    need_to_sleep = False
                    continue
                logger.error(f"Task failed with exception: {type(e)}: {e}|[{traceback.format_exc()}]. Retrying...")
                await sleep(5, 30)
                need_to_sleep = False

    @staticmethod
    def chain_edges(lst, chain_len, fillvalue=None, include_terminal=True):
        lst = list(lst)
        chunks = []
        for i in range(0, len(lst), chain_len):
            chunk = lst[i:i + chain_len]
            if len(chunk) < chain_len:
                chunk += [fillvalue] * (chain_len - len(chunk))
            chunks.append(tuple(chunk))
        res = [[chunks[i], chunks[i + 1]] for i in range(len(chunks) - 1)]
        if include_terminal and len(lst) % chain_len == 0:
            res.append([chunks[-1], tuple([fillvalue] * chain_len)])
        return res

    def get_global_data(self):
        global_data = super().get_global_data()
        semaphore = asyncio.Semaphore(SIMULTANEOUS_TASKS)
        global_data.update({'semaphore': semaphore})
        return global_data
