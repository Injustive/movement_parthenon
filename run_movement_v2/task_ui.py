from utils.utils import (Logger, sleep, retry, check_res_status,
                         asset_balance, read_json, Contract,
                         get_decimals, get_data_lines, with_retry_async,
                         transfer, get_gas_params)
from .config import *
import asyncio
from contextlib import suppress
import re


class TaskUi(Logger):
    def __init__(self, client, session, db_manager, context):
        self.client = client
        self.session = session
        self.db_manager = db_manager
        self.context = context
        super().__init__(self.client.address, additional={'pk': self.client.key,
                                                          'proxy': self.session.proxies.get('http')})

    async def run(self):
        await self.razor_wallet_login()
        await self.connect_captcha_solver()
        # watcher = TwoStepWalletWatcher(self.context)
        # task = asyncio.create_task(watcher.start(timeout_ms=100_000_000))
        page = await self.context.new_page()
        await page.goto("https://parthenon.movementlabs.xyz/")
        for c_page in list(self.context.pages):
            if c_page.url != page.url:
                await c_page.close()
        await sleep(2)
        await page.keyboard.press("Escape")
        await page.keyboard.press("Escape")
        await page.click(".connect-wallet-button")
        await page.click('span:has-text("Razor")')
        async with self.context.expect_event("page", timeout=100_000_0) as popup_info:
            pass
        async with self.context.expect_event("page", timeout=5000) as inner_popup_info:
            razor_page = await popup_info.value
            await razor_page.click("text='Confirm'")
        razor_page = await inner_popup_info.value
        await razor_page.click("text='Sign'")
        verify_q = await self.start_verify_listener(self.context)
        token = await asyncio.wait_for(verify_q.get(), timeout=600)
        self.logger.success("Successfully got verify token!")
        await self.db_manager.insert_column(self.client.key, 'jwt_token', token)

    async def manual_run(self):
        await self.razor_wallet_login()
        page = await self.context.new_page()
        await page.goto("https://parthenon.movementlabs.xyz/")
        for c_page in list(self.context.pages):
            if c_page.url != page.url:
                await c_page.close()
        await sleep(2)
        await page.keyboard.press("Escape")
        await page.keyboard.press("Escape")
        await page.click(".connect-wallet-button")
        await page.click('span:has-text("Razor")')
        async with self.context.expect_event("page", timeout=100_000_0) as popup_info:
            pass
        async with self.context.expect_event("page", timeout=5000) as inner_popup_info:
            razor_page = await popup_info.value
            await razor_page.click("text='Confirm'")
        razor_page = await inner_popup_info.value
        await razor_page.click("text='Sign'")

        verify_q = await self.start_verify_listener(self.context)
        token = await asyncio.wait_for(verify_q.get(), timeout=600)
        self.logger.success("Successfully got verify token!")
        await self.db_manager.insert_column(self.client.key, 'jwt_token', token)

    async def check_terms_and_enable_start(self, page):
        async def dump_state(tag="state"):
            st = await page.evaluate("""
            () => {
                const cb = document.querySelector('#terms-of-service, input[name="confirmed"][type="checkbox"]');
                const btns = [...document.querySelectorAll('button')].filter(b => (b.textContent||'').trim()==='Start');
                const enabled = btns.some(b => !b.disabled);
                const cs = cb ? window.getComputedStyle(cb) : null;
                return {
                    hasCheckbox: !!cb,
                    checked: !!(cb && cb.checked),
                    cbDisplay: cs?.display, cbVis: cs?.visibility, cbOp: cs?.opacity, cbPE: cs?.pointerEvents,
                    startBtns: btns.length, startEnabled: enabled
                };
            }""")
            return st
        await page.get_by_role("button", name="Start").first.wait_for(state="visible")
        chk = page.locator('#terms-of-service, input[name="confirmed"][type="checkbox"]')
        await chk.wait_for(state="attached")
        await dump_state("before")
        try:
            await chk.check(timeout=1500)
        except Exception as e:
            pass
        st = await dump_state("after-check")
        if not st["checked"]:
            try:
                await chk.focus()
                await page.keyboard.press("Space")
            except Exception as e:
                pass
        st = await dump_state("after-space")
        if not st["checked"]:
            try:
                box = await chk.bounding_box()
                if box:
                    await page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            except Exception as e:
                pass
        st = await dump_state("after-mouse")
        if not st["checked"]:
            try:
                await page.evaluate("""
                () => {
                    const cb = document.querySelector('#terms-of-service, input[name="confirmed"][type="checkbox"]');
                    if (!cb) return;
                    if (!cb.checked) cb.checked = true;
                    cb.dispatchEvent(new MouseEvent('click', {bubbles:true, composed:true}));
                    cb.dispatchEvent(new Event('input', {bubbles:true}));
                    cb.dispatchEvent(new Event('change', {bubbles:true}));
                }""")
            except Exception:
                pass

        await dump_state("after-js")

    async def razor_wallet_login(self):
        page = await self.context.new_page()
        session = await self.context.new_cdp_session(page)
        win = await session.send("Browser.getWindowForTarget")
        await session.send("Browser.setWindowBounds", {
            "windowId": win["windowId"],
            "bounds": {"windowState": "maximized"}
        })
        await page.goto("chrome-extension://fdcnegogpncmfejlfnffnofpngdiejii/index.html#/account/initialize/welcome")
        await sleep(2)
        await self.check_terms_and_enable_start(page)
        await page.click('button:has-text("Start")')
        await page.click('button:has-text("I already have a wallet")')
        await page.click('//html/body/div/div[2]/div[1]/div[2]/div[2]/div/div/div[2]/button[2]')
        name_wallet = page.locator('input[placeholder="Wallet Name"]')
        await name_wallet.fill("emul")
        key_wallet = page.locator('input[placeholder="To restore with private key, please enter your private key from Razor Wallet. (The private key is a 66-digit string starting with 0x)"]')
        await key_wallet.fill(self.client.key)
        await page.click('button:has-text("Proceed")')
        new_pass = page.locator('input[placeholder="New password"]')
        confirm_pass = page.locator('input[placeholder="Confirm password"]')
        await new_pass.fill(DEFAULT_PASSWORD)
        await confirm_pass.fill(DEFAULT_PASSWORD)
        await page.click('button:has-text("Proceed")')
        await page.click('button:has-text("Done")')
        await sleep(3)
        page = await self.context.new_page()
        await page.goto("chrome-extension://fdcnegogpncmfejlfnffnofpngdiejii/index.html#/account/initialize/welcome")
        enter_pwd = page.locator('input[placeholder="Please enter password"]')
        await enter_pwd.fill(DEFAULT_PASSWORD)
        await page.click('button:has-text("Unlock wallet")')

    async def connect_captcha_solver(self):
        page = await self.context.new_page()
        await page.goto("chrome-extension://hlifkpholllijblknnmbfagnkjneagid/popup/popup.html")
        await page.click('input#toggle')
        await page.click('span:has-text("already has a key?")')
        await page.fill('input[placeholder="CSK_**********************************"]', CAPTCHA_API_KEY)
        await page.click('button:has-text("Bind Key")')
        await page.click('//html/body/div/div/div/div[2]/div[2]/div[2]/div/div[1]/div[1]/div[2]/label/div')
        await page.click('//html/body/div/div/div/div[2]/div[2]/div[2]/div/div[3]/div[1]/div[2]/label/div')
        await page.click('//html/body/div/div/div/div[2]/div[2]/div[2]/div/div[4]/div[1]/div[2]/label/div')
        row = page.locator(
            "xpath=//*[normalize-space(.)='hCaptcha']/ancestor::*[self::div or self::li][1]"
        ).first
        await row.wait_for(state="visible")
        img = row.get_by_role("img").last
        await img.click()
        await page.fill('//html/body/div/div/div/div[2]/div[2]/div[2]/div/div[2]/div[2]/div/div/div[3]/div[2]/div/input', '100')
        await page.close()

    async def start_verify_listener(self, context):
        q = asyncio.Queue()
        async def handle(resp):
            try:
                if resp.request.method != "POST": return
                if "/api/auth/users/verify" not in resp.url: return
                if not resp.ok: return
                js = await resp.json()
                data = js.get("data")
                if data:
                    await q.put(data)
            except Exception:
                pass
        context.on("response", lambda r: asyncio.create_task(handle(r)))
        return q

class TwoStepWalletWatcher:
    def __init__(self, context):
        self.context = context
        self.done = asyncio.get_running_loop().create_future()
        self.state = {"confirm": False, "sign": False}
        self._tasks: set[asyncio.Task] = set()
        self.CONFIRM_RE = re.compile(r"(confirm|approve|allow|підтверд|подтверд)", re.I)
        self.SIGN_RE = re.compile(r"(sign|подпис|підпис)", re.I)

    async def start(self, timeout_ms=120_000):
        for p in self.context.pages:
            self._attach_page(p)
        def on_page(p):
            self._attach_page(p)
        self._on_page = on_page
        self.context.on("page", self._on_page)

        try:
            await asyncio.wait_for(self.done, timeout=timeout_ms/1000)
        finally:
            with suppress(Exception):
                self.context.off("page", self._on_page)
            for t in list(self._tasks):
                t.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)

        return self.state.copy()

    def _attach_page(self, p):
        def on_popup(pop):
            self._spawn(self._handle(pop))
        p.on("popup", on_popup)

        self._spawn(self._handle(p))

    def _spawn(self, coro):
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(lambda t: self._tasks.discard(t))

    async def _handle(self, page):
        closed = asyncio.create_task(page.wait_for_event("close"))

        try:
            with suppress(Exception):
                await page.wait_for_load_state("domcontentloaded", timeout=10000)

            while not page.is_closed() and not self.done.done():
                if not self.state["confirm"]:
                    try:
                        btn = page.get_by_role("button", name=self.CONFIRM_RE)
                        if await btn.count():
                            with suppress(Exception):
                                await btn.first.click(timeout=1500)
                                self.state["confirm"] = True
                                await asyncio.sleep(0.25)
                    except Exception:
                        if page.is_closed():
                            break
                if self.state["confirm"] and not self.state["sign"]:
                    try:
                        btn = page.get_by_role("button", name=self.SIGN_RE)
                        if await btn.count():
                            with suppress(Exception):
                                await btn.first.click(timeout=1500)
                                self.state["sign"] = True
                                await asyncio.sleep(0.25)
                    except Exception:
                        if page.is_closed():
                            break

                if self.state["confirm"] and self.state["sign"] and not self.done.done():
                    self.done.set_result(True)
                    break
                await asyncio.sleep(10)
        finally:
            with suppress(Exception):
                closed.cancel()
