from better_automation.discord import DiscordClient, DiscordAccount
from pydantic import Field
from utils.utils import retry, check_res_status, generate_url_safe_base64
import warnings
from better_automation.discord.errors import Forbidden, Unauthorized


warnings.filterwarnings(
    "ignore",
    message="coroutine .* was never awaited",
    category=RuntimeWarning,
)


class CustomDiscordAccount(DiscordAccount):
    auth_token: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9+._-]{70}|[A-Za-z0-9+._-]{72}$",
    )


class DiscordTask:
    def __init__(self, token, session, client, logger, db_manager):
        self.token = token
        self.logger = logger
        self.session = session
        self.client = client
        self.discord_account: DiscordAccount = CustomDiscordAccount(token)
        self.db_manager = db_manager

    async def connect(self):
        oauth_data = {
            "client_id": "1357382246167871589",
            "scope": "identify guilds guilds.members.read",
            "response_type": "code",
            "redirect_uri": "https://parthenon.movementlabs.xyz/auth/discord/connect",
        }
        
        async with DiscordClient(
            self.discord_account, proxy=self.session.proxies.get("http"), verify=False
        ) as discord:
            oauth_data.pop("redirect_uri", None)
            state = oauth_data.get("state")
            try:
                bind_code = await discord.bind_app(**oauth_data)
            except (Forbidden, Unauthorized):
                self.logger.error('Bad discord')
                return False
            self.logger.success("Successfully got bind code for Discord!")
            await self.send_code_to_app(bind_code)
            connect_response = (await self.connect_to_app(bind_code)).json().get("data")
            if connect_response == 'success':
                self.logger.success("Successfully connected to app!")
                return True
            else:
                self.logger.error(f"Failed to connect discord to app! {connect_response}")
                return False

    @retry()
    @check_res_status()
    async def send_code_to_app(self, code):
        url = 'https://parthenon.movementlabs.xyz/auth/discord/connect'
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'priority': 'u=0, i',
            'referer': 'https://discord.com/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': self.session.headers['User-Agent']
        }
        params = {
            'code': code,
        }
        return await self.session.get(
            url,
            headers=headers,
            params=params,
            allow_redirects=False,
        )

    @retry()
    @check_res_status()
    async def connect_to_app(self, code):
        url = 'https://parthenon-api.movementlabs.xyz/api/auth/connect-discord'
        json_data = {
            'code': code,
            'redirectUri': 'https://parthenon.movementlabs.xyz/auth/discord/connect',
        }
        return await self.session.post(url, json=json_data)


