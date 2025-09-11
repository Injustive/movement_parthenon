import twitter
from twitter import Client
from utils.utils import retry, check_res_status, generate_url_safe_base64
import uuid
from contextlib import asynccontextmanager
from twitter.errors import (BadAccountToken,
                            AccountLocked,
                            AccountSuspended,
                            FailedToFindDuplicatePost,
                            ServerError,
                            HTTPException)
from utils.utils import (BadTwitterTokenException,
                         LockedTwitterTokenException,
                         SuspendedTwitterTokenException,
                         TwitterException,
                         sleep)


class TwitterTask:
    def __init__(self, token, session, client, logger, db_manager):
        self.session = session
        self.token = token
        self.account = twitter.Account(auth_token=token)
        self.twitter_client = None
        self.logger = logger
        self.db_manager = db_manager
        self.client = client

    @asynccontextmanager
    async def twitter_session(self):
        await sleep(3, 60)
        try:
            if not self.twitter_client:
                self.logger.info('Opening new Twitter client session...')
                self.twitter_client = await Client(self.account,
                                                   proxy=self.session.proxies.get('http'),
                                                   auto_relogin=True).__aenter__()
            yield self.twitter_client
        except BadAccountToken:
            self.logger.error(f'Bad token! Maybe replace it {self.token}')
            raise BadTwitterTokenException(token=self.token)
        except AccountLocked:
            self.logger.error(f'Twitter account is locked! {self.token}')
            raise LockedTwitterTokenException(token=self.token)
        except AccountSuspended:
            self.logger.error(f'Twitter account is suspended! {self.token}')
            raise SuspendedTwitterTokenException(token=self.token)
        except (FailedToFindDuplicatePost, ServerError, HTTPException) as e:
            raise TwitterException(f'{self.token} | {e}')
        except KeyError:
            raise TwitterException(f'{self.token} | You need to wait some time to send new request to Twitter')

    async def connect(self):
        async with self.twitter_session():
            state = str(uuid.uuid4())
            code_challenge = str(uuid.uuid4())
            oauth2_data = {
                "response_type": "code",
                "client_id": "UzJuQ3lCNDF1X1FuRHp5MWFoRnU6MTpjaQ",
                "code_challenge": code_challenge,
                "code_challenge_method": "plain",
                "redirect_uri": "https://parthenon.movementlabs.xyz/auth/twitter/connect",
                "state": state,
                "scope": "tweet.read users.read follows.read like.read offline.access",
            }
            code = await self.twitter_client.oauth2(**oauth2_data)
            await self.callback_request(code, state)
            connect_response = await self.connect_callback(code, code_challenge)
            if "Twitter account already linked to another account" in connect_response.text:
                self.logger.error("Twitter account already linked to another account")
                return False
            self.logger.success("Twitter connected successfully!")
            return True

    @retry()
    @check_res_status(expected_statuses=[200, 201, 301, 302, 307])
    async def callback_request(self, code, state):
        url = 'https://parthenon.movementlabs.xyz/auth/twitter/connect'
        params = {
            "state": state,
            "code": code,
        }
        return await self.session.get(url, params=params, allow_redirects=False)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 400])
    async def connect_callback(self, code, code_verifier):
        url = 'https://parthenon-api.movementlabs.xyz/api/auth/connect-twitter'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': self.session.headers.get('authorization'),
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
            'user-agent': self.session.headers.get('User-Agent')
        }
        json_data = {
            'code': code,
            'redirectUri': 'https://parthenon.movementlabs.xyz/auth/twitter/connect',
            'codeVerifier': code_verifier,
        }
        return await self.session.post(url, json=json_data, headers=headers)

    async def complete_follow_task(self, username):
        username = username.replace('@', '')
        async with self.twitter_session():
            user_info = await self.twitter_client.request_user_by_username(username=username)
            await self.twitter_client.follow(user_info.id)
            self.logger.success(f'Followed {username} successfully!')