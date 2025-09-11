from database.engine import DbManager
from sqlalchemy import select, Boolean
from utils.client import Client
from utils.models import Proxy
from sqlalchemy import String


class MovementDbManager(DbManager):
    async def create_base_note(self, pk, proxy, twitter_token, discord_token):
        await super().create_base_note(pk, proxy, twitter_token=twitter_token, discord_token=discord_token)

    async def get_run_data(self):
        async with self.session.begin():
            result = await self.session.execute(select(self.base))
            users = result.scalars().all()
            return [{'client': Client(user.private_key),
                     'proxy': Proxy(user.proxy),
                     'twitter_token': user.twitter_token,
                     'discord_token': user.discord_token}
                    for user in users]

    async def add_n_swaps(self, pk):
        async with self.session.begin():
            row = (
                await self.session.execute(
                    select(self.base)
                    .where(self.base.private_key == pk)
                    .with_for_update()
                )
            ).scalar_one()
            row.swaps_n += 1