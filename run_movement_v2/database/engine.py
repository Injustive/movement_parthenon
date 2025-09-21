from database.engine import DbManager
from sqlalchemy import select, Boolean
from utils.client import Client
from utils.models import Proxy
from sqlalchemy import select, func, exists


class MovementDbManager(DbManager):
    async def create_base_note(self, pk, proxy, twitter_token, discord_token, bitget_deposit_address):
        await super().create_base_note(pk,
                                       proxy,
                                       twitter_token=twitter_token,
                                       discord_token=discord_token,
                                       bitget_deposit_address=bitget_deposit_address)

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

    async def add_register_columns(self, table_name="movement_base"):
        from sqlalchemy import MetaData, Table
        from sqlalchemy.sql import text
        from sqlalchemy.exc import SQLAlchemyError
        try:
            engine = self.get_engine()
            async with engine.begin() as conn:
                metadata = MetaData()
                await conn.run_sync(lambda sync_conn: Table(
                    table_name,
                    metadata,
                    autoload_with=sync_conn
                ))
                await conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN bitget_deposit_address STRING"))
                await conn.commit()
        except SQLAlchemyError as e:
            await conn.rollback()
