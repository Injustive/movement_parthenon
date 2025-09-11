from database.base_models import BaseModel
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, JSON, func, Float
from sqlalchemy.ext.hybrid import hybrid_property


class Base(DeclarativeBase):
    pass


class MovementBaseModel(BaseModel):
    __tablename__ = "movement_base"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    aptos_address: Mapped[str] = mapped_column(String, nullable=True)
    discord_token: Mapped[str] = mapped_column(String, nullable=True)
    twitter_token: Mapped[str] = mapped_column(String, nullable=True)
    jwt_token: Mapped[str] = mapped_column(String, nullable=True)
    discord_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    twitter_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    bad_discord: Mapped[bool] = mapped_column(Boolean, default=False)
    bad_twitter: Mapped[bool] = mapped_column(Boolean, default=False)
    additional_wallet_pk: Mapped[str] = mapped_column(String, nullable=True)
    swaps_n: Mapped[int] = mapped_column(Integer, default=0)
    points_n: Mapped[int] = mapped_column(Integer, default=0)
    mandatory_tasks_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    move_balance: Mapped[float] = mapped_column(Float, nullable=True)
