from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from . import config


def _normalize_db_url(url: str) -> str:
    # Railway (and Heroku-style platforms) inject postgres:// but modern
    # SQLAlchemy + psycopg2 want the postgresql:// scheme.
    if url.startswith("postgres://"):
        return "postgresql+psycopg2://" + url[len("postgres://"):]
    return url


DATABASE_URL = _normalize_db_url(config.DATABASE_URL)

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def init_db():
    from . import models  # noqa: F401  (registers models on Base.metadata)

    Base.metadata.create_all(bind=engine)
