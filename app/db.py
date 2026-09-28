from sqlalchemy import create_engine, inspect, text
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
    _patch_missing_columns()


def _patch_missing_columns():
    """Add columns introduced after a table already existed in production.

    There's no migration framework here on purpose (the schema is small
    and changes rarely) — this just keeps an already-deployed Postgres
    database in sync with new nullable-with-default columns instead of
    requiring a manual ALTER TABLE or a full Alembic setup.
    """
    inspector = inspect(engine)
    if "scans" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("scans")}
    if "candidate_limit" in existing:
        return
    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE scans ADD COLUMN candidate_limit INTEGER NOT NULL DEFAULT 600"
        ))
