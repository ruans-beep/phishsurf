import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, String, Integer, DateTime, ForeignKey, JSON, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from .db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=_uuid)
    domain = Column(String, nullable=False, index=True)
    days = Column(Integer, nullable=False)
    limit = Column(Integer, nullable=False)
    candidate_limit = Column(Integer, nullable=False, default=600)
    status = Column(String, nullable=False, default="queued")  # queued|running|done|error
    error_message = Column(Text, nullable=True)
    candidate_count = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    results = relationship(
        "Result",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="desc(Result.score)",
    )


class Result(Base):
    __tablename__ = "results"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    candidate_domain = Column(String, nullable=False)
    score = Column(Integer, nullable=False, default=0)
    label = Column(String, nullable=False)
    signals = Column(JSON, nullable=False, default=list)
    evidence = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="results")


class ScanLock(Base):
    """Singleton row (id=1) that gates the single-scan-at-a-time worker."""

    __tablename__ = "scan_lock"

    id = Column(Integer, primary_key=True)
    running_scan_id = Column(String, nullable=True)


class Brand(Base):
    """A brand domain on the live watchlist. The watcher fuzzy-matches every
    domain seen on the certificate-transparency stream against active
    brands' tokens, independent of and in addition to on-demand scans.
    """

    __tablename__ = "brands"

    id = Column(String, primary_key=True, default=_uuid)
    domain = Column(String, nullable=False, unique=True, index=True)
    brand_token = Column(String, nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    hits = relationship(
        "WatchHit",
        back_populates="brand",
        cascade="all, delete-orphan",
        order_by="desc(WatchHit.discovered_at)",
    )


class WatchHit(Base):
    """A domain the live watcher matched against a brand and enriched/scored.
    One row per (brand, domain) — a domain is only ever processed once per
    brand even if its certificate shows up on the stream again.
    """

    __tablename__ = "watch_hits"
    __table_args__ = (UniqueConstraint("brand_id", "candidate_domain", name="uq_watch_hit_brand_domain"),)

    id = Column(String, primary_key=True, default=_uuid)
    brand_id = Column(String, ForeignKey("brands.id"), nullable=False, index=True)
    candidate_domain = Column(String, nullable=False)
    match_score = Column(Integer, nullable=False, default=0)  # fuzzy-match ratio, 0-100
    score = Column(Integer, nullable=False, default=0)  # brand-protection score, 0-100
    label = Column(String, nullable=False)
    signals = Column(JSON, nullable=False, default=list)
    evidence = Column(JSON, nullable=False, default=dict)
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    brand = relationship("Brand", back_populates="hits")
