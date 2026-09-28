import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Text
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
