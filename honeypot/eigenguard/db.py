"""SQLite persistence for honeypot sessions and credential attempts.

Two tables instead of the original single wide table:

* ``sessions``  - one row per TCP connection, holding the flow-level metrics.
* ``attempts``  - one row per authentication attempt, holding the exact
                  username and password the client sent.

Splitting them means a single brute-force connection that tries 40 passwords
produces 40 attempt rows instead of being collapsed into one lossy record.
"""
from __future__ import annotations

import contextlib
from typing import Iterator, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
    func,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from .config import config

Base = declarative_base()


class Session_(Base):
    """One SSH connection / TCP flow. Named ``Session_`` to avoid clashing
    with SQLAlchemy's own ``Session`` class."""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)

    started_at = Column(DateTime, default=func.now(), index=True)
    ended_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)

    src_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer, default=22)

    country = Column(String, index=True)
    country_code = Column(String)
    city = Column(String)
    region = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    geo_source = Column(String)

    client_version = Column(String, index=True)
    kex_algorithm = Column(String)
    host_key_type = Column(String)
    auth_methods_offered = Column(Text)
    auth_methods_tried = Column(Text)

    # --- flow metrics -------------------------------------------------
    total_fwd_packets = Column(Integer, default=0)
    total_bwd_packets = Column(Integer, default=0)
    total_length_fwd_packets = Column(Integer, default=0)
    total_length_bwd_packets = Column(Integer, default=0)

    flow_bytes_per_second = Column(Float, default=0.0)
    flow_packets_per_second = Column(Float, default=0.0)

    fwd_packet_length_max = Column(Float, default=0.0)
    fwd_packet_length_mean = Column(Float, default=0.0)
    fwd_packet_length_std = Column(Float, default=0.0)
    fwd_packet_length_min = Column(Float, default=0.0)

    bwd_packet_length_max = Column(Float, default=0.0)
    bwd_packet_length_mean = Column(Float, default=0.0)
    bwd_packet_length_std = Column(Float, default=0.0)
    bwd_packet_length_min = Column(Float, default=0.0)

    flow_iat_mean = Column(Float, default=0.0)
    flow_iat_std = Column(Float, default=0.0)
    flow_iat_max = Column(Float, default=0.0)
    flow_iat_min = Column(Float, default=0.0)

    fwd_iat_mean = Column(Float, default=0.0)
    fwd_iat_std = Column(Float, default=0.0)
    fwd_iat_max = Column(Float, default=0.0)

    bwd_iat_mean = Column(Float, default=0.0)
    bwd_iat_std = Column(Float, default=0.0)
    bwd_iat_max = Column(Float, default=0.0)

    down_up_ratio = Column(Float, default=0.0)
    average_packet_size = Column(Float, default=0.0)
    avg_fwd_segment_size = Column(Float, default=0.0)
    avg_bwd_segment_size = Column(Float, default=0.0)

    # --- classification ------------------------------------------------
    attempt_count = Column(Integer, default=0, index=True)
    label = Column(String(32), default="ssh-scan", index=True)
    detection_reason = Column(String, nullable=True)

    __table_args__ = (
        Index("ix_sessions_label_started", "label", "started_at"),
    )


class Attempt_(Base):
    """One authentication attempt: the credential an attacker actually sent."""

    __tablename__ = "attempts"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), index=True)

    username = Column(String, index=True)
    password = Column(String)
    auth_method = Column(String, default="password")
    success = Column(Boolean, default=False)
    attempted_at = Column(DateTime, default=func.now(), index=True)


def _build_engine():
    url = config.database_url
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, future=True, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            # WAL lets the API read while the honeypot writes.
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    return engine


engine = _build_engine()
SessionFactory = sessionmaker(bind=engine, future=True, expire_on_commit=False)


def init_db() -> None:
    """Create tables if they do not exist yet."""
    Base.metadata.create_all(engine)


@contextlib.contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session context manager."""
    db = SessionFactory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def object_as_dict(obj) -> dict:
    """Flatten a SQLAlchemy row into a plain dict."""
    return {
        column.key: getattr(obj, column.key)
        for column in obj.__table__.columns
    }


def get_db():
    """FastAPI dependency yielding a database session."""
    db = SessionFactory()
    try:
        yield db
    finally:
        db.close()