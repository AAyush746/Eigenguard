"""Read-only REST API over honeypot sessions and credential attempts."""
from __future__ import annotations

import csv
import io
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .config import config
from .db import Attempt_, Session_, get_db, init_db, object_as_dict
from .geo import get_resolver

app = FastAPI(
    title="EigenGuard Honeypot API",
    version="1.0.0",
    description=(
        "Read-only API exposing SSH honeypot sessions and the credentials "
        "attackers actually submitted."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.api_cors_origins,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Ensure the database exists before the first request is served."""
    init_db()
    yield


app.router.lifespan_context = lifespan


@app.get("/")
def read_root() -> dict:
    resolver = get_resolver()
    return {
        "service": "eigenguard-honeypot-api",
        "version": app.version,
        "geoip": resolver.status,
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/health")
def api_health() -> dict:
    return {"status": "ok", "geoip": get_resolver().status}


@app.get("/api/sessions")
def list_sessions(
    limit: int = Query(default=100, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    label: Optional[str] = Query(default=None),
    include_attempts: bool = Query(
        default=False,
        description=(
            "Embed the first N credential attempts of each session. The "
            "dashboard needs them to render a credential column without a "
            "second round trip."
        ),
    ),
    attempts_per_session: int = Query(default=5, ge=1, le=100),
    db: Session = Depends(get_db),
) -> dict:
    """Most recent honeypot connections, newest first."""
    query = db.query(Session_)
    if label:
        query = query.filter(Session_.label == label)
    total = query.count()
    rows = (
        query.order_by(Session_.started_at.desc(), Session_.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    results = [object_as_dict(row) for row in rows]
    if include_attempts:
        by_session = _attempts_by_session(
            db, [row.id for row in rows], attempts_per_session
        )
        for payload in results:
            payload["attempts"] = by_session.get(payload["id"], [])

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "results": results,
    }


@app.get("/api/sessions/{session_id}")
def get_session(session_id: int, db: Session = Depends(get_db)) -> dict:
    row = db.get(Session_, session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="session not found")
    payload = object_as_dict(row)
    payload["attempts"] = [
        object_as_dict(a)
        for a in db.query(Attempt_)
        .filter(Attempt_.session_id == session_id)
        .order_by(Attempt_.id)
        .all()
    ]
    return payload


@app.get("/api/attempts")
def list_attempts(
    limit: int = Query(default=200, ge=1, le=5000),
    db: Session = Depends(get_db),
) -> dict:
    """Credential attempts, newest first."""
    total = db.query(Attempt_).count()
    rows = (
        db.query(Attempt_)
        .order_by(Attempt_.attempted_at.desc(), Attempt_.id.desc())
        .limit(limit)
        .all()
    )
    return {"total": total, "results": [object_as_dict(r) for r in rows]}


@app.get("/api/stats")
def stats(db: Session = Depends(get_db)) -> dict:
    """Aggregate counters used by the dashboard."""
    session_rows = db.query(Session_).all()
    total_sessions = len(session_rows)

    if total_sessions == 0:
        return {
            "total_sessions": 0,
            "total_attempts": 0,
            "sessions_today": 0,
            "attempts_today": 0,
            "unique_ips": 0,
            "unique_countries": 0,
            "bruteforce_sessions": 0,
            "top_countries": [],
            "top_usernames": [],
            "top_passwords": [],
            "avg_flow_duration": 0.0,
            "max_flow_rate": 0.0,
            "avg_packet_size": 0.0,
            "avg_attempts_per_session": 0.0,
            "first_seen": None,
            "last_seen": None,
        }

    today = datetime.now(timezone.utc).date()
    attempts = db.query(Attempt_).all()

    sessions_today = sum(
        1 for s in session_rows if _as_utc(s.started_at).date() == today
    )
    attempts_today = sum(
        1 for a in attempts if _as_utc(a.attempted_at).date() == today
    )

    countries = Counter(s.country or "Unknown" for s in session_rows)
    usernames = Counter(a.username for a in attempts if a.username)
    passwords = Counter(a.password for a in attempts if a.password)

    durations = [s.duration_seconds or 0.0 for s in session_rows]
    rates = [s.flow_bytes_per_second or 0.0 for s in session_rows]
    sizes = [s.average_packet_size or 0.0 for s in session_rows]

    return {
        "total_sessions": total_sessions,
        "total_attempts": len(attempts),
        "sessions_today": sessions_today,
        "attempts_today": attempts_today,
        "unique_ips": len({s.src_ip for s in session_rows if s.src_ip}),
        "unique_countries": len(countries),
        "bruteforce_sessions": sum(1 for s in session_rows if s.label == "ssh-bruteforce"),
        "top_countries": _top(countries, 5),
        "top_usernames": _top(usernames, 5),
        "top_passwords": _top(passwords, 5),
        "avg_flow_duration": sum(durations) / len(durations),
        "max_flow_rate": max(rates) if rates else 0.0,
        "avg_packet_size": sum(sizes) / len(sizes) if sizes else 0.0,
        "avg_attempts_per_session": len(attempts) / total_sessions,
        "first_seen": min(
            (_as_utc(s.started_at) for s in session_rows if s.started_at),
            default=None,
        ).isoformat() if any(s.started_at for s in session_rows) else None,
        "last_seen": max(
            (_as_utc(s.started_at) for s in session_rows if s.started_at),
            default=None,
        ).isoformat() if any(s.started_at for s in session_rows) else None,
    }


@app.get("/api/timeline")
def timeline(days: int = Query(default=14, ge=1, le=365), db: Session = Depends(get_db)) -> dict:
    """Daily counts of sessions and attempts, oldest first."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.query(Session_).all()

    per_day: Counter = Counter()
    for row in rows:
        if row.started_at:
            per_day[_as_utc(row.started_at).date().isoformat()] += 1

    return {
        "days": days,
        "series": [
            {"date": day, "sessions": count}
            for day, count in sorted(per_day.items())
        ],
    }


@app.get("/api/export/attempts.csv")
def export_attempts(db: Session = Depends(get_db)):
    """All captured credentials as CSV."""
    rows = db.query(Attempt_).order_by(Attempt_.attempted_at.desc()).all()
    if not rows:
        raise HTTPException(status_code=404, detail="no attempts recorded yet")

    sessions = {s.id: s for s in db.query(Session_).all()}

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "session_id",
            "attempted_at",
            "src_ip",
            "src_port",
            "country",
            "country_code",
            "city",
            "username",
            "password",
            "auth_method",
            "success",
            "session_label",
        ]
    )
    for attempt in rows:
        session = sessions.get(attempt.session_id)
        writer.writerow(
            [
                attempt.session_id,
                attempt.attempted_at,
                session.src_ip if session else "",
                session.src_port if session else "",
                session.country if session else "",
                session.country_code if session else "",
                session.city if session else "",
                attempt.username,
                attempt.password,
                attempt.auth_method,
                attempt.success,
                session.label if session else "",
            ]
        )

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=eigenguard_attempts.csv"
        },
    )


def _attempts_by_session(
    db: Session, session_ids: List[int], per_session: int
) -> dict:
    """Group credential attempts by session id, capped at ``per_session`` each.

    Two queries rather than one per session, so a page of 500 sessions costs
    the same as a page of 1.
    """
    if not session_ids:
        return {}

    rows = (
        db.query(Attempt_)
        .filter(Attempt_.session_id.in_(session_ids))
        .order_by(Attempt_.session_id, Attempt_.id)
        .all()
    )

    grouped: dict = {}
    for row in rows:
        bucket = grouped.setdefault(row.session_id, [])
        if len(bucket) < per_session:
            bucket.append(object_as_dict(row))
    return grouped


def _as_utc(value: Optional[datetime]) -> datetime:
    """Treat naive timestamps as UTC, which is how they are stored."""
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _top(counter: Counter, n: int) -> List[dict]:
    return [{"name": name, "count": count} for name, count in counter.most_common(n)]