"""Tests for the read-only REST API."""
from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_TMP = tempfile.mkdtemp(prefix="eigenguard-api-test-")
os.environ["EG_DATABASE_URL"] = f"sqlite:///{Path(_TMP) / 'api.db'}"
os.environ["EG_AUTH_DELAY"] = "0"

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eigenguard.api import app  # noqa: E402
from eigenguard.db import (  # noqa: E402
    Attempt_,
    Session_,
    SessionFactory,
    get_db,
    init_db,
)


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def seeded(client):
    """Insert one brute-force session with three attempts."""
    db = SessionFactory()
    try:
        session = Session_(
            src_ip="203.0.113.10",
            src_port=55512,
            dst_port=2222,
            country="Netherlands",
            country_code="NL",
            city="Amsterdam",
            latitude=52.37,
            longitude=4.89,
            client_version="SSH-2.0-OpenSSH_8.2",
            attempt_count=3,
            label="ssh-bruteforce",
            detection_reason="3 failed auth attempts (threshold 3)",
            duration_seconds=4.2,
            total_length_fwd_packets=900,
            total_length_bwd_packets=1200,
            flow_bytes_per_second=500.0,
            average_packet_size=175.0,
        )
        db.add(session)
        db.flush()
        for user, password in (("root", "123456"), ("root", "admin"), ("admin", "root")):
            db.add(
                Attempt_(
                    session_id=session.id,
                    username=user,
                    password=password,
                    auth_method="password",
                    success=False,
                )
            )
        db.commit()
        session_id = session.id
    finally:
        db.close()
    yield session_id


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_root_reports_geoip_status(client):
    body = client.get("/").json()
    assert body["service"] == "eigenguard-honeypot-api"
    assert "geoip" in body


def test_stats_reflects_seeded_rows(client, seeded):
    body = client.get("/api/stats").json()
    assert body["total_attempts"] >= 3
    assert body["unique_ips"] >= 1
    assert body["bruteforce_sessions"] >= 1
    usernames = {entry["name"] for entry in body["top_usernames"]}
    assert {"root", "admin"} <= usernames
    passwords = {entry["name"] for entry in body["top_passwords"]}
    assert "123456" in passwords


def test_stats_handles_an_empty_database(client):
    """The dashboard must not break when there is nothing to show."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from eigenguard.db import Base

    # A private, empty database so this check is independent of seeded rows.
    engine = create_engine(f"sqlite:///{Path(_TMP) / 'empty.db'}")
    Base.metadata.create_all(engine)
    empty_factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db():
        db = empty_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as isolated:
            body = isolated.get("/api/stats").json()
        assert body["total_sessions"] == 0
        assert body["total_attempts"] == 0
        assert body["top_countries"] == []
        assert body["top_usernames"] == []
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_sessions_endpoint_paginates(client, seeded):
    body = client.get("/api/sessions", params={"limit": 1}).json()
    assert body["limit"] == 1
    assert len(body["results"]) == 1
    assert body["total"] >= 1


def test_sessions_can_be_filtered_by_label(client, seeded):
    body = client.get("/api/sessions", params={"label": "ssh-bruteforce"}).json()
    assert body["total"] >= 1
    assert all(row["label"] == "ssh-bruteforce" for row in body["results"])


def test_sessions_omit_attempts_by_default(client, seeded):
    """The nested list is opt-in so the default response stays small."""
    body = client.get("/api/sessions", params={"limit": 50}).json()
    assert all("attempts" not in row for row in body["results"])


def test_sessions_can_embed_their_attempts(client, seeded):
    """The dashboard needs credentials per row without a second request."""
    body = client.get(
        "/api/sessions",
        params={"limit": 50, "include_attempts": True},
    ).json()

    row = next(r for r in body["results"] if r["id"] == seeded)
    assert row["attempt_count"] == 3
    assert len(row["attempts"]) == 3
    assert {a["password"] for a in row["attempts"]} == {"123456", "admin", "root"}
    assert all(a["session_id"] == seeded for a in row["attempts"])


def test_embedded_attempts_are_capped(client, seeded):
    """A 500-password session must not ship 500 rows to the browser."""
    body = client.get(
        "/api/sessions",
        params={"limit": 50, "include_attempts": True, "attempts_per_session": 2},
    ).json()

    row = next(r for r in body["results"] if r["id"] == seeded)
    assert len(row["attempts"]) == 2


def test_sessions_with_no_attempts_get_an_empty_list(client, seeded):
    """Recon-only sessions must still carry the key, or the UI has to guess."""
    db = SessionFactory()
    try:
        recon = Session_(
            src_ip="203.0.113.99",
            src_port=40000,
            attempt_count=0,
            label="ssh-recon",
            detection_reason="banner exchange with no authentication attempt",
        )
        db.add(recon)
        db.commit()
        recon_id = recon.id
    finally:
        db.close()

    body = client.get(
        "/api/sessions",
        params={"limit": 50, "include_attempts": True},
    ).json()
    row = next(r for r in body["results"] if r["id"] == recon_id)
    assert row["attempts"] == []


def test_attempts_per_session_is_validated(client, seeded):
    response = client.get(
        "/api/sessions",
        params={"include_attempts": True, "attempts_per_session": 0},
    )
    assert response.status_code == 422


def test_session_detail_includes_attempts(client, seeded):
    body = client.get(f"/api/sessions/{seeded}").json()
    assert body["src_ip"] == "203.0.113.10"
    assert len(body["attempts"]) == 3
    assert {a["password"] for a in body["attempts"]} == {"123456", "admin", "root"}


def test_unknown_session_returns_404(client):
    assert client.get("/api/sessions/999999").status_code == 404


def test_attempts_endpoint_returns_credentials(client, seeded):
    body = client.get("/api/attempts").json()
    assert body["total"] >= 3
    assert any(row["username"] == "root" for row in body["results"])


def test_csv_export_is_downloadable(client, seeded):
    response = client.get("/api/export/attempts.csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    text = response.text
    assert "session_id" in text
    assert "203.0.113.10" in text


def test_timeline_groups_by_day(client, seeded):
    body = client.get("/api/timeline", params={"days": 30}).json()
    assert body["days"] == 30
    assert isinstance(body["series"], list)


def test_limit_validation_rejects_nonsense(client):
    assert client.get("/api/sessions", params={"limit": 0}).status_code == 422
    assert client.get("/api/sessions", params={"limit": 99999}).status_code == 422