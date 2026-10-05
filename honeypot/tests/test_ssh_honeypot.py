"""End-to-end tests for the SSH honeypot.

These start the real server on an ephemeral port and connect with a real
paramiko client, so they exercise the actual SSH handshake and credential
capture path rather than mocking it.
"""
from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from pathlib import Path

import paramiko
import pytest

# Point the honeypot at a throwaway database before anything imports config.
_TMP = tempfile.mkdtemp(prefix="eigenguard-test-")
os.environ.setdefault("EG_DATABASE_URL", f"sqlite:///{Path(_TMP) / 'test.db'}")
os.environ.setdefault("EG_AUTH_DELAY", "0")
os.environ.setdefault("EG_BRUTE_FORCE_THRESHOLD", "3")

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eigenguard.config import config  # noqa: E402
from eigenguard.db import Attempt_, Session_, SessionFactory, init_db  # noqa: E402
from eigenguard.ssh_server import (  # noqa: E402
    SSHServer,
    load_or_create_host_key,
)


@pytest.fixture(scope="module")
def ssh_port() -> int:
    """Reserve a free port and release it for the honeypot to bind."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def running_honeypot(ssh_port):
    """Run the honeypot for the duration of the test module."""
    init_db()
    key = load_or_create_host_key(Path(_TMP) / "host_key")
    server = SSHServer("127.0.0.1", ssh_port, key)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Wait until the listener is accepting connections.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", ssh_port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.05)
    else:  # pragma: no cover - only on a badly broken machine
        pytest.fail("honeypot did not start listening")

    yield ssh_port
    server.stop()


def wait_until(predicate, timeout: float = 5.0, interval: float = 0.05) -> bool:
    """Poll until ``predicate`` is true.

    The honeypot writes the session from its own thread after the socket
    closes, so the client's failure can be observed slightly before the
    corresponding row lands in the database.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def attempt_login(port: int, username: str, password: str) -> None:
    """Try to log in. The honeypot must always refuse."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "127.0.0.1",
            port=port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
        )
    except paramiko.AuthenticationException:
        return  # the expected outcome
    finally:
        client.close()
    pytest.fail("honeypot allowed authentication - this must never happen")


def test_banner_is_a_plausible_openssh_string(running_honeypot):
    transport = paramiko.Transport(socket.create_connection(("127.0.0.1", running_honeypot)))
    transport.start_client()
    try:
        assert transport.remote_version.startswith("SSH-2.0-")
        assert "OpenSSH" in transport.remote_version
    finally:
        transport.close()


def test_authentication_is_always_refused(running_honeypot):
    attempt_login(running_honeypot, "admin", "hunter2")


def test_credential_is_captured_verbatim(running_honeypot):
    """The password stored must be the one the client actually sent."""
    marker_user = "capture-probe-user"
    marker_pass = "correct-horse-battery-staple"

    attempt_login(running_honeypot, marker_user, marker_pass)

    def stored():
        db = SessionFactory()
        try:
            return (
                db.query(Attempt_)
                .filter(Attempt_.username == marker_user)
                .all()
            )
        finally:
            db.close()

    assert wait_until(lambda: bool(stored())), "the submitted username was not recorded"

    rows = stored()
    assert rows[-1].password == marker_pass
    assert rows[-1].success is False
    assert rows[-1].auth_method == "password"


def test_every_attempt_in_one_session_is_recorded(running_honeypot):
    """Repeated passwords on one connection become distinct attempt rows."""
    before = _session_count()

    transport = paramiko.Transport(
        socket.create_connection(("127.0.0.1", running_honeypot))
    )
    transport.start_client()
    try:
        for password in ("first-guess", "second-guess", "third-guess"):
            try:
                transport.auth_password("multi-probe", password)
            except paramiko.AuthenticationException:
                pass  # expected: the honeypot refuses every attempt
            time.sleep(0.05)
    finally:
        transport.close()

    assert wait_until(
        lambda: _session_count() == before + 1
    ), "the multi-attempt session was not stored"

    db = SessionFactory()
    try:
        session = (
            db.query(Session_)
            .filter(Session_.attempt_count >= 3)
            .order_by(Session_.id.desc())
            .first()
        )
        assert session is not None, "no session recorded three or more attempts"
        passwords = {
            a.password
            for a in db.query(Attempt_).filter(Attempt_.session_id == session.id).all()
        }
        assert passwords >= {"first-guess", "second-guess", "third-guess"}
    finally:
        db.close()


def test_session_gets_flow_metrics_and_classification(running_honeypot):
    attempt_login(running_honeypot, "flow-probe", "pw")

    def latest():
        db = SessionFactory()
        try:
            return (
                db.query(Session_)
                .filter(Session_.attempt_count == 1)
                .order_by(Session_.id.desc())
                .first()
            )
        finally:
            db.close()

    assert wait_until(lambda: latest() is not None), "no session was recorded"

    db = SessionFactory()
    try:
        session = latest()
        # Real bytes crossed the socket during the SSH handshake.
        assert session.total_length_bwd_packets > 0, "no server bytes recorded"
        assert session.duration_seconds >= 0
        assert session.label in {"ssh-bruteforce", "ssh-recon"}
        assert session.detection_reason
        assert session.attempt_count >= 1
    finally:
        db.close()


def test_private_addresses_are_not_geo_mapped(running_honeypot):
    """127.0.0.1 must be reported as a private network, not a real country."""
    db = SessionFactory()
    try:
        session = db.query(Session_).order_by(Session_.id.desc()).first()
        assert session.country == "Private Network"
        assert session.geo_source == "private"
        assert session.latitude is None
    finally:
        db.close()


def _session_count() -> int:
    db = SessionFactory()
    try:
        return db.query(Session_).count()
    finally:
        db.close()