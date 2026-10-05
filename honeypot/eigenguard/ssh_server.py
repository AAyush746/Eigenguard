"""A real SSH server that records the credentials attackers actually send.

How it works
------------
paramiko implements the server half of the SSH protocol, so this honeypot
speaks real SSH: it performs the key exchange, presents a host key, and
advertises ``password`` and ``keyboard-interactive`` authentication. Every
credential a client submits reaches ``check_auth_*``, where it is recorded.

Authentication is *always* rejected. The attacker never gets a shell, and no
command is ever executed. The point is to observe, not to serve.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional

import paramiko
from paramiko import AUTH_FAILED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, Transport

from .config import config
from .db import Attempt_, Session_, SessionFactory, init_db
from .flow import PacketRecorder
from .geo import get_resolver

logger = logging.getLogger("eigenguard.honeypot")

# Drop a client that has exceeded this many failed attempts.
MAX_SESSION_SECONDS = 600


class CountingSocket:
    """Transparent socket wrapper that timestamps every read and write.

    Flow metrics are computed from bytes crossing this wrapper, which means
    they reflect the real connection rather than an estimate.
    """

    def __init__(self, sock: socket.socket, recorder: "CredentialRecorder"):
        self._sock = sock
        self._recorder = recorder

    def recv(self, *args, **kwargs) -> bytes:
        data = self._sock.recv(*args, **kwargs)
        if data:
            self._recorder.note_bytes("fwd", len(data))
        return data

    def send(self, data, *args, **kwargs):
        sent = self._sock.send(data, *args, **kwargs)
        if sent:
            self._recorder.note_bytes("bwd", sent)
        return sent

    def sendall(self, data, *args, **kwargs):
        self._sock.sendall(data, *args, **kwargs)
        self._recorder.note_bytes("bwd", len(data))

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _fingerprint(key: paramiko.PKey) -> str:
    """Short, stable identifier for a public key."""
    try:
        blob = key.asbytes()
    except Exception:
        blob = str(key).encode()
    digest = hashlib.sha256(blob).digest()
    return f"ssh-{key.get_name()}-{base64.b64encode(digest).decode()[:16]}"


def _parse_interactive_responses(responses) -> tuple:
    """Pull username/password out of keyboard-interactive responses."""
    username, password = "", ""
    for response in responses or ():
        if isinstance(response, tuple) and len(response) == 2:
            prompt, value = response
            prompt = (prompt or "").lower()
            if "user" in prompt:
                username = value or ""
            elif "password" in prompt:
                password = value or ""
        elif not password:
            password = response if isinstance(response, str) else ""
    return username, password


class CredentialRecorder:
    """Buffers everything observed during one connection, then persists it."""

    def __init__(self, peer_host: str, peer_port: int):
        self.peer_host = peer_host
        self.peer_port = peer_port
        self.packets = PacketRecorder()
        self.attempts: List[dict] = []
        self.started_monotonic = time.time()
        self.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self.client_version: Optional[str] = None
        self.kex_algorithm: Optional[str] = None
        self.host_key_type: Optional[str] = None
        self.auth_methods_offered: List[str] = []
        self.auth_methods_tried: List[str] = []
        self._lock = threading.Lock()

    # -- observation -------------------------------------------------------
    def note_bytes(self, direction: str, size: int) -> None:
        self.packets.record(time.time(), direction, size)

    def note_client_version(self, version: str) -> None:
        self.client_version = version

    def note_auth_offer(self, methods) -> None:
        if isinstance(methods, str):
            methods = [m.strip() for m in methods.split(",")]
        self.auth_methods_offered = [m for m in (methods or []) if m]

    def note_kex(self, algorithm: Optional[str]) -> None:
        if algorithm:
            self.kex_algorithm = algorithm

    def note_host_key(self, key_type: Optional[str]) -> None:
        if key_type:
            self.host_key_type = key_type

    def record(self, username: str, password: str, method: str) -> None:
        """Store one credential attempt. Called from the transport thread."""
        with self._lock:
            self.attempts.append(
                {
                    "username": (username or "")[:128],
                    "password": (password or "")[:256],
                    "auth_method": method,
                    "success": False,
                }
            )
            if method not in self.auth_methods_tried:
                self.auth_methods_tried.append(method)

    @property
    def attempt_count(self) -> int:
        return len(self.attempts)

    # -- classification ----------------------------------------------------
    def classify(self) -> tuple:
        """Return (label, reason). Thresholds live in config, not in code."""
        count = self.attempt_count
        threshold = config.brute_force_threshold
        if count >= threshold:
            return (
                "ssh-bruteforce",
                f"{count} failed auth attempts (threshold {threshold})",
            )
        if count == 0:
            return "ssh-recon", "banner exchange with no authentication attempt"
        return "ssh-recon", f"{count} auth attempt(s), below threshold {threshold}"

    # -- persistence --------------------------------------------------------
    def persist(self) -> Optional[int]:
        """Write the session and its attempts. Returns the session id."""
        metrics = self.packets.compute(
            started_at=self.started_monotonic, ended_at=time.time()
        )
        location = get_resolver().lookup(self.peer_host)
        label, reason = self.classify()

        flow_values = metrics.as_dict()
        db = SessionFactory()
        try:
            row = Session_(
                started_at=self.started_at,
                ended_at=datetime.now(timezone.utc).replace(tzinfo=None),
                src_ip=self.peer_host,
                src_port=self.peer_port,
                dst_port=config.ssh_port,
                country=location.country,
                country_code=location.country_code,
                city=location.city,
                region=location.region,
                latitude=location.latitude,
                longitude=location.longitude,
                geo_source=location.source,
                client_version=self.client_version,
                kex_algorithm=self.kex_algorithm,
                host_key_type=self.host_key_type,
                auth_methods_offered=",".join(self.auth_methods_offered),
                auth_methods_tried=",".join(self.auth_methods_tried),
                attempt_count=self.attempt_count,
                label=label,
                detection_reason=reason,
                **flow_values,
            )
            db.add(row)
            db.flush()
            for attempt in self.attempts:
                db.add(Attempt_(session_id=row.id, **attempt))
            db.commit()
            session_id = row.id
        except Exception:
            db.rollback()
            logger.exception("Failed to persist session for %s", self.peer_host)
            session_id = None
        finally:
            db.close()

        if session_id is None:
            return None

        logger.info(
            "session=%s %s:%s label=%s attempts=%d bytes=%d client=%r",
            session_id,
            self.peer_host,
            self.peer_port,
            label,
            self.attempt_count,
            self.packets.total_bytes,
            self.client_version,
        )
        for attempt in self.attempts:
            logger.info(
                "    captured auth: user=%r password=%r via %s",
                attempt["username"],
                attempt["password"],
                attempt["auth_method"],
            )
        return session_id


class HoneypotServerInterface(paramiko.ServerInterface):
    """Records every credential it is offered and refuses all of them."""

    def __init__(self, recorder: CredentialRecorder):
        self.recorder = recorder

    # -- banner -------------------------------------------------------------
    def get_banner(self) -> tuple:
        # paramiko sends "<banner>\r\n<language>\r\n" itself.
        return config.ssh_pre_auth_noise, ""

    # -- authentication ------------------------------------------------------
    def get_allowed_auths(self, username: str) -> str:
        self.recorder.note_auth_offer("password,keyboard-interactive")
        return "password,keyboard-interactive"

    def check_auth_none(self, username: str) -> int:
        self.recorder.record(username, "", "none")
        return AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        self._slow_down()
        self.recorder.record(username, password, "password")
        return AUTH_FAILED

    def check_auth_interactive(self, username: str, submethods: str = "") -> int:
        self.recorder.record(username, "", f"interactive:{submethods or 'none'}")
        return AUTH_FAILED

    def check_auth_interactive_response(self, responses) -> int:
        username, password = _parse_interactive_responses(responses)
        self._slow_down()
        self.recorder.record(username, password, "keyboard-interactive")
        return AUTH_FAILED

    def check_auth_publickey(self, key: paramiko.PKey) -> int:
        # A public-key attempt is reconnaissance, not a credential guess.
        self.recorder.record("", _fingerprint(key), "publickey")
        return AUTH_FAILED

    # -- everything past authentication is refused ----------------------------
    def check_channel_request(self, kind: str, chanid: int) -> int:
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command: bytes) -> int:
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel) -> int:
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args, **kwargs) -> int:
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, address, port) -> int:
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_global_request(self, kind: str, msg: str) -> int:
        return AUTH_FAILED

    def _slow_down(self) -> None:
        """Pace authentication replies so parallel guessing gains nothing."""
        if config.auth_delay > 0:
            time.sleep(config.auth_delay)


class SSHServer:
    """Threaded TCP listener that drives one paramiko transport per socket."""

    def __init__(self, host: str, port: int, host_key: paramiko.RSAKey):
        self.host = host
        self.port = port
        self.host_key = host_key
        self._listener: Optional[socket.socket] = None
        self._stop = threading.Event()

    def _watchdog(self, transport: Transport, recorder: CredentialRecorder) -> None:
        """Enforce the attempt ceiling and an overall session time limit."""
        while not self._stop.is_set():
            time.sleep(0.5)
            if not transport.is_active():
                return
            exceeded = recorder.attempt_count >= config.max_auth_attempts
            expired = time.time() - recorder.started_monotonic > MAX_SESSION_SECONDS
            if exceeded or expired:
                logger.info(
                    "closing %s (%s)",
                    recorder.peer_host,
                    "attempt limit reached" if exceeded else "session timeout",
                )
                transport.close()
                return

    def _handle(self, client_socket: socket.socket, address) -> None:
        peer_host, peer_port = address[0], address[1]
        recorder = CredentialRecorder(peer_host, peer_port)

        transport = Transport(CountingSocket(client_socket, recorder))
        transport.local_version = config.ssh_banner
        transport.add_server_key(self.host_key)
        interface = HoneypotServerInterface(recorder)

        done = threading.Event()

        def _finish():
            done.set()

        try:
            transport.start_server(server=interface)
            recorder.note_client_version(transport.remote_version or "")
            recorder.note_kex(getattr(transport, "kex_engine", None) and
                              getattr(transport.kex_engine, "agreed_algo", None))
            recorder.note_host_key(transport.host_key_type)

            threading.Thread(
                target=self._watchdog, args=(transport, recorder), daemon=True
            ).start()

            while transport.is_active() and not done.is_set():
                time.sleep(0.2)
        except Exception as exc:
            logger.debug("connection error from %s:%s: %s", peer_host, peer_port, exc)
        finally:
            try:
                transport.close()
            except Exception:
                pass
            recorder.persist()

    def serve_forever(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, self.port))
        self._listener.listen(128)
        self._listener.settimeout(0.5)
        logger.info(
            "SSH honeypot listening on %s:%d | banner %s",
            self.host,
            self.port,
            config.ssh_banner,
        )
        try:
            while not self._stop.is_set():
                try:
                    client_socket, address = self._listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                client_socket.settimeout(30)
                threading.Thread(
                    target=self._handle,
                    args=(client_socket, address),
                    daemon=True,
                    name=f"ssh-{address[0]}:{address[1]}",
                ).start()
        finally:
            self._listener.close()
            logger.info("SSH honeypot stopped")

    def stop(self) -> None:
        self._stop.set()


def load_or_create_host_key(path) -> paramiko.RSAKey:
    """Load the honeypot host key, generating it on first run.

    A stable key makes repeat connections look like a real server instead of
    one that regenerates its identity on every restart.
    """
    if path.exists():
        try:
            return paramiko.RSAKey.from_private_key_file(str(path))
        except Exception as exc:
            logger.warning("unreadable host key %s (%s), regenerating", path, exc)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    path.chmod(0o600)
    logger.info("generated honeypot host key at %s", path)
    return key


def run() -> None:
    """Entry point for the honeypot process."""
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    )
    config.ensure_dirs()
    init_db()

    resolver = get_resolver()
    if resolver.available:
        logger.info("GeoIP ready (GeoLite2-City)")
    else:
        logger.warning(
            "GeoIP unavailable (%s); locations recorded as Unknown",
            resolver.status["error"],
        )

    host_key = load_or_create_host_key(config.host_key_path)
    SSHServer(config.ssh_host, config.ssh_port, host_key).serve_forever()


if __name__ == "__main__":
    run()