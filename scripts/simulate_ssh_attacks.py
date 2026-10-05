#!/usr/bin/env python3
"""Drive realistic SSH brute-force traffic at the EigenGuard honeypot.

The honeypot only records what a real SSH client sends it, so demonstrating the
dashboard needs real client traffic. This script is a real paramiko client: it
performs the genuine SSH handshake and submits genuine credentials, so every row
it produces in the database was captured from an actual SSH conversation rather
than inserted by hand.

Attack shapes it reproduces:

* **dictionary sweep** - one connection, many passwords for one account
* **credential stuffing** - many common username/password pairs
* **user enumeration** - one password tried against many accounts
* **reconnaissance** - connect and disconnect without authenticating
* **single guess** - a lone login attempt, e.g. a worm scanning the internet

Usage
-----
    python3 scripts/simulate_ssh_attacks.py --port 2222
    python3 scripts/simulate_ssh_attacks.py --port 2222 --rounds 5
    python3 scripts/simulate_ssh_attacks.py --list-passwords

The honeypot refuses every credential by design, so a successful login here is a
bug in the honeypot, not a win.
"""
from __future__ import annotations

import argparse
import random
import socket
import sys
import time
from typing import List, Tuple

import paramiko

# Passwords observed in real SSH brute-force telemetry. Ordered by how often
# they turn up, because the distribution matters: `root`/`123456` should
# dominate the dashboard the way it does on a real exposed host.
COMMON_PASSWORDS = [
    "123456",
    "password",
    "123456789",
    "12345",
    "12345678",
    "root",
    "admin",
    "toor",
    "qwerty",
    "abc123",
    "111111",
    "123123",
    "welcome",
    "letmein",
    "monkey",
    "dragon",
    "iloveyou",
    "sunshine",
    "princess",
    "football",
    "passw0rd",
    "default",
    "changeme",
    "P@ssw0rd",
    "1q2w3e4r",
    "test",
    "guest",
    "master",
    "ubnt",
    "pi",
    "vagrant",
    "alpine",
    "raspberry",
]

# Accounts attackers actually try, with rough relative frequency. Kept as
# (user, weight) pairs so the weights cannot drift out of sync with the list.
COMMON_USERS: List[Tuple[str, int]] = [
    ("root", 40),
    ("admin", 20),
    ("user", 6),
    ("ubuntu", 5),
    ("pi", 4),
    ("test", 3),
    ("guest", 3),
    ("oracle", 2),
    ("mysql", 2),
    ("postgres", 2),
    ("git", 2),
    ("deploy", 2),
    ("support", 2),
    ("ftp", 2),
]

USER_NAMES = [name for name, _ in COMMON_USERS]
USER_WEIGHTS = [weight for _, weight in COMMON_USERS]

# Key pairs attackers actually use, so the credential pairs look like real
# stuffing rather than random noise.
CRED_PAIRS = [
    ("root", "root"),
    ("root", "toor"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("user", "user"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("test", "test"),
    ("guest", "guest"),
    ("oracle", "oracle"),
    ("deploy", "deploy"),
]


def try_passwords(
    host: str,
    port: int,
    username: str,
    passwords: List[str],
    think_time: float = 0.12,
) -> int:
    """Open one connection and submit each password in turn.

    A single transport is reused on purpose: this is what a brute forcer does,
    and it is what makes the honeypot record many attempts under one session.
    """
    submitted = 0
    transport = None
    try:
        transport = paramiko.Transport(socket.create_connection((host, port), timeout=10))
        transport.start_client(timeout=10)

        for password in passwords:
            try:
                transport.auth_password(username, password)
                print(
                    f"    !! honeypot accepted {username}:{password} — this is a bug",
                    file=sys.stderr,
                )
            except paramiko.AuthenticationException:
                submitted += 1
            except paramiko.SSHException as exc:
                # The honeypot drops a session at max_auth_attempts, and closes
                # on transport errors. Both are correct behaviour.
                print(f"    transport closed after {submitted} attempt(s): {exc}")
                break
            time.sleep(think_time)
    except (paramiko.SSHException, OSError) as exc:
        print(f"    connection error: {exc}")
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
    return submitted


def dictionary_sweep(host: str, port: int, rng: random.Random) -> int:
    """One account, many passwords - the most common shape by far."""
    username = rng.choices(USER_NAMES, weights=USER_WEIGHTS, k=1)[0]
    passwords = rng.sample(COMMON_PASSWORDS, k=rng.randint(8, 20))
    print(f"  dictionary sweep as '{username}' with {len(passwords)} passwords")
    return try_passwords(host, port, username, passwords)


def credential_stuffing(host: str, port: int, rng: random.Random) -> int:
    """One known-default pair per connection."""
    pairs = rng.sample(CRED_PAIRS, k=rng.randint(4, 10))
    print(f"  credential stuffing with {len(pairs)} common pairs")
    total = 0
    for username, password in pairs:
        total += try_passwords(host, port, username, [password], think_time=0.05)
        time.sleep(rng.uniform(0.05, 0.3))
    return total


def user_enumeration(host: str, port: int, rng: random.Random) -> int:
    """One password, many accounts - looking for a weak password."""
    password = rng.choice(["root", "admin", "123456", "password"])
    users = rng.sample(USER_NAMES, k=rng.randint(5, 12))
    print(f"  user enumeration with '{password}' across {len(users)} accounts")
    total = 0
    for username in users:
        total += try_passwords(host, port, username, [password], think_time=0.05)
        time.sleep(rng.uniform(0.02, 0.15))
    return total


def reconnaissance(host: str, port: int, rng: random.Random | None = None) -> int:
    """Connect, read the banner, and leave without authenticating.

    Takes ``rng`` for a uniform signature with the other shapes even though a
    banner grab needs no randomness.
    """
    print("  reconnaissance: banner grab with no authentication")
    transport = None
    try:
        transport = paramiko.Transport(socket.create_connection((host, port), timeout=10))
        transport.start_client(timeout=10)
        print(f"    banner: {transport.remote_version}")
    except (paramiko.SSHException, OSError) as exc:
        print(f"    error: {exc}")
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
    return 0


def single_guess(host: str, port: int, rng: random.Random) -> int:
    """One lone attempt, like a worm stepping through the address space."""
    username = rng.choice(USER_NAMES)
    password = rng.choice(COMMON_PASSWORDS)
    print(f"  single guess {username}:{password}")
    return try_passwords(host, port, username, [password], think_time=0)


ATTACKS = {
    "sweep": dictionary_sweep,
    "stuffing": credential_stuffing,
    "enumerate": user_enumeration,
    "recon": reconnaissance,
    "single": single_guess,
}


def wait_for_honeypot(host: str, port: int, timeout: float = 10.0) -> bool:
    """Block until the honeypot accepts a TCP connection."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", default="127.0.0.1", help="honeypot host")
    parser.add_argument(
        "--port", type=int, default=2222, help="honeypot SSH port (EG_SSH_PORT)"
    )
    parser.add_argument(
        "--rounds", type=int, default=3, help="how many times to run the mix"
    )
    parser.add_argument(
        "--attacks",
        nargs="*",
        choices=sorted(ATTACKS),
        default=sorted(ATTACKS),
        help="attack shapes to run",
    )
    parser.add_argument("--seed", type=int, default=None, help="reproducible randomness")
    parser.add_argument(
        "--list-passwords", action="store_true", help="print the password corpus"
    )
    args = parser.parse_args()

    if args.list_passwords:
        for password in COMMON_PASSWORDS:
            print(password)
        return 0

    rng = random.Random(args.seed)
    shapes = [name for name in sorted(ATTACKS) if name in args.attacks]

    print(f"target {args.host}:{args.port}")
    if not wait_for_honeypot(args.host, args.port):
        print(
            f"nothing is listening on {args.host}:{args.port}.\n"
            "Start the honeypot first:  bash honeypot/start.sh",
            file=sys.stderr,
        )
        return 1

    total = 0
    for round_number in range(1, max(1, args.rounds) + 1):
        print(f"\nround {round_number}/{max(1, args.rounds)}")
        for name in shapes:
            total += ATTACKS[name](args.host, args.port, rng)
            time.sleep(rng.uniform(0.1, 0.5))

    print(f"\nsubmitted approximately {total} credential attempts")
    print("View them at the dashboard, or export with:")
    print(f"  curl -s http://localhost:8000/api/export/attempts.csv | head")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())