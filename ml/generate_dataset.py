#!/usr/bin/env python3
"""Build a labelled HTTP traffic dataset by generating real traffic.

Why this exists
---------------
The original dataset had ~100 rows and the labels were inferred from the log
contents by a hand-written rule set, then used to score a model that was
trained on those same rules. That is circular: the accuracy measured nothing.

This script instead creates ground truth by *provenance*. It drives real
traffic against the logger and knows which generator produced each request:

* benign  - ordinary browsing and API usage
* sqlmap  - the real sqlmap binary, SQL injection probing
* nikto   - the real nikto binary, web vulnerability scanner
* nmap    - the real nmap HTTP scripts, port/service probing
* ffuf    - the real ffuf binary, directory brute force
* dirb    - the real dirb binary, directory brute force

Because the label comes from *who sent the request* rather than from inspecting
its contents, a model evaluated on this data is being tested on a real signal.

Usage
-----
    python3 ml/generate_dataset.py --out data/http_dataset.csv
    python3 ml/generate_dataset.py --attacks-only     # skip benign
    python3 ml/generate_dataset.py --tools sqlmap nikto
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "EigenGuardDemoClient/1.0 (+https://example.invalid/bot)",
]

BENIGN_PATHS = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/pricing",
    "/docs",
    "/docs/getting-started",
    "/blog",
    "/blog/how-we-monitor-traffic",
    "/api/demo/items",
    "/api/demo/status",
    "/api/demo/items?page=1",
    "/api/demo/items?page=2",
    "/assets/app.css",
    "/assets/app.js",
    "/images/logo.svg",
    "/images/hero.png",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/health",
    "/version",
]

# Non-browser benign clients. Without these, "has a browser user agent"
# becomes a perfect label because every attacker tool identifies itself.
AUXILIARY_USER_AGENTS = [
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "EigenGuardMonitor/1.0 (+health-check)",
    "Wget/1.21.3",
    "Zabbix/7.0",
    "Prometheus/2.48.0",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
]

ATTACK_USER_AGENTS = {
    "sqlmap": "sqlmap/1.8.2#stable (https://sqlmap.org)",
    "nikto": "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)",
    "nmap": "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "ffuf": "ffuf/2.1.0",
    "dirb": "Mozilla/5.00 (Dirb/2.28)",
}


# --------------------------------------------------------------------------
# logger process control
# --------------------------------------------------------------------------
def find_free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def find_http_port(start: int = 8080, span: int = 40) -> int:
    """Find a port that scanners recognise as an HTTP service.

    This matters for nmap: its NSE scripts are matched on service name, and a
    bare high port is detected as "unknown", so ``http-enum`` and friends are
    skipped entirely. Binding on a port from the http-proxy range makes nmap
    classify the service correctly and actually run the scripts.
    """
    for candidate in range(start, start + span):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", candidate))
            except OSError:
                continue
        return candidate
    # Nothing in the well-known range was free; fall back to any free port.
    return find_free_port()


def start_logger(port: int, log_file: Path) -> subprocess.Popen:
    env = dict(os.environ, EG_DATA_DIR=str(log_file.parent))
    proc = subprocess.Popen(
        ["node", "http_logger/server.js"],
        cwd=str(REPO_ROOT),
        env=dict(env, PORT=str(port)),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            raise RuntimeError(f"logger exited early:\n{stderr}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return proc
        except OSError:
            time.sleep(0.15)
    proc.kill()
    raise RuntimeError("logger did not start listening in time")


def stop_logger(proc: subprocess.Popen, log_file: Path) -> int:
    """Shut the logger down and return the number of records it wrote."""
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    return count_log_lines(log_file)


def count_log_lines(log_file: Path) -> int:
    if not log_file.exists():
        return 0
    with log_file.open() as handle:
        return sum(1 for _ in handle)


# --------------------------------------------------------------------------
# benign traffic
# --------------------------------------------------------------------------
def generate_benign(port: int, requests: int, seed: int = 7) -> int:
    """Simulate ordinary browsing traffic.

    Two details matter for keeping the dataset honest:

    * Requests are issued from a thread pool. The attack tools run with high
      concurrency, so generating benign traffic sequentially would make
      response time a giveaway and let the model separate the classes on
      latency alone.
    * Non-browser user agents are included. Real servers see crawlers,
      monitoring probes and API clients, so a dataset in which every benign
      request is a browser would make the user agent a trivial label.
    """
    from concurrent.futures import ThreadPoolExecutor

    import urllib.error
    import urllib.request

    rng = random.Random(seed)
    base = f"http://127.0.0.1:{port}"
    sent = 0

    def one_request(url: str, user_agent: str) -> bool:
        try:
            req = urllib.request.Request(
                base + url,
                headers={"User-Agent": user_agent, "Accept": "*/*"},
            )
            with urllib.request.urlopen(req, timeout=5):
                return True
        except urllib.error.HTTPError:
            return True  # a 404 is still logged
        except Exception:
            return False

    tasks = []
    for _ in range(max(1, requests // 6)):
        # Each "user" browses a handful of pages, like a real session.
        user_agent = rng.choice(BENIGN_USER_AGENTS)
        for _ in range(rng.randint(3, 8)):
            tasks.append((rng.choice(BENIGN_PATHS), user_agent))
            # A small fraction of sessions also come from a non-browser client.
            if rng.random() < 0.25:
                tasks.append((rng.choice(BENIGN_PATHS), rng.choice(AUXILIARY_USER_AGENTS)))

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(one_request, url, agent) for url, agent in tasks]
        for future in futures:
            if future.result():
                sent += 1
            # A light pause keeps the rate realistic without serialising.
            if rng.random() < 0.15:
                time.sleep(rng.uniform(0.001, 0.01))
    return sent


# --------------------------------------------------------------------------
# real attack tools
# --------------------------------------------------------------------------
def run_tool(command: List[str], timeout: int = 180) -> bool:
    """Run an attack tool, tolerating its absence or a non-zero exit."""
    binary = command[0]
    if shutil.which(binary) is None:
        print(f"    ! {binary} is not installed, skipping")
        return False
    try:
        subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # A tool that hangs is still useful: it has usually fired off plenty
        # of requests by the time the timeout fires.
        pass
    return True


def attack_sqlmap(port: int, timeout: int = 180) -> bool:
    """Real SQL injection probing against the demo endpoint."""
    # --forms makes sqlmap hunt for HTML forms on the page; with none present
    # it exits after a couple of requests, so the parameter is given directly.
    return run_tool(
        [
            "sqlmap",
            "-u",
            f"http://127.0.0.1:{port}/api/demo/items?id=1",
            "--batch",
            "-p",
            "id",
            "--level=3",
            "--risk=2",
            "--technique=BEUSTQ",
            "--threads=4",
            "--timeout=10",
            "--retries=1",
            "--no-logging",
        ],
        timeout=timeout,
    )


def attack_nikto(port: int, timeout: int = 240) -> bool:
    """Real web vulnerability scanning."""
    return run_tool(
        ["nikto", "-h", f"http://127.0.0.1:{port}", "-Tuning", "1234bde", "-timeout", "8"],
        timeout=timeout,
    )


def attack_nmap(port: int, timeout: int = 240) -> bool:
    """Real Nmap NSE HTTP probing.

    The scripts are chosen from the http-* family and the port must be one
    nmap classifies as HTTP, otherwise the service is detected as "unknown"
    and every script is skipped.
    """
    return run_tool(
        [
            "nmap",
            "-sT",
            "-Pn",
            "-p",
            str(port),
            "--script",
            "http-enum,http-shellshock,http-default-accounts,http-passwd,"
            "http-config-backup,http-vhosts,http-methods,http-headers",
            "--script-args",
            f"http.useragent={ATTACK_USER_AGENTS['nmap']}",
            "127.0.0.1",
        ],
        timeout=timeout,
    )


def attack_ffuf(port: int, timeout: int = 180) -> bool:
    """Real directory brute forcing."""
    wordlist = Path("/usr/share/dirb/wordlists/common.txt")
    if not wordlist.exists():
        wordlist = Path("/usr/share/wordlists/dirb/common.txt")
    if not wordlist.exists():
        print("    ! no dirb wordlist found, skipping ffuf")
        return False
    return run_tool(
        [
            "ffuf",
            "-u",
            f"http://127.0.0.1:{port}/FUZZ",
            "-w",
            str(wordlist),
            "-t",
            "20",
            "-timeout",
            "8",
            "-noninteractive",
            "-s",
        ],
        timeout=timeout,
    )


def attack_dirb(port: int, timeout: int = 180) -> bool:
    """Real directory brute forcing with dirb."""
    wordlist = Path("/usr/share/dirb/wordlists/common.txt")
    if not wordlist.exists():
        print("    ! no dirb wordlist found, skipping dirb")
        return False
    return run_tool(
        [
            "dirb",
            f"http://127.0.0.1:{port}",
            str(wordlist),
            "-r",
            "-S",
        ],
        timeout=timeout,
    )


ATTACK_RUNNERS: Dict[str, Callable[..., bool]] = {
    "sqlmap": attack_sqlmap,
    "nikto": attack_nikto,
    "nmap": attack_nmap,
    "ffuf": attack_ffuf,
    "dirb": attack_dirb,
}


# --------------------------------------------------------------------------
# labelling and export
# --------------------------------------------------------------------------
def label_requests(log_file: Path, blocks: List[tuple]) -> List[dict]:
    """Attach a label to every logged record using known block boundaries.

    ``blocks`` is a list of ``(label, count)`` pairs in the order the traffic
    was generated. The logger only ever appends, so slicing the log by the
    number of lines present after each stage recovers the exact boundaries.
    Nothing is inferred from the request contents, which is what makes the
    resulting labels usable as ground truth.
    """
    with log_file.open() as handle:
        records = [json.loads(line) for line in handle if line.strip()]

    labelled: List[dict] = []
    cursor = 0
    for label, count in blocks:
        chunk = records[cursor : cursor + count]
        cursor += count
        for record in chunk:
            record["label"] = label
            record["source"] = "generated"
            labelled.append(record)

    # Anything past the accounted-for blocks could not be attributed, so it is
    # dropped rather than guessed at.
    leftover = len(records) - cursor
    if leftover > 0:
        print(f"  dropping {leftover} unattributable request(s)")
    return labelled


def to_csv(records: List[dict], out_path: Path) -> None:
    if not records:
        raise SystemExit("no records captured; nothing to write")
    columns = [
        "timestamp",
        "ip",
        "method",
        "path",
        "query",
        "contentLength",
        "userAgent",
        "referer",
        "status",
        "responseTime",
        "responseSize",
        "label",
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=str(REPO_ROOT / "data" / "http_dataset.csv"),
        help="path for the labelled CSV",
    )
    parser.add_argument(
        "--log",
        default=str(REPO_ROOT / "data" / "generated" / "http_requests.ndjson"),
        help="where the logger writes while generating",
    )
    parser.add_argument(
        "--benign",
        type=int,
        default=1200,
        help="number of benign requests to generate",
    )
    parser.add_argument(
        "--tools",
        nargs="*",
        default=list(ATTACK_RUNNERS),
        help="attack tools to run",
    )
    parser.add_argument(
        "--attacks-only",
        action="store_true",
        help="skip benign traffic (for augmenting an existing capture)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="per-tool timeout in seconds",
    )
    args = parser.parse_args()

    tools = [t for t in args.tools if t in ATTACK_RUNNERS]
    if not tools:
        print("no valid attack tools selected", file=sys.stderr)
        return 2

    log_file = Path(args.log)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.write_text("")

    # Prefer a port nmap recognises as HTTP so its NSE scripts actually run.
    port = find_http_port() if "nmap" in tools else find_free_port()
    print(f"starting logger on 127.0.0.1:{port}")
    logger_proc = start_logger(port, log_file)

    # Blocks are recorded as (label, cumulative line count) so that each stage
    # can be sliced out of the log exactly.
    blocks: List[tuple] = []
    try:
        if not args.attacks_only:
            print(f"generating {args.benign} benign requests...")
            generate_benign(port, args.benign)
            # The logger appends asynchronously, so give it a moment to drain.
            time.sleep(1.0)
            benign_count = count_log_lines(log_file)
            blocks.append(("benign", benign_count))
            print(f"  benign requests logged: {benign_count}")

        previous = blocks[-1][1] if blocks else 0
        for tool in tools:
            print(f"running {tool} against the logger...")
            if not ATTACK_RUNNERS[tool](port, timeout=args.timeout):
                continue
            time.sleep(0.5)
            current = count_log_lines(log_file)
            produced = current - previous
            previous = current
            if produced:
                blocks.append((tool, produced))
                print(f"  {tool} produced {produced} requests")
    finally:
        total = stop_logger(logger_proc, log_file)

    print(f"total requests logged: {total}")
    if total == 0:
        print("the logger recorded nothing", file=sys.stderr)
        return 1

    records = label_requests(log_file, blocks)
    if not records:
        print("no records could be labelled", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    to_csv(records, out_path)

    counts = Counter(r["label"] for r in records)
    print(f"\nwrote {len(records)} labelled rows to {out_path}")
    for label, count in counts.most_common():
        print(f"  {label:<14} {count}")
    print(
        f"  {'benign':<14} {counts.get('benign', 0)} "
        f"(attack total {len(records) - counts.get('benign', 0)})"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())