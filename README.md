# EigenGuard

A security intelligence platform in three parts: an SSH honeypot that records
the credentials attackers actually submit, a React dashboard that visualises
them in real time, and an ML pipeline that classifies HTTP traffic with
genuinely held-out evaluation.

Authentication at the honeypot **always fails**. No shell is ever granted, no
command is ever executed. The point is to observe.

---

## Quick start

```bash
# 1. honeypot + REST API
pip install -r honeypot/requirements.txt
bash honeypot/start.sh

# 2. dashboard
npm --prefix dashboard install
npm --prefix dashboard run dev      # http://localhost:5173

# 3. generate traffic to look at
python3 scripts/simulate_ssh_attacks.py --port 2222
```

| Service | Port | URL |
|---|---|---|
| SSH honeypot | 2222 | `ssh -p 2222 root@localhost` |
| REST API | 8000 | http://localhost:8000/docs |
| Dashboard | 5173 | http://localhost:5173 |
| HTTP logger | 3000 | http://localhost:3000 |

`bash honeypot/stop.sh` shuts down the honeypot and the API.

---

## Components

### SSH honeypot — `honeypot/`

Python, paramiko, FastAPI, SQLite.

A real SSH server. It completes the key exchange, presents a persistent host
key, and advertises `password` and `keyboard-interactive`, so every credential a
client submits reaches the process and is stored verbatim.

Two tables, not one wide table:

* `sessions` — one row per TCP connection, holding 29 CIC-IDS2017-style flow
  features measured from bytes that actually crossed the socket.
* `attempts` — one row per credential.

That split matters. A brute forcer trying 40 passwords on one connection
produces 40 attempt rows. The original single-table design collapsed that into
one record and lost the credentials, which are the entire point.

Sessions are classified `ssh-bruteforce` or `ssh-recon` against a configurable
threshold, and every row carries the reason.

### Dashboard — `dashboard/`

React 18, Vite, Tailwind, Recharts.

Eight stat cards, a 24-hour timeline, a world map of attacker origins,
credential rankings, and a filterable session table with a detail drawer
showing full flow metrics and every credential submitted on that connection.

It polls every three seconds and keeps the last good reading on screen if the
API goes away, so a restart does not read as data loss.

### HTTP logger — `http_logger/`

Node's built-in `http` module, zero dependencies.

Appends one NDJSON line per request. Append-only by design: the previous
implementation rewrote the entire log on every request, which is O(n) per
request and corrupts the file if the process dies mid-write.

### ML pipeline — `ml/`

Python, pandas, scikit-learn.

Generates a labelled dataset by **running the real tools** — `sqlmap`, `nikto`,
`nmap`, `ffuf`, `dirb` — against the logger, then extracts 37 numeric features
and trains and evaluates classifiers.

---

## Results

From `data/http_dataset.csv` — 22,360 rows, 79.4% attack, seed 42.
Full detail in [docs/model_card.md](docs/model_card.md).

### Random forest, held-out test set

| Metric | Score |
|---|---|
| Accuracy | 0.9982 |
| Precision | 0.9992 |
| Recall | 0.9986 |
| F1 | 0.9989 |
| ROC-AUC | 0.9997 |

### Leave-one-attack-tool-out

The number above should not be read as "99.8% detection". Holding out an entire
scanner removes the shortcut of recognising it by user agent alone:

| Held-out tool | Recall | Precision |
|---|---|---|
| `nmap` | 0.8868 | 1.0000 |
| `dirb` | 0.7850 | 1.0000 |
| `ffuf` | 0.2547 | 1.0000 |
| `nikto` | 0.0683 | 1.0000 |
| `sqlmap` | **0.0000** | 0.0000 |

**Mean recall on an unseen tool: 0.3989** — about a fortieth of the random-split
F1. Precision stays at 1.0 throughout, so the failure mode is missed attacks,
not false alarms. The feature set learns *path-probing* behaviour and does not
transfer to *injection-payload* behaviour it has never seen.

This gap is reported rather than hidden, because it is the finding.

### Isolation forest, unsupervised

Flags 2,236 of 22,360 requests. Against the labels it was never shown:
precision 0.8394, recall 0.1058, F1 0.1879.

Accuracy 0.2743 is expected rather than broken. With 79% of traffic hostile,
"rare" and "malicious" are not the same thing.

---

## Testing

```bash
bash scripts/smoke_test.sh
```

| Suite | Count | What it covers |
|---|---|---|
| `honeypot/tests` | 23 | Real SSH handshake, credential capture, flow metrics, every API endpoint |
| `ml/tests` | 23 | Feature extraction, literal token matching, label independence |
| `http_logger/test` | 7 | NDJSON logging, stats, export, clear |
| `dashboard` | 29 | Unit formatting, and the app rendered against a real API payload |

The honeypot tests start a real paramiko server on an ephemeral port and connect
with a real client. Nothing is mocked at the socket boundary.

The dashboard includes a contract test that renders `App` against a payload
shaped like the honeypot API's. That test exists because the previous dashboard
requested `/api/attacks` and read fields like `flow_duration` and
`syn_flag_count` that the API never returned, so it rendered a permanent
"Loading…" screen.

---

## Repository layout

```
Eigenguard/
├── honeypot/                SSH honeypot + FastAPI
│   ├── eigenguard/
│   │   ├── ssh_server.py    paramiko transport, credential capture
│   │   ├── flow.py          packet events → 29 CIC flow features
│   │   ├── db.py            SQLAlchemy models
│   │   ├── geo.py           GeoLite2, degrades to Unknown
│   │   ├── api.py           read-only REST layer
│   │   └── config.py        every value overridable via EG_* env vars
│   ├── tests/
│   ├── start.sh / stop.sh
│   └── requirements.txt
├── dashboard/               React + Vite dashboard
│   ├── src/lib/api.ts       typed API client
│   ├── src/lib/format.ts    pure formatters (unit-tested)
│   ├── src/types/api.ts     mirrors the API columns exactly
│   └── src/__tests__/       component contract test
├── http_logger/             dependency-free Node logger
├── ml/
│   ├── generate_dataset.py  labels by provenance, using real tools
│   ├── features.py          37 numeric features, label never used
│   ├── train.py             supervised + unsupervised evaluation
│   └── tests/
├── scripts/
│   ├── simulate_ssh_attacks.py   real SSH client traffic
│   └── smoke_test.sh             every suite
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── model_card.md
│   └── deployment.md
└── data/                    dataset, metrics, feature importance
```

---

## Configuration

Everything is overridable by environment variable; see
`honeypot/eigenguard/config.py` and [docs/api.md](docs/api.md).

| Variable | Default | Meaning |
|---|---|---|
| `EG_SSH_PORT` | `2222` | SSH honeypot port |
| `EG_BRUTE_FORCE_THRESHOLD` | `3` | Attempts before a session counts as brute force |
| `EG_MAX_AUTH_ATTEMPTS` | `20` | Drop a client past this many attempts |
| `EG_AUTH_DELAY` | `0.15` | Delay before answering auth, defeats parallel guessing |
| `EG_API_PORT` | `8000` | REST API port |
| `EG_CORS_ORIGINS` | `*` | Tighten this before exposing the API |
| `EG_GEOIP_ENABLED` | `true` | Set `false` to skip geo lookups |

---

## Notes on methodology

Two things this project deliberately does not do.

**It does not derive labels from features.** The previous implementation inferred
its own ground truth by matching request contents against a hand-written rule
list, then scored a model trained on those same features. The number measured
how carefully the rules were written. Here, labels come from which tool sent
each request, recorded by log-line boundaries during generation.

**It does not report an unsupervised score as detection accuracy.** Isolation
forest accuracy against a 79%-attack dataset is a property of the class
balance, not of the model. Both models are reported, with the difference
explained.

There is also no comparison to published CIC-IDS2017 numbers here. The labels
are generated rather than imported, so the figures are not comparable to results
on those datasets.

## Requirements

* Python 3.9+ — `pip install -r honeypot/requirements.txt -r ml/requirements.txt`
* Node 18+ — `npm --prefix dashboard install`
* Optional: `sqlmap`, `nikto`, `nmap`, `ffuf`, `dirb` to regenerate the dataset
* Optional: [GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
  for geolocation. Without it, locations record as `Unknown`.

## Licence

MIT