# Architecture

EigenGuard is three cooperating components. Each one is independently runnable
and independently tested, because the interesting question is what happens at
the seams between them.

```
                        ┌──────────────────────────────────────┐
  internet ──SSH──────▶ │  honeypot/            paramiko        │
                        │  SSH server :2222                     │
                        │    · records credentials             │
                        │    · measures real flow bytes        │
                        │    · refuses every login             │
                        └───────────────┬──────────────────────┘
                                        │ sessions + attempts
                                        ▼
                        ┌──────────────────────────────────────┐
                        │  honeypot/            FastAPI :8000   │
                        │  read-only REST API over SQLite      │
                        └───────────────┬──────────────────────┘
                                        │ /api/sessions, /api/stats
                                        ▼
                        ┌──────────────────────────────────────┐
                        │  dashboard/          React + Vite    │
                        │  live view on :5173                  │
                        └──────────────────────────────────────┘

  HTTP traffic ──▶ http_logger/ :3000 ──NDJSON──▶ ml/ ──▶ metrics + CSV
```

## 1. SSH honeypot (`honeypot/`)

A real SSH server built on [paramiko](https://www.paramiko.org/). It completes
the key exchange, presents a host key, and advertises `password` and
`keyboard-interactive` authentication, so **every credential a client submits
reaches the process and is recorded verbatim**.

Authentication always fails. Channel, shell, exec and forwarding requests are
all refused. The honeypot observes; it never serves.

| Module | Responsibility |
|---|---|
| `ssh_server.py` | Listener, paramiko `Transport` per socket, credential capture |
| `flow.py` | Packet events → 29 CIC-style flow features |
| `db.py` | SQLAlchemy models: `sessions` and `attempts` |
| `geo.py` | GeoLite2 lookups that degrade to `Unknown` instead of raising |
| `api.py` | Read-only REST layer |
| `config.py` | Every value overridable with an `EG_*` environment variable |

### Two tables, not one

`sessions` holds one row per TCP connection with the flow metrics. `attempts`
holds one row per credential. Splitting them matters: a single brute-force
connection trying 40 passwords produces 40 attempt rows. The original single
wide table collapsed that into one lossy record and lost the credentials.

### Flow features are measured, not estimated

`CountingSocket` in `ssh_server.py` timestamps and sizes every read and write.
`flow.py` turns that event stream into the feature names used by CIC-IDS2017
(`flow_iat_mean`, `down_up_ratio`, `avg_fwd_segment_size`, …), so the values
describe bytes that actually crossed the socket.

**Unit note:** durations are stored in **seconds**. Some published CIC-IDS2017
dumps use microseconds. The dashboard divides by nothing and labels the column
accordingly — the earlier dashboard divided seconds by 1e6 and rendered every
connection as `0.00s`.

### Classification

`CredentialRecorder.classify()` compares the attempt count against
`EG_BRUTE_FORCE_THRESHOLD` (default 3):

* `ssh-bruteforce` — at or above the threshold
* `ssh-recon` — banner exchange with no or few attempts

The threshold lives in configuration, not in the code.

## 2. Dashboard (`dashboard/`)

React 18 + Vite + Tailwind + Recharts. Polls the API every three seconds and
renders eight stat cards, a 24-hour timeline, a world map, credential rankings
and a session table.

Two decisions worth knowing:

* **Types mirror the API.** `src/types/api.ts` is a transcription of the columns
  in `db.py`. The previous version of this dashboard declared its own invented
  shape (`flow_duration`, `syn_flag_count`, `command`) and requested
  `/api/attacks`, an endpoint that never existed, so it rendered nothing.
  `src/__tests__/App.test.tsx` renders the app against a real payload to keep
  that from coming back.
* **Relative API base.** `vite.config.ts` proxies `/api` to the honeypot, so
  development needs no CORS setup and no hard-coded port. Override with
  `VITE_API_BASE`.

## 3. HTTP logger (`http_logger/`)

Dependency-free Node HTTP server. Appends one NDJSON line per request, which is
what the ML pipeline reads.

Two properties were deliberately chosen:

* **Append-only.** The original read the whole log into memory and rewrote it on
  every request — O(n) per request, and a crash mid-write corrupted the file.
* **Control endpoints excluded.** `/api/*` introspection paths are not counted as
  traffic, otherwise a dashboard polling `/api/stats` would appear in the
  dataset as synthetic activity.

## 4. ML pipeline (`ml/`)

Feature extraction, training and honest evaluation over HTTP traffic.

```
ml/generate_dataset.py  →  data/http_dataset.csv   (labels from provenance)
ml/features.py          →  37 numeric features, label never used
ml/train.py             →  data/model_metrics.json + feature importance PNG
```

The labels come from *which tool sent each request*, never from inspecting the
request. See [model_card.md](model_card.md) for what the reported numbers do and
do not mean.

## Data flow

1. An SSH client connects to `:2222`.
2. `ssh_server.py` performs the handshake and records every credential offered.
3. Bytes are counted per direction and reduced to flow features.
4. On disconnect, one `sessions` row plus N `attempts` rows are written.
5. `api.py` serves the rows; the dashboard polls and renders.
6. GeoLite2 resolves the source IP when the database is present, and the
   location is recorded as `Private Network` / `Unknown` when it is not.