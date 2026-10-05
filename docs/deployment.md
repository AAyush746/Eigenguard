# Deployment and operations

## Running the honeypot

```bash
cd honeypot
pip install -r requirements.txt
bash start.sh              # SSH honeypot + REST API
bash start.sh --with-ui    # also the dashboard, if its node_modules exist
bash stop.sh               # stop everything started by start.sh
```

| Service | Port | Notes |
|---|---|---|
| SSH honeypot | 2222 | Point this at the internet to capture real traffic |
| REST API | 8000 | Docs at `/docs` |
| Dashboard | 5173 | Dev server, proxies `/api` to 8000 |

`start.sh` writes PIDs to `honeypot/.run/` and logs to `honeypot/logs/`.
It refuses to start with a clear message if the Python dependencies are missing.

## Exposing the honeypot

The honeypot is intended to be reachable from untrusted networks. Two rules:

**Never port-forward the API.** It is read-only, but it publishes every captured
credential and is not authenticated. The default `EG_CORS_ORIGINS=*` is meant for
local development; set it to your dashboard's origin in production.

**Use a non-standard SSH port** — 2222 already is. Port 22 attracts a different,
much noisier population of scanners than a high port.

Forwards to consider, from least to most exposure:

```bash
# Only reachable from a VPN subnet
ufw allow from 10.8.0.0/24 to any port 2222 proto tcp

# Bound to one interface
EG_SSH_HOST=203.0.113.10 bash start.sh

# Behind nginx, with the API private
#   stream { server { listen 2222; proxy_pass 127.0.0.1:2222; } }
```

The honeypot's outbound network needs are minimal: it only listens, and it never
connects anywhere except DNS-free GeoLite2 file reads.

## GeoIP

`honeypot/data/GeoLite2-City.mmdb` comes from
[MaxMind's GeoLite2 free database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data),
which requires accepting their licence. It is deliberately **not** committed to
this repository.

Without it the honeypot still records everything; `country`, `city` and
`latitude` come back `Unknown` and `geo_source` is `unavailable`. Check status at
`GET /api/health` — the dashboard shows a "GeoIP offline" badge when
`available` is false.

To disable lookups entirely: `EG_GEOIP_ENABLED=false`.

## Database

SQLite via SQLAlchemy, at `honeypot/data/honeypot.db` by default. The connection
sets `journal_mode=WAL` so the API can read while the honeypot writes.

WAL means three files matter when backing up or moving: `.db`, `.db-wal` and
`.db-shm`. Copying the `.db` alone can lose recent writes.

```bash
# Consistent snapshot
sqlite3 honeypot/data/honeypot.db ".backup '/backup/honeypot-$(date +%F).db'"

# Retention: keep 90 days of sessions
sqlite3 honeypot/data/honeypot.db \
  "DELETE FROM attempts WHERE attempted_at < datetime('now','-90 days');
   DELETE FROM sessions WHERE started_at  < datetime('now','-90 days'); VACUUM;"
```

Set `EG_DATABASE_URL` to point at PostgreSQL instead. The models are portable;
the honeypot has only been exercised against SQLite.

## Logging

Structured lines to `honeypot/logs/{ssh,api}.log` at `EG_LOG_LEVEL`.

Every captured credential is logged at `INFO`:

```
2026-10-05 16:36:17 INFO  eigenguard.honeypot | session=66 203.0.113.10:41234
  label=ssh-bruteforce attempts=10 bytes=8264 client='SSH-2.0-OpenSSH_8.9p1'
    captured auth: user='root' password='123456' via password
```

**These logs are the captured credentials in plaintext.** Treat them as
sensitive: they belong in a directory with restrictive permissions, and should
not be shipped to a log aggregator without redaction.

Set `EG_LOG_LEVEL=WARNING` to record session metadata without credential lines.

## Running the dashboard

```bash
cd dashboard
npm install
npm run dev       # http://localhost:5173, /api proxied to :8000
npm run build     # production bundle into dist/
npm run preview   # serve the built bundle
```

Point the built bundle at a remote API:

```bash
VITE_API_BASE=https://honeypot.example.com npm run build
```

The world map fetches `world-atlas@2` from jsDelivr at runtime. Offline, the map
panel shows "Map unavailable" and every other panel keeps working.

## Running the HTTP logger and ML pipeline

```bash
# 1. log traffic
node http_logger/server.js          # :3000, appends to data/http_requests.ndjson

# 2. generate a labelled dataset (needs the real tools on PATH)
python3 ml/generate_dataset.py --out data/http_dataset.csv

# 3. train and evaluate
python3 ml/train.py --data data/http_dataset.csv
```

`data/http_dataset.csv` is not committed (3.4 MB, reproducible from the step
above). `data/model_metrics.json` and `data/feature_importance.png` are, so the
figures quoted in the README stay reviewable.

`generate_dataset.py` binds a port from 8080 upward when `nmap` is in the tool
list, because nmap's NSE scripts are matched on service name and a bare high port
is detected as `unknown`, which skips them entirely.

## Tests

```bash
bash scripts/smoke_test.sh          # everything
```

Or individually:

```bash
python3 -m pytest honeypot/tests -q   # 23 tests: SSH capture + REST API
python3 -m pytest ml/tests -q         # 23 tests: feature extraction
npm --prefix http_logger test         # 7 tests:  request logger
npm --prefix dashboard test           # 29 tests: formatting + component contract
npm --prefix dashboard run lint
npm --prefix dashboard run typecheck
npm --prefix dashboard run build
```