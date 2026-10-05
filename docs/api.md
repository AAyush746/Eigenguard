# Honeypot API

Read-only REST API over the honeypot database. Served by `honeypot/eigenguard/api.py`
on port 8000 by default. Interactive documentation is at `/docs`.

The API never accepts a write. Authentication is rejected by the SSH server, so
there is no credential here that could grant access to anything.

## Configuration

Every value comes from `honeypot/eigenguard/config.py` and is overridable:

| Variable | Default | Meaning |
|---|---|---|
| `EG_SSH_HOST` | `0.0.0.0` | SSH listen address |
| `EG_SSH_PORT` | `2222` | SSH listen port |
| `EG_SSH_BANNER` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` | Version string presented to clients |
| `EG_BRUTE_FORCE_THRESHOLD` | `3` | Attempts before a session is labelled brute force |
| `EG_MAX_AUTH_ATTEMPTS` | `20` | Session is dropped past this many attempts |
| `EG_AUTH_DELAY` | `0.15` | Seconds to wait before answering an auth request |
| `EG_API_HOST` / `EG_API_PORT` | `0.0.0.0` / `8000` | API bind address |
| `EG_DATABASE_URL` | `sqlite:///honeypot/data/honeypot.db` | SQLAlchemy URL |
| `EG_GEOIP_ENABLED` | `true` | Set `false` to skip geo lookups |
| `EG_CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `EG_LOG_LEVEL` | `INFO` | Python logging level |

## Endpoints

### `GET /health`

```json
{ "status": "ok" }
```

### `GET /api/health`

Adds GeoIP status, which is the usual cause of "the map is empty":

```json
{
  "status": "ok",
  "geoip": {
    "enabled": true,
    "available": true,
    "database_path": ".../honeypot/data/GeoLite2-City.mmdb",
    "error": null
  }
}
```

`available: false` means `honeypot/data/GeoLite2-City.mmdb` is missing or
`geoip2` is not installed. Sessions are still recorded; locations come back
`Unknown`. See [deployment.md](deployment.md#geoip).

### `GET /api/sessions`

Most recent connections, newest first.

| Parameter | Default | Range | Meaning |
|---|---|---|---|
| `limit` | `100` | 1–2000 | Page size |
| `offset` | `0` | ≥0 | Rows to skip |
| `label` | — | — | `ssh-bruteforce` or `ssh-recon` |
| `include_attempts` | `false` | — | Embed each session's first N credentials |
| `attempts_per_session` | `5` | 1–100 | Cap when `include_attempts` is set |

```json
{
  "total": 66,
  "limit": 100,
  "offset": 0,
  "results": [
    {
      "id": 66,
      "started_at": "2026-10-05T16:36:14.724383",
      "ended_at": "2026-10-05T16:36:17.327305",
      "duration_seconds": 2.6029224395751953,
      "src_ip": "203.0.113.10",
      "src_port": 60376,
      "dst_port": 2222,
      "country": "China",
      "country_code": "CN",
      "city": "Shanghai",
      "latitude": 31.2304,
      "longitude": 121.4737,
      "geo_source": "geoip2",
      "client_version": "SSH-2.0-OpenSSH_8.9p1",
      "attempt_count": 3,
      "label": "ssh-bruteforce",
      "detection_reason": "3 failed auth attempts (threshold 3)",
      "total_fwd_packets": 12,
      "flow_bytes_per_second": 3052.72,
      "average_packet_size": 175.5,
      "attempts": [
        { "id": 1, "username": "root", "password": "123456",
          "auth_method": "password", "success": false }
      ]
    }
  ]
}
```

`attempts` is present only when `include_attempts=true`, and is always an array
— empty for recon sessions that never authenticated.

### `GET /api/sessions/{id}`

One session with its **complete** attempt list. `404` if unknown.

### `GET /api/attempts`

Credential attempts across all sessions, newest first. `limit` 1–5000, default
200.

### `GET /api/stats`

Aggregate counters, computed in SQL-friendly single passes:

```json
{
  "total_sessions": 66,
  "total_attempts": 78,
  "sessions_today": 66,
  "attempts_today": 78,
  "unique_ips": 1,
  "unique_countries": 1,
  "bruteforce_sessions": 2,
  "top_countries": [{ "name": "China", "count": 12 }],
  "top_usernames": [{ "name": "root", "count": 18 }],
  "top_passwords": [{ "name": "123456", "count": 9 }],
  "avg_flow_duration": 4.25,
  "max_flow_rate": 2048.0,
  "avg_packet_size": 175.5,
  "avg_attempts_per_session": 3.26,
  "first_seen": "2026-10-05T16:30:00",
  "last_seen": "2026-10-05T16:36:14"
}
```

With an empty database every counter is `0` and the three `top_*` arrays are
`[]`; the endpoint never returns `null` for them.

### `GET /api/timeline?days=14`

Daily session counts, oldest first.

### `GET /api/export/attempts.csv`

Every captured credential as CSV, joined with source IP and location. Returns
`404` when nothing has been captured yet.

```bash
curl -s http://localhost:8000/api/export/attempts.csv -o credentials.csv
```

## Timestamp handling

Timestamps are stored naive and interpreted as **UTC**. `_as_utc()` in
`api.py` attaches the timezone where it is missing, so a session recorded at
`16:36:14` is bucketed under the correct day regardless of the server's local
timezone.

## Client examples

```bash
# Recent brute-force sessions with their credentials
curl -s 'http://localhost:8000/api/sessions?label=ssh-bruteforce&include_attempts=true'

# Everything submitted today
curl -s 'http://localhost:8000/api/attempts?limit=500'

# Feed the ML feature extractor
curl -s http://localhost:8000/api/export/attempts.csv > /tmp/creds.csv
```

From the dashboard, `src/lib/api.ts` wraps these in typed functions and
`src/types/api.ts` mirrors every field above.