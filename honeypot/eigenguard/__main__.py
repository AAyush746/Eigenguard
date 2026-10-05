"""Entry point for the honeypot REST API.

    python -m eigenguard            # serve the API
    python -m eigenguard.ssh_server # serve the SSH honeypot

The API is started here rather than with a bare ``uvicorn`` command so the
database is created before the first request arrives, and so host and port come
from the same ``EG_*`` environment variables the honeypot reads.
"""
from __future__ import annotations

import uvicorn

from .config import config
from .db import init_db


def main() -> None:
    config.ensure_dirs()
    init_db()

    uvicorn.run(
        "eigenguard.api:app",
        host=config.api_host,
        port=config.api_port,
        log_level=config.log_level.lower(),
    )


if __name__ == "__main__":
    main()