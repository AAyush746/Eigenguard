"""GeoIP resolution for honeypot visitors.

Uses a local MaxMind GeoLite2-City database when it is available. Everything
degrades gracefully: private addresses are labelled as such and a missing or
unreadable database yields `Unknown` rather than an exception, so a honeypot
never drops a connection because a geo lookup failed.
"""
from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass
from typing import Optional

from .config import config

UNKNOWN = {
    "country": "Unknown",
    "country_code": "XX",
    "city": "Unknown",
    "region": "Unknown",
    "latitude": None,
    "longitude": None,
    "is_private": False,
    "source": "unknown",
}


@dataclass(frozen=True)
class GeoLocation:
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    region: str = "Unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_private: bool = False
    source: str = "unknown"

    def as_dict(self) -> dict:
        return {
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "region": self.region,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "is_private": self.is_private,
            "source": self.source,
        }


def _is_private(ip: ipaddress._BaseAddress) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


class GeoIPResolver:
    """Thread-safe wrapper around a MaxMind GeoLite2 City database."""

    def __init__(self, db_path=None, enabled: bool = True):
        self.db_path = db_path or config.geoip_db_path
        self.enabled = enabled
        self._reader = None
        self._lock = threading.Lock()
        self._load_error: Optional[str] = None
        if self.enabled:
            self._load()

    def _load(self) -> None:
        if not self.db_path or not self.db_path.exists():
            self._load_error = f"database not found at {self.db_path}"
            return
        try:
            import geoip2.database  # imported lazily so it stays optional
            import geoip2.errors
        except ImportError as exc:
            self._load_error = f"geoip2 is not installed ({exc})"
            return
        try:
            self._reader = geoip2.database.Reader(str(self.db_path))
        except Exception as exc:  # corrupt file, bad permissions, ...
            self._load_error = f"could not open database: {exc}"
            return
        self._load_error = None

    @property
    def available(self) -> bool:
        return self._reader is not None

    @property
    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "available": self.available,
            "database_path": str(self.db_path),
            "error": self._load_error,
        }

    def lookup(self, raw_ip: str) -> GeoLocation:
        """Resolve an IP address. Never raises."""
        if not raw_ip:
            return GeoLocation()

        # Normalise IPv4-mapped IPv6 such as ::ffff:1.2.3.4
        cleaned = raw_ip.strip()
        if cleaned.startswith("::ffff:"):
            cleaned = cleaned[7:]

        try:
            ip = ipaddress.ip_address(cleaned)
        except ValueError:
            return GeoLocation(source="invalid")

        if _is_private(ip):
            return GeoLocation(
                country="Private Network",
                country_code="LAN",
                city="LAN",
                region="LAN",
                is_private=True,
                source="private",
            )

        if not self.enabled:
            return GeoLocation(source="disabled")

        with self._lock:
            if self._reader is None:
                return GeoLocation(source="unavailable")
            try:
                response = self._reader.city(cleaned)
            except Exception:
                # Address not in the database, or the DB has no city record.
                return GeoLocation(source="not-found")

        subdivision = ""
        if response.subdivisions:
            subdivision = response.subdivisions.most_specific.name or ""

        return GeoLocation(
            country=response.country.name or "Unknown",
            country_code=response.country.iso_code or "XX",
            city=response.city.name or "Unknown",
            region=subdivision or "Unknown",
            latitude=response.location.latitude,
            longitude=response.location.longitude,
            source="geoip2",
        )

    def close(self) -> None:
        with self._lock:
            if self._reader is not None:
                self._reader.close()
                self._reader = None


_resolver: Optional[GeoIPResolver] = None
_resolver_lock = threading.Lock()


def get_resolver() -> GeoIPResolver:
    """Return the process-wide resolver, creating it on first use."""
    global _resolver
    if _resolver is None:
        with _resolver_lock:
            if _resolver is None:
                _resolver = GeoIPResolver()
    return _resolver


def get_location(raw_ip: str) -> dict:
    """Backwards-compatible helper returning a plain dict."""
    return get_resolver().lookup(raw_ip).as_dict()