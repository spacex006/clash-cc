"""
geo.py — تشخیص کشور proxy ها بر اساس IP واقعی.
"""

from __future__ import annotations

import socket
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────────────
# تنظیمات
# ──────────────────────────────────────────────────────────────────────────────

MMDB_PATH = Path("Country.mmdb")
DNS_TIMEOUT = 2.0
DNS_WORKERS = 100


def country_flag(code: str) -> str:
    """تبدیل کد ISO به emoji پرچم."""
    if not code or len(code) != 2 or code == "XX":
        return "🏳"
    code = code.upper()
    return "".join(chr(ord(c) + 127397) for c in code)


# ──────────────────────────────────────────────────────────────────────────────
# IP detection
# ──────────────────────────────────────────────────────────────────────────────

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def is_ipv4(addr: str) -> bool:
    return bool(_IPV4_RE.match(addr or ""))


def is_ip(addr: str) -> bool:
    if not addr:
        return False
    if is_ipv4(addr):
        return True
    if ":" in addr and not addr.startswith("/"):
        # IPv6 ساده
        try:
            socket.inet_pton(socket.AF_INET6, addr)
            return True
        except (OSError, ValueError):
            return False
    return False


def resolve_dns(host: str) -> Optional[str]:
    """تبدیل domain به IP."""
    if not host:
        return None
    if is_ip(host):
        return host
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        return socket.gethostbyname(host)
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# GeoIP lookup
# ──────────────────────────────────────────────────────────────────────────────

_reader = None


def _get_reader():
    global _reader
    if _reader is None:
        if not GEOIP_AVAILABLE:
            raise RuntimeError("geoip2 نصب نیست. pip install geoip2")
        if not MMDB_PATH.exists():
            raise RuntimeError(f"فایل {MMDB_PATH} یافت نشد.")
        _reader = geoip2.database.Reader(str(MMDB_PATH))
    return _reader


def lookup_country(ip: str) -> str:
    """کد ISO کشور از IP."""
    if not ip:
        return "XX"
    try:
        reader = _get_reader()
        response = reader.country(ip)
        return response.country.iso_code or "XX"
    except Exception:
        return "XX"


# ──────────────────────────────────────────────────────────────────────────────
# Pipeline اصلی
# ──────────────────────────────────────────────────────────────────────────────

def _process_one(idx: int, p: Dict) -> Tuple[int, str, str]:
    """resolve IP و country رو انجام میده."""
    server = str(p.get("server", "")).strip()
    ip = resolve_dns(server)
    if not ip:
        return idx, "XX", server  # IP پیدا نشد، از خود server استفاده کن
    country = lookup_country(ip)
    return idx, country, ip


def annotate_countries(proxies: List[Dict]) -> List[Dict]:
    """
    تشخیص کشور و بازنویسی نام proxy ها به فرمت:
    🇺🇸 US1 | 1.2.3.4:443
    """
    if not GEOIP_AVAILABLE:
        print("  [geo] ⚠ geoip2 نصب نیست — رد میشه")
        return proxies
    if not MMDB_PATH.exists():
        print(f"  [geo] ⚠ {MMDB_PATH} یافت نشد — رد میشه")
        return proxies

    # ── DNS resolve + country lookup موازی ─────────────────────────────
    countries: Dict[int, str] = {}
    ips: Dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as ex:
        futures = [ex.submit(_process_one, i, p) for i, p in enumerate(proxies)]
        done = 0
        for fut in as_completed(futures):
            try:
                idx, country, ip = fut.result()
            except Exception:
                continue
            countries[idx] = country
            ips[idx] = ip
            done += 1
            if done % 200 == 0:
                print(f"  [geo] {done}/{len(proxies)} resolved")

    # ── بازنویسی نام proxy ها با شماره‌گذاری بر اساس کشور ──────────────
    country_counter: Dict[str, int] = defaultdict(int)
    result: List[Dict] = []

    for i, p in enumerate(proxies):
        country = countries.get(i, "XX")
        ip = ips.get(i, p.get("server", ""))
        port = p.get("port", 0)

        country_counter[country] += 1
        idx_in_country = country_counter[country]

        flag = country_flag(country)

        # فرمت: 🇺🇸 US1 | 1.2.3.4:443
        new_name = f"{flag} {country}{idx_in_country} | {ip}:{port}"
        new_name = new_name[:80]

        p = dict(p)
        p["_country"] = country
        p["_resolved_ip"] = ip
        p["name"] = new_name
        result.append(p)

    # ── نمایش آمار ─────────────────────────────────────────────────────
    counter = Counter(p.get("_country", "XX") for p in result)
    print(f"\n  [geo] توزیع کشورها:")
    for country, cnt in counter.most_common(20):
        flag = country_flag(country)
        print(f"    {flag} {country:<4} {cnt:>4}")

    return result
