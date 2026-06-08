"""
geo.py — تشخیص کشور proxy ها بر اساس IP واقعی.

استفاده از MaxMind GeoLite2 (آفلاین، سریع، دقیق).
"""

from __future__ import annotations

import socket
import re
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

# ── پرچم emoji برای کد کشور ──────────────────────────────────────────────────
def country_flag(code: str) -> str:
    """تبدیل کد ISO (مثل US) به emoji پرچم 🇺🇸"""
    if not code or len(code) != 2:
        return "🏴"
    code = code.upper()
    return "".join(chr(ord(c) + 127397) for c in code)


# نام‌های کامل کشور
COUNTRY_NAMES = {
    "US": "USA",        "DE": "Germany",      "JP": "Japan",
    "FR": "France",     "GB": "UK",           "NL": "Netherlands",
    "CA": "Canada",     "RU": "Russia",       "IR": "Iran",
    "TR": "Turkey",     "SG": "Singapore",    "HK": "Hong Kong",
    "KR": "Korea",      "TW": "Taiwan",       "AU": "Australia",
    "IT": "Italy",      "ES": "Spain",        "SE": "Sweden",
    "FI": "Finland",    "NO": "Norway",       "CH": "Switzerland",
    "AT": "Austria",    "BE": "Belgium",      "PL": "Poland",
    "RO": "Romania",    "UA": "Ukraine",      "IN": "India",
    "BR": "Brazil",     "MX": "Mexico",       "AR": "Argentina",
    "ZA": "S.Africa",   "AE": "UAE",          "SA": "S.Arabia",
    "IL": "Israel",     "EG": "Egypt",        "CN": "China",
    "VN": "Vietnam",    "ID": "Indonesia",    "TH": "Thailand",
    "MY": "Malaysia",   "PH": "Philippines",  "BG": "Bulgaria",
    "CZ": "Czech",      "DK": "Denmark",      "GR": "Greece",
    "HU": "Hungary",    "IE": "Ireland",      "LU": "Luxembourg",
    "PT": "Portugal",   "SK": "Slovakia",     "SI": "Slovenia",
    "EE": "Estonia",    "LV": "Latvia",       "LT": "Lithuania",
    "IS": "Iceland",    "MT": "Malta",        "CY": "Cyprus",
    "MD": "Moldova",    "RS": "Serbia",       "HR": "Croatia",
    "MK": "N.Macedonia", "AL": "Albania",     "BA": "Bosnia",
    "ME": "Montenegro", "AM": "Armenia",      "AZ": "Azerbaijan",
    "GE": "Georgia",    "KZ": "Kazakhstan",   "UZ": "Uzbekistan",
    "KG": "Kyrgyzstan", "TJ": "Tajikistan",
}


# ──────────────────────────────────────────────────────────────────────────────
# IP detection
# ──────────────────────────────────────────────────────────────────────────────

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def is_ip(addr: str) -> bool:
    """آیا آدرس IPv4 یا IPv6 هست؟"""
    if not addr:
        return False
    if _IPV4_RE.match(addr):
        return True
    if ":" in addr and _IPV6_RE.match(addr):
        return True
    return False


def resolve_dns(host: str) -> Optional[str]:
    """تبدیل domain به IP. در خطا None برمی‌گرداند."""
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
    """Lazy load reader."""
    global _reader
    if _reader is None:
        if not GEOIP_AVAILABLE:
            raise RuntimeError("geoip2 نصب نیست. pip install geoip2")
        if not MMDB_PATH.exists():
            raise RuntimeError(f"فایل {MMDB_PATH} یافت نشد.")
        _reader = geoip2.database.Reader(str(MMDB_PATH))
    return _reader


def lookup_country(ip: str) -> str:
    """کد ISO کشور رو از IP پیدا میکنه. در خطا 'XX' برمی‌گرداند."""
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

def _process_one(p: Dict) -> Tuple[Dict, str]:
    """resolve IP و country رو برای یه proxy انجام میده."""
    server = p.get("server", "")
    ip = resolve_dns(server)
    if not ip:
        return p, "XX"
    country = lookup_country(ip)
    return p, country


def annotate_countries(proxies: List[Dict]) -> List[Dict]:
    """
    برای هر proxy، فیلد '_country' اضافه میکنه و نام proxy رو بازنویسی میکنه.
    موازی با ThreadPool.
    """
    if not GEOIP_AVAILABLE:
        print("  [geo] ⚠ geoip2 نصب نیست — رد میشه")
        return proxies
    if not MMDB_PATH.exists():
        print(f"  [geo] ⚠ {MMDB_PATH} یافت نشد — رد میشه")
        return proxies

    result = [None] * len(proxies)

    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as ex:
        futures = {ex.submit(_process_one, p): i for i, p in enumerate(proxies)}
        done = 0
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                p, country = fut.result()
            except Exception:
                p = proxies[i]
                country = "XX"

            # حذف emoji پرچم قدیمی از نام (فیک‌های احتمالی)
            old_name = p.get("name", "")
            clean_name = re.sub(
                r"[\U0001F1E6-\U0001F1FF]{2}",  # regional indicators (پرچم)
                "",
                old_name
            ).strip()

            flag = country_flag(country)
            cname = COUNTRY_NAMES.get(country, country)

            # نام جدید: 🇺🇸 US | OriginalName
            new_name = f"{flag} {cname} | {clean_name}" if clean_name else f"{flag} {cname}"
            new_name = new_name[:80]

            p["_country"] = country
            p["name"] = new_name
            result[i] = p

            done += 1
            if done % 200 == 0:
                print(f"  [geo] {done}/{len(proxies)} resolved")

    # شمارش کشورها
    from collections import Counter
    counter = Counter(p.get("_country", "XX") for p in result)
    print(f"\n  [geo] توزیع کشورها:")
    for country, cnt in counter.most_common(15):
        flag = country_flag(country)
        cname = COUNTRY_NAMES.get(country, country)
        print(f"    {flag} {cname:<15} {cnt:>4}")

    return result
