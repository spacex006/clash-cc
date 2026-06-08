"""
geo.py — تشخیص کشور proxy ها بر اساس IP واقعی + CDN detection.
"""

from __future__ import annotations

import ipaddress
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
    if not code or len(code) != 2 or code in ("XX", "CD"):
        if code == "CD":
            return "🌐"   # CDN
        return "🏳"
    code = code.upper()
    return "".join(chr(ord(c) + 127397) for c in code)


# ──────────────────────────────────────────────────────────────────────────────
# CDN IP ranges (معروف‌ترین‌ها)
# ──────────────────────────────────────────────────────────────────────────────

CDN_RANGES = {
    "Cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "Amazon": [
        "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15",
        "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16",
        "54.239.128.0/18", "99.84.0.0/16", "204.246.164.0/22",
        "204.246.168.0/22", "205.251.192.0/19",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18",
        "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20",
        "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22",
        "199.27.72.0/21", "199.232.0.0/16",
    ],
    "Google": [
        "35.190.0.0/17", "35.191.0.0/16", "130.211.0.0/16",
        "35.224.0.0/12", "172.217.0.0/16", "216.58.192.0/19",
    ],
    "Microsoft": [
        "13.107.6.152/31", "13.107.18.10/31", "13.107.128.0/22",
        "40.74.0.0/15", "40.78.0.0/15", "40.96.0.0/13",
        "52.108.0.0/14", "52.112.0.0/14",
    ],
}

# تبدیل به objects برای lookup سریع
_CDN_NETWORKS: Dict[str, List] = {}
for cdn_name, ranges in CDN_RANGES.items():
    _CDN_NETWORKS[cdn_name] = [ipaddress.ip_network(r) for r in ranges]


def detect_cdn(ip: str) -> Optional[str]:
    """اگر IP متعلق به یه CDN معروف باشه، نامش رو برمی‌گرده."""
    if not ip:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cdn_name, networks in _CDN_NETWORKS.items():
            for net in networks:
                if ip_obj in net:
                    return cdn_name
    except ValueError:
        pass
    return None


# ──────────────────────────────────────────────────────────────────────────────
# IP detection
# ──────────────────────────────────────────────────────────────────────────────

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def is_ipv4(addr: str) -> bool:
    return bool(_IPV4_RE.match(addr or ""))


def is_ip(addr: str) -> bool:
    if not addr:
        return False
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
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
            raise RuntimeError("geoip2 نصب نیست.")
        if not MMDB_PATH.exists():
            raise RuntimeError(f"{MMDB_PATH} یافت نشد.")
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
# Pipeline اصلی - با CDN detection + SNI fallback
# ──────────────────────────────────────────────────────────────────────────────

def _process_one(idx: int, p: Dict) -> Tuple[int, str, str, bool]:
    """
    برمی‌گرداند: (index, country, display_ip, is_cdn)
    """
    server = str(p.get("server", "")).strip()
    sni    = str(p.get("servername") or p.get("sni") or "").strip()

    # ── مرحله ۱: resolve خود server ─────────────────────────────────
    ip = resolve_dns(server)
    if not ip:
        return idx, "XX", server, False

    # ── مرحله ۲: چک کنیم CDN هست؟ ─────────────────────────────────
    cdn = detect_cdn(ip)

    if cdn:
        # CDN شناسایی شد، سعی کن از SNI استفاده کنی
        if sni and sni != server and not is_ip(sni):
            sni_ip = resolve_dns(sni)
            if sni_ip:
                sni_cdn = detect_cdn(sni_ip)
                if not sni_cdn:
                    # SNI به یه سرور غیر CDN اشاره داره — استفاده کن
                    country = lookup_country(sni_ip)
                    if country != "XX":
                        return idx, country, sni_ip, False

        # SNI کار نکرد یا CDN بود → برچسب CDN
        return idx, "CD", f"{cdn[:2].upper()}-{ip}", True

    # ── مرحله ۳: GeoIP معمولی ───────────────────────────────────────
    country = lookup_country(ip)
    return idx, country, ip, False


def annotate_countries(proxies: List[Dict]) -> List[Dict]:
    """تشخیص کشور و بازنویسی نام."""
    if not GEOIP_AVAILABLE:
        print("  [geo] ⚠ geoip2 نصب نیست — رد میشه")
        return proxies
    if not MMDB_PATH.exists():
        print(f"  [geo] ⚠ {MMDB_PATH} یافت نشد — رد میشه")
        return proxies

    countries: Dict[int, str] = {}
    ips: Dict[int, str] = {}
    cdns: Dict[int, bool] = {}

    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as ex:
        futures = [ex.submit(_process_one, i, p) for i, p in enumerate(proxies)]
        done = 0
        for fut in as_completed(futures):
            try:
                idx, country, ip, is_cdn = fut.result()
            except Exception:
                continue
            countries[idx] = country
            ips[idx] = ip
            cdns[idx] = is_cdn
            done += 1
            if done % 200 == 0:
                print(f"  [geo] {done}/{len(proxies)} resolved")

    # ── بازنویسی نام ها ─────────────────────────────────────────────
    country_counter: Dict[str, int] = defaultdict(int)
    result: List[Dict] = []

    for i, p in enumerate(proxies):
        country = countries.get(i, "XX")
        ip = ips.get(i, p.get("server", ""))
        port = p.get("port", 0)
        is_cdn = cdns.get(i, False)

        country_counter[country] += 1
        idx_in_country = country_counter[country]

        flag = country_flag(country)

        # برای IPv6 با براکت
        if ip and ":" in ip and not ip.startswith("CD"):
            ip_display = f"[{ip}]"
        else:
            ip_display = ip

        if country == "CD":
            # CDN
            new_name = f"🌐 CDN{idx_in_country} | {ip_display}:{port}"
        else:
            new_name = f"{flag} {country}{idx_in_country} | {ip_display}:{port}"

        new_name = new_name[:80]

        p = dict(p)
        p["_country"] = country
        p["_resolved_ip"] = ip
        p["_is_cdn"] = is_cdn
        p["name"] = new_name
        result.append(p)

    # ── آمار ─────────────────────────────────────────────────────────
    counter = Counter(p.get("_country", "XX") for p in result)
    print(f"\n  [geo] توزیع کشورها:")
    for country, cnt in counter.most_common(20):
        flag = country_flag(country)
        label = "CDN" if country == "CD" else country
        print(f"    {flag} {label:<5} {cnt:>4}")

    return result
