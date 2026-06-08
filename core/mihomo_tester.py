"""
mihomo_tester.py — تست واقعی proxy ها با Mihomo core.
HTTP request از طریق proxy + تشخیص IP خروجی واقعی + کشور.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

# ──────────────────────────────────────────────────────────────────────────────
# تنظیمات
# ──────────────────────────────────────────────────────────────────────────────

MIHOMO_BIN     = Path("./mihomo")
MIHOMO_CONFIG  = Path("/tmp/mihomo_test_config.yaml")
MIHOMO_API     = "http://127.0.0.1:9090"
TEST_URL       = "http://cp.cloudflare.com/generate_204"
IP_LOOKUP_URL  = "http://ifconfig.me/ip"
TEST_TIMEOUT   = 5000   # ms (برای Mihomo)
HTTP_TIMEOUT   = 8      # seconds (برای requests پایتون)
WORKERS        = 50     # تست موازی
STARTUP_WAIT   = 5      # ثانیه برای آماده شدن Mihomo


# ──────────────────────────────────────────────────────────────────────────────
# Country flag
# ──────────────────────────────────────────────────────────────────────────────

def country_flag(code: str) -> str:
    if not code or len(code) != 2 or code == "XX":
        return "🏳"
    code = code.upper()
    return "".join(chr(ord(c) + 127397) for c in code)


# ──────────────────────────────────────────────────────────────────────────────
# تولید config برای Mihomo
# ──────────────────────────────────────────────────────────────────────────────

def _build_mihomo_config(proxies: List[Dict]) -> Dict:
    """ساخت config مینیمال Mihomo فقط برای تست."""
    # حذف فیلدهای داخلی
    clean = []
    for p in proxies:
        cp = {k: v for k, v in p.items() if not k.startswith("_")}
        clean.append(cp)

    names = [p["name"] for p in clean]

    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller": "127.0.0.1:9090",
        "proxies": clean,
        "proxy-groups": [{
            "name": "TEST",
            "type": "select",
            "proxies": names if names else ["DIRECT"],
        }],
        "rules": ["MATCH,TEST"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Mihomo process management
# ──────────────────────────────────────────────────────────────────────────────

def _start_mihomo(config: Dict) -> subprocess.Popen:
    """Mihomo رو با config داده شده اجرا میکنه."""
    # quote کردن فیلدهای حساس مثل converter اصلی
    class QuotedStr(str):
        pass

    def quoted_str_representer(dumper, data):
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")

    yaml.add_representer(QuotedStr, quoted_str_representer)

    def wrap_sensitive(obj):
        if isinstance(obj, dict):
            new = {}
            for k, v in obj.items():
                if k in ("short-id", "public-key", "uuid", "password") and isinstance(v, str):
                    new[k] = QuotedStr(v)
                else:
                    new[k] = wrap_sensitive(v)
            return new
        elif isinstance(obj, list):
            return [wrap_sensitive(i) for i in obj]
        return obj

    safe_config = wrap_sensitive(config)
    MIHOMO_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    MIHOMO_CONFIG.write_text(
        yaml.dump(safe_config, allow_unicode=True, sort_keys=False, width=4096),
        encoding="utf-8",
    )

    proc = subprocess.Popen(
        [str(MIHOMO_BIN), "-f", str(MIHOMO_CONFIG), "-d", "/tmp/mihomo_data"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # صبر تا API آماده بشه
    for _ in range(STARTUP_WAIT * 2):
        try:
            urllib.request.urlopen(f"{MIHOMO_API}/version", timeout=1).read()
            print(f"  [mihomo] ✅ API آماده شد")
            return proc
        except Exception:
            time.sleep(0.5)

    print(f"  [mihomo] ❌ API آماده نشد")
    proc.kill()
    return None


def _stop_mihomo(proc: subprocess.Popen):
    """خاتمه Mihomo."""
    if proc:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


# ──────────────────────────────────────────────────────────────────────────────
# تست از طریق Mihomo API
# ──────────────────────────────────────────────────────────────────────────────

def _test_proxy_api(proxy_name: str) -> Optional[int]:
    """
    تست proxy از طریق Mihomo API.
    برمی‌گرداند: latency (ms) یا None.
    """
    try:
        # encode نام proxy
        encoded = urllib.parse.quote(proxy_name, safe="")
        url = f"{MIHOMO_API}/proxies/{encoded}/delay?url={urllib.parse.quote(TEST_URL)}&timeout={TEST_TIMEOUT}"

        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read())
            return data.get("delay")
    except Exception:
        return None


def _get_ip_via_proxy(proxy_name: str) -> Optional[str]:
    """
    IP خروجی واقعی proxy رو میگیره.
    اول proxy رو در گروه TEST انتخاب میکنیم، بعد از طریق mixed-port وصل میشیم.
    """
    try:
        # ست کردن proxy فعلی در گروه TEST
        encoded = urllib.parse.quote(proxy_name, safe="")
        url = f"{MIHOMO_API}/proxies/TEST"
        data = json.dumps({"name": proxy_name}).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="PUT",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3).read()

        # request از طریق mixed-port
        proxy_handler = urllib.request.ProxyHandler({
            "http": "http://127.0.0.1:7890",
            "https": "http://127.0.0.1:7890",
        })
        opener = urllib.request.build_opener(proxy_handler)
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]

        with opener.open(IP_LOOKUP_URL, timeout=HTTP_TIMEOUT) as resp:
            ip = resp.read().decode().strip()
            return ip
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# GeoIP local (با MaxMind)
# ──────────────────────────────────────────────────────────────────────────────

_geo_reader = None

def _get_geo_reader():
    global _geo_reader
    if _geo_reader is None:
        try:
            import geoip2.database
            mmdb = Path("Country.mmdb")
            if mmdb.exists():
                _geo_reader = geoip2.database.Reader(str(mmdb))
        except Exception:
            pass
    return _geo_reader


def _lookup_country(ip: str) -> str:
    if not ip:
        return "XX"
    reader = _get_geo_reader()
    if not reader:
        return "XX"
    try:
        return reader.country(ip).country.iso_code or "XX"
    except Exception:
        return "XX"


# ──────────────────────────────────────────────────────────────────────────────
# تست batch
# ──────────────────────────────────────────────────────────────────────────────

def _test_one(p: Dict) -> Optional[Dict]:
    """
    یه proxy رو تست میکنه و در صورت زنده بودن:
    - latency
    - IP خروجی واقعی
    - کشور واقعی
    رو ضمیمه میکنه.
    """
    name = p.get("name", "")

    # ① latency test
    latency = _test_proxy_api(name)
    if latency is None or latency <= 0 or latency >= TEST_TIMEOUT:
        return None

    # ② IP خروجی واقعی
    real_ip = _get_ip_via_proxy(name)
    if not real_ip:
        # proxy کار میکنه ولی IP نگرفتیم
        country = "XX"
    else:
        country = _lookup_country(real_ip)

    p = dict(p)
    p["_latency_ms"] = latency
    p["_real_ip"] = real_ip or ""
    p["_real_country"] = country
    return p


# ──────────────────────────────────────────────────────────────────────────────
# تابع اصلی
# ──────────────────────────────────────────────────────────────────────────────

def http_test_all(proxies: List[Dict]) -> List[Dict]:
    """
    تست همه proxy ها با Mihomo:
    - حذف proxy های مرده
    - دریافت کشور واقعی از IP خروجی
    - بازنویسی نام
    """
    if not MIHOMO_BIN.exists():
        print(f"  [mihomo] ⚠ {MIHOMO_BIN} یافت نشد — رد میشه")
        return proxies

    if not proxies:
        return []

    print(f"  [mihomo] ساخت config برای {len(proxies)} proxy …")
    config = _build_mihomo_config(proxies)

    print(f"  [mihomo] اجرای Mihomo …")
    proc = _start_mihomo(config)
    if not proc:
        return proxies

    try:
        print(f"  [mihomo] شروع تست با {WORKERS} thread موازی …")
        alive: List[Dict] = []
        total = len(proxies)
        done = 0

        # تست‌ها رو تک تک انجام میدیم چون نیاز به PUT روی گروه TEST داریم
        # که نباید همزمان باشه. ولی latency test میتونه موازی باشه.
        # راه‌حل: اول همه latency ها، بعد فقط زنده‌ها رو IP test
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # ── مرحله ۱: latency test (موازی) ──────────────────────────
        latencies = {}
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futs = {ex.submit(_test_proxy_api, p["name"]): i for i, p in enumerate(proxies)}
            for fut in as_completed(futs):
                i = futs[fut]
                try:
                    lat = fut.result()
                    if lat and 0 < lat < TEST_TIMEOUT:
                        latencies[i] = lat
                except Exception:
                    pass
                done += 1
                if done % 100 == 0:
                    print(f"  [mihomo] {done}/{total} latency تست شد، {len(latencies)} زنده")

        print(f"  [mihomo] latency test: {len(latencies)}/{total} زنده")

        # ── مرحله ۲: IP test (سریال چون باید گروه TEST رو تغییر بدیم) ──
        print(f"  [mihomo] گرفتن IP خروجی واقعی …")
        for i, p in enumerate(proxies):
            if i not in latencies:
                continue
            real_ip = _get_ip_via_proxy(p["name"])
            country = _lookup_country(real_ip) if real_ip else "XX"

            p = dict(p)
            p["_latency_ms"] = latencies[i]
            p["_real_ip"] = real_ip or ""
            p["_real_country"] = country
            alive.append(p)

            if len(alive) % 50 == 0:
                print(f"  [mihomo] {len(alive)}/{len(latencies)} IP گرفته شد")

        # ── مرحله ۳: بازنویسی نام بر اساس کشور واقعی ──────────────
        from collections import defaultdict
        counter = defaultdict(int)
        alive.sort(key=lambda p: (p.get("_real_country", "XX"), p.get("_latency_ms", 9999)))

        for p in alive:
            country = p.get("_real_country", "XX")
            counter[country] += 1
            idx = counter[country]
            flag = country_flag(country)
            real_ip = p.get("_real_ip", "")
            port = p.get("port", 0)
            lat = p.get("_latency_ms", 0)

            if real_ip and ":" in real_ip:
                ip_display = f"[{real_ip}]"
            else:
                ip_display = real_ip or "?"

            p["_country"] = country
            p["name"] = f"{flag} {country}{idx} | {ip_display} ({lat}ms)"[:80]

        # آمار
        from collections import Counter
        stats = Counter(p.get("_real_country", "XX") for p in alive)
        print(f"\n  [mihomo] توزیع کشورهای واقعی:")
        for country, cnt in stats.most_common(20):
            flag = country_flag(country)
            print(f"    {flag} {country:<4} {cnt:>4}")

        print(f"\n  [mihomo] ✅ {len(alive)}/{total} proxy واقعاً زنده + کشور دقیق")

        return alive

    finally:
        _stop_mihomo(proc)
