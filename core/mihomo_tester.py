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
import urllib.parse
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

MIHOMO_CONFIG  = Path("/tmp/mihomo_test_config.yaml")
MIHOMO_API     = "http://127.0.0.1:9090"
TEST_URL       = "http://cp.cloudflare.com/generate_204"
IP_LOOKUP_URL  = "http://ifconfig.me/ip"
TEST_TIMEOUT   = 5000   # ms
HTTP_TIMEOUT   = 8      # seconds
WORKERS        = 50
STARTUP_WAIT   = 15      # seconds


# ──────────────────────────────────────────────────────────────────────────────
# پیدا کردن binary mihomo
# ──────────────────────────────────────────────────────────────────────────────

def _find_mihomo() -> Path:
    """جستجوی binary mihomo در چند مکان."""
    candidates = [
        Path.cwd() / "mihomo",
        Path("./mihomo").resolve(),
        Path("/usr/local/bin/mihomo"),
        Path("/usr/bin/mihomo"),
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c.resolve()
    return Path.cwd() / "mihomo"


MIHOMO_BIN = _find_mihomo()


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
    clean = []
    seen_names: Dict[str, int] = {}
    
    for p in proxies:
        cp = {k: v for k, v in p.items() if not k.startswith("_")}
        
        # اطمینان از یکتا بودن نام
        original_name = cp.get("name", "proxy")
        name = original_name
        if name in seen_names:
            seen_names[name] += 1
            name = f"{original_name}#{seen_names[original_name]}"
            cp["name"] = name
        else:
            seen_names[name] = 0
        
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

def _start_mihomo(config: Dict) -> Optional[subprocess.Popen]:
    """Mihomo رو با config داده شده اجرا میکنه."""
    # quote کردن فیلدهای حساس
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

    # چک کن binary موجوده
    if not MIHOMO_BIN.exists():
        print(f"  [mihomo] ❌ binary پیدا نشد: {MIHOMO_BIN}")
        print(f"  [mihomo] cwd: {Path.cwd()}")
        try:
            files = [f.name for f in Path.cwd().iterdir()][:30]
            print(f"  [mihomo] فایل‌های cwd: {files}")
        except Exception:
            pass
        return None

    print(f"  [mihomo] استفاده از binary: {MIHOMO_BIN}")

    try:
        proc = subprocess.Popen(
            [str(MIHOMO_BIN), "-f", str(MIHOMO_CONFIG), "-d", "/tmp/mihomo_data"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception as e:
        print(f"  [mihomo] ❌ خطا در اجرا: {e}")
        return None

    # صبر تا API آماده بشه
    for attempt in range(STARTUP_WAIT * 2):
        try:
            urllib.request.urlopen(f"{MIHOMO_API}/version", timeout=2).read()
            print(f"  [mihomo] ✅ API آماده شد (بعد از {attempt * 0.5:.1f}s)")
            return proc
        except Exception:
            time.sleep(0.5)

        # چک کن آیا Mihomo کرش کرده
        if proc.poll() is not None:
            stdout = proc.stdout.read().decode(errors="replace")[-2000:]
            stderr = proc.stderr.read().decode(errors="replace")[-2000:]
            print(f"  [mihomo] ❌ Mihomo خاتمه یافت با کد {proc.returncode}")
            if stdout:
                print(f"  [mihomo] stdout: {stdout}")
            if stderr:
                print(f"  [mihomo] stderr: {stderr}")
            return None

    # تایم‌اوت
    print(f"  [mihomo] ❌ API آماده نشد بعد از {STARTUP_WAIT}s")
    try:
        stdout = proc.stdout.read(2000).decode(errors="replace")
        stderr = proc.stderr.read(2000).decode(errors="replace")
        if stdout:
            print(f"  [mihomo] stdout: {stdout}")
        if stderr:
            print(f"  [mihomo] stderr: {stderr}")
    except Exception:
        pass
    proc.kill()
    return None


def _stop_mihomo(proc: Optional[subprocess.Popen]):
    """خاتمه Mihomo."""
    if proc:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# ──────────────────────────────────────────────────────────────────────────────
# تست از طریق Mihomo API
# ──────────────────────────────────────────────────────────────────────────────

def _test_proxy_api(proxy_name: str) -> Optional[int]:
    """تست proxy از طریق Mihomo API. برمی‌گرداند: latency (ms) یا None."""
    try:
        encoded = urllib.parse.quote(proxy_name, safe="")
        url = (f"{MIHOMO_API}/proxies/{encoded}/delay"
               f"?url={urllib.parse.quote(TEST_URL)}&timeout={TEST_TIMEOUT}")

        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read())
            return data.get("delay")
    except Exception:
        return None


def _get_ip_via_proxy(proxy_name: str) -> Optional[str]:
    """IP خروجی واقعی proxy رو میگیره."""
    try:
        # ست کردن proxy فعلی در گروه TEST
        url = f"{MIHOMO_API}/proxies/TEST"
        data = json.dumps({"name": proxy_name}).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="PUT",
            headers={"Content-Type": "application/json"},
        )
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
# GeoIP local
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
# تابع اصلی
# ──────────────────────────────────────────────────────────────────────────────

def http_test_all(proxies: List[Dict]) -> List[Dict]:
    """تست همه proxy ها با Mihomo."""
    # refresh کن MIHOMO_BIN
    global MIHOMO_BIN
    MIHOMO_BIN = _find_mihomo()

    if not MIHOMO_BIN.exists():
        print(f"  [mihomo] ⚠ binary یافت نشد")
        print(f"  [mihomo] cwd: {Path.cwd()}")
        print(f"  [mihomo] جستجو شد: {MIHOMO_BIN}")
        try:
            files = [f.name for f in Path.cwd().iterdir()][:30]
            print(f"  [mihomo] فایل‌های موجود: {files}")
        except Exception:
            pass
        return proxies

    if not proxies:
        return []

    # یکتاسازی نام‌ها قبل از Mihomo
    seen_names: Dict[str, int] = {}
    for p in proxies:
        original_name = p.get("name", "proxy")
        name = original_name
        if name in seen_names:
            seen_names[name] += 1
            name = f"{original_name}#{seen_names[original_name]}"
            p["name"] = name
        else:
            seen_names[name] = 0
    
    print(f"  [mihomo] ساخت config برای {len(proxies)} proxy …")
    config = _build_mihomo_config(proxies)

    print(f"  [mihomo] اجرای Mihomo …")
    proc = _start_mihomo(config)
    if not proc:
        return proxies

    try:
        print(f"  [mihomo] شروع latency test با {WORKERS} thread موازی …")

        # ── مرحله ۱: latency test (موازی) ──
        latencies: Dict[int, int] = {}
        total = len(proxies)
        done = 0

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
                    print(f"  [mihomo] {done}/{total} latency, {len(latencies)} زنده")

        print(f"  [mihomo] ✅ latency test: {len(latencies)}/{total} زنده")

        # ── مرحله ۲: IP test (سریال) ──
        print(f"  [mihomo] گرفتن IP خروجی واقعی برای {len(latencies)} proxy …")
        alive: List[Dict] = []

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

        print(f"  [mihomo] ✅ IP test کامل: {len(alive)} proxy")

        # ── مرحله ۳: مرتب‌سازی + بازنویسی نام ──
        alive.sort(key=lambda p: (p.get("_real_country", "XX"),
                                   p.get("_latency_ms", 9999)))

        counter: Dict[str, int] = defaultdict(int)
        for p in alive:
            country = p.get("_real_country", "XX")
            counter[country] += 1
            idx = counter[country]
            flag = country_flag(country)
            real_ip = p.get("_real_ip", "")
            port = p.get("port", 0)
            lat = p.get("_latency_ms", 0)

            if real_ip and ":" in real_ip and not real_ip.replace(".", "").isdigit():
                ip_display = f"[{real_ip}]"
            else:
                ip_display = real_ip or "?"

            p["_country"] = country
            p["name"] = f"{flag} {country}{idx} | {ip_display} ({lat}ms)"[:80]

        # ── آمار ──
        stats = Counter(p.get("_real_country", "XX") for p in alive)
        print(f"\n  [mihomo] توزیع کشورهای واقعی:")
        for country, cnt in stats.most_common(20):
            flag = country_flag(country)
            print(f"    {flag} {country:<4} {cnt:>4}")

        print(f"\n  [mihomo] ✅ {len(alive)}/{total} proxy واقعاً زنده + کشور دقیق")

        return alive

    finally:
        _stop_mihomo(proc)
