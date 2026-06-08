"""
deduplicator.py — حذف تکراری سنگین + تست TCP پینگ اختیاری.

سطوح dedup (ترتیب اجرا):
  1. کلید ترکیبی: type|server|port|credential|network|path
  2. UUID تنها: یک UUID → یک کانفیگ (off by default برای CDN)
  3. server:port تنها (اختیاری)

بعد از dedup، تست TCP موازی انجام می‌شه و latency برمی‌گردد.
"""

from __future__ import annotations

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class DedupConfig:
    uuid_dedup:      bool = False   # True = یک UUID در کل خروجی
    server_port_dedup: bool = True  # True = یک کانفیگ به ازای هر server:port
    name_dedup:      bool = False   # True = نام‌های نرمال‌شده یکتا
    tcp_test:        bool = True    # True = تست TCP و حذف مرده‌ها
    tcp_timeout:     float = 3.0    # ثانیه
    tcp_workers:     int   = 120    # thread های موازی


# ──────────────────────────────────────────────────────────────────────────────
# کلیدسازی
# ──────────────────────────────────────────────────────────────────────────────

def _composite_key(p: Dict) -> str:
    """کلید اصلی — جامع‌ترین سطح dedup."""
    credential = p.get("uuid") or p.get("password") or ""
    path = ""
    if isinstance(p.get("ws-opts"), dict):
        path = p["ws-opts"].get("path", "")
    elif isinstance(p.get("grpc-opts"), dict):
        path = p["grpc-opts"].get("grpc-service-name", "")

    parts = [
        p.get("type", ""),
        p.get("server", ""),
        str(p.get("port", "")),
        credential,
        p.get("network", "tcp"),
        path,
    ]
    return "|".join(s.lower() for s in parts)


def _normalize_name(name: str) -> str:
    """حذف emoji، کد کشور، و فضاها برای مقایسه نام."""
    # حذف emoji (unicode ranges)
    name = re.sub(r"[\U00010000-\U0010ffff]|[\u2000-\u27ff]", "", name)
    # حذف پیشوندهای رایج کشور/منطقه
    name = re.sub(r"\b[A-Z]{2,3}\b|\d+x\b", "", name, flags=re.IGNORECASE)
    # فشرده‌سازی فضا
    return re.sub(r"\s+", " ", name).strip().lower()


# ──────────────────────────────────────────────────────────────────────────────
# Dedup اصلی
# ──────────────────────────────────────────────────────────────────────────────

def deduplicate(proxies: List[Dict], cfg: DedupConfig) -> List[Dict]:
    """
    حذف تکراری با سه سطح مستقل.
    ترتیب ورودی حفظ می‌شود (first-seen wins).
    """
    seen_composite:   set = set()
    seen_uuid:        set = set()
    seen_server_port: set = set()
    seen_name:        set = set()

    result: List[Dict] = []

    for p in proxies:
        # ── سطح ۱: کلید ترکیبی (همیشه فعال) ──────────────────────────────
        ck = _composite_key(p)
        if ck in seen_composite:
            continue
        seen_composite.add(ck)

        # ── سطح ۲: UUID تنها ──────────────────────────────────────────────
        if cfg.uuid_dedup:
            uid = (p.get("uuid") or "").strip().lower()
            if uid:
                if uid in seen_uuid:
                    continue
                seen_uuid.add(uid)

        # ── سطح ۳: server:port ────────────────────────────────────────────
        if cfg.server_port_dedup:
            sp = f"{p.get('server','')}:{p.get('port','')}".lower()
            if sp in seen_server_port:
                continue
            seen_server_port.add(sp)

        # ── سطح ۴: نام نرمال‌شده ──────────────────────────────────────────
        if cfg.name_dedup:
            nn = _normalize_name(p.get("name", ""))
            if nn and nn in seen_name:
                continue
            seen_name.add(nn)

        result.append(p)

    return result


# ──────────────────────────────────────────────────────────────────────────────
# TCP پینگ
# ──────────────────────────────────────────────────────────────────────────────

def _tcp_ping(host: str, port: int, timeout: float) -> Optional[float]:
    """اتصال TCP و اندازه‌گیری latency (ms). None = مرده."""
    try:
        af   = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0  = time.perf_counter()
        err = sock.connect_ex((host, port))
        ms  = (time.perf_counter() - t0) * 1000
        sock.close()
        return ms if err == 0 else None
    except Exception:
        return None


def tcp_filter_and_sort(
    proxies: List[Dict],
    timeout: float = 3.0,
    workers: int = 120,
) -> Tuple[List[Dict], List[Dict]]:
    """
    تست TCP موازی.
    برمی‌گرداند: (alive_sorted_by_latency, dead_list)
    هر proxy dict یک فیلد "_latency_ms" دریافت می‌کند.
    """
    alive: List[Tuple[float, Dict]] = []
    dead:  List[Dict]               = []

    def test(p: Dict):
        ms = _tcp_ping(
            host    = str(p.get("server", "")),
            port    = int(p.get("port", 443)),
            timeout = timeout,
        )
        return p, ms

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(test, p): p for p in proxies}
        done = 0
        for fut in as_completed(futures):
            p, ms = fut.result()
            done += 1
            if ms is not None:
                p = dict(p)
                p["_latency_ms"] = round(ms, 1)
                alive.append((ms, p))
            else:
                dead.append(p)
            if done % 100 == 0:
                print(f"  [tcp] {done}/{len(proxies)} tested, "
                      f"{len(alive)} alive …")

    alive.sort(key=lambda t: t[0])
    return [p for _, p in alive], dead


# ──────────────────────────────────────────────────────────────────────────────
# یکتاسازی نام‌ها (برای خروجی YAML)
# ──────────────────────────────────────────────────────────────────────────────

def unique_names(proxies: List[Dict]) -> List[Dict]:
    """
    اگر چند proxy اسم یکسان داشتند [2]، [3] اضافه می‌کند.
    """
    counts: Dict[str, int] = {}
    result = []
    for p in proxies:
        p = dict(p)
        base = p.get("name", "proxy")
        if base in counts:
            counts[base] += 1
            p["name"] = f"{base} [{counts[base]}]"
        else:
            counts[base] = 0
        result.append(p)
    return result
