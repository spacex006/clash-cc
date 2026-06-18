"""
fetcher.py — دریافت URI های پروکسی از URL های سورس.

هر URL ممکنه:
  - لیست plain text از URI ها باشه
  - محتوای base64-encoded باشه
  - فایل Clash YAML باشه (فعلاً skip می‌شه — موضوع converter است)
"""

from __future__ import annotations

import base64
import re
import sys
from typing import List

import requests

# ──────────────────────────────────────────────────────────────────────────────
PROXY_PREFIXES = (
    "vmess://", "vless://", "ss://", "trojan://",
    "hysteria2://", "hy2://", "tuic://",
)

HEADERS = {"User-Agent": "clash-lite/1.0 (proxy-fetcher)"}
REQUEST_TIMEOUT = 20   # seconds


# ──────────────────────────────────────────────────────────────────────────────

def _b64_try(text: str) -> str:
    """سعی می‌کند base64 decode کند؛ اگر محتوا URI دارد برگرداند."""
    try:
        clean = re.sub(r"\s+", "", text)
        # base64 خالص باشه
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", clean):
            return text
        padded  = clean + "=" * (-len(clean) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        if any(decoded.lstrip().startswith(p) for p in PROXY_PREFIXES):
            return decoded
    except Exception:
        pass
    return text


def _extract_uris(text: str) -> List[str]:
    """استخراج همه URI های پروکسی از متن (یک URI در هر خط)."""
    text = _b64_try(text)
    result = []
    for line in text.splitlines():
        line = line.strip()
        if line and any(line.startswith(p) for p in PROXY_PREFIXES):
            result.append(line)
    return result


def fetch_url(url: str) -> List[str]:
    """
    دریافت یک URL و استخراج URI های پروکسی.
    برمی‌گرداند: list از URI string های خام.
    """
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        resp.raise_for_status()
        uris = _extract_uris(resp.text)
        return uris
    except Exception as exc:
        print(f"  [fetcher] ⚠ {url!r}  →  {exc}", file=sys.stderr)
        return []


def fetch_all(urls: List[str]) -> List[str]:
    """
    دریافت از همه URL ها و ادغام نتایج.
    ترتیب اصلی حفظ می‌شود (برای dedup قطعی‌بودن).
    """
    all_uris: List[str] = []
    for url in urls:
        fetched = fetch_url(url)
        print(f"  [fetcher] {len(fetched):>5} URIs  ←  {url}")
        all_uris.extend(fetched)
    return all_uris
