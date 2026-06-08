"""
sanitizer.py — پاکسازی عمیق تمام فیلدهای proxy dict از کاراکترهای کنترلی.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

# کاراکترهای کنترلی که Go YAML قبول نمی‌کنه
# (همه 0x00-0x1F به جز Tab/LF/CR، و 0x7F)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean_str(s: str) -> str:
    """حذف کاراکترهای کنترلی از یک رشته."""
    return _CTRL_RE.sub("", s)


def _sanitize_value(val: Any) -> Any:
    """پاکسازی بازگشتی: str/dict/list."""
    if isinstance(val, str):
        return _clean_str(val)
    elif isinstance(val, dict):
        return {k: _sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_sanitize_value(i) for i in val]
    return val


def sanitize_proxy(p: Dict) -> Tuple[Dict, bool]:
    """پاکسازی یک proxy dict."""
    clean = {}
    changed = False
    for k, v in p.items():
        new_v = _sanitize_value(v)
        clean[k] = new_v
        if new_v != v:
            changed = True
    return clean, changed


def sanitize_all(proxies: List[Dict]) -> Tuple[List[Dict], int]:
    """پاکسازی همه proxy ها."""
    result = []
    total = 0
    for p in proxies:
        clean, changed = sanitize_proxy(p)
        if changed:
            print(f"  [sanitizer] 🧹 کنترلی حذف شد: {p.get('name', '?')}")
            total += 1
        result.append(clean)
    return result, total
