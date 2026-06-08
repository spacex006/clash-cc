"""
validator.py — اعتبارسنجی فایل YAML خروجی.

بررسی‌ها:
  ✓ YAML parse بدون خطا
  ✓ وجود بخش proxies
  ✓ فیلدهای اجباری هر proxy
  ✓ معتبربودن REALITY short-id
  ✓ پورت در بازه 1-65535
  ✓ وجود proxy-groups
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

import yaml

from .fixer import is_valid_short_id

# ──────────────────────────────────────────────────────────────────────────────

_REQUIRED_FIELDS: dict = {
    "vmess":     ["server", "port", "uuid", "cipher"],
    "vless":     ["server", "port", "uuid"],
    "ss":        ["server", "port", "cipher", "password"],
    "trojan":    ["server", "port", "password"],
    "hysteria2": ["server", "port", "password"],
}

# ──────────────────────────────────────────────────────────────────────────────

def validate(yaml_path: Path) -> Tuple[bool, List[str], List[str]]:
    """
    بررسی فایل YAML.

    برمی‌گرداند: (is_ok, errors, warnings)
      is_ok    = True اگر هیچ error وجود نداشته باشد
      errors   = مشکلات بحرانی
      warnings = مشکلات غیربحرانی
    """
    errors:   List[str] = []
    warnings: List[str] = []

    # ── ۱. Parse YAML ─────────────────────────────────────────────────────────
    try:
        raw = yaml_path.read_text(encoding="utf-8")
        # حذف comment های ابتدایی برای yaml.safe_load
        yaml_content = "\n".join(
            ln for ln in raw.splitlines()
            if not ln.startswith("#")
        )
        config = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        errors.append(f"YAML parse error: {exc}")
        return False, errors, warnings
    except Exception as exc:
        errors.append(f"File read error: {exc}")
        return False, errors, warnings

    if not isinstance(config, dict):
        errors.append("محتوای YAML یک dict نیست.")
        return False, errors, warnings

    # ── ۲. بخش proxies ─────────────────────────────────────────────────────────
    proxies = config.get("proxies")
    if not isinstance(proxies, list):
        errors.append("بخش 'proxies' یافت نشد یا لیست نیست.")
        return False, errors, warnings

    if len(proxies) == 0:
        warnings.append("هیچ proxy ای در فایل نیست.")

    # ── ۳. بررسی هر proxy ─────────────────────────────────────────────────────
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            errors.append(f"proxy #{i} یک dict نیست.")
            continue

        ptype = p.get("type", "unknown")
        pname = p.get("name", f"#proxy-{i}")

        # فیلدهای اجباری
        required = _REQUIRED_FIELDS.get(ptype, ["server", "port"])
        for fld in required:
            if not p.get(fld):
                warnings.append(f"[{pname}] فیلد '{fld}' خالی یا غایب")

        # پورت
        try:
            port = int(p.get("port", 0))
            if not (1 <= port <= 65535):
                errors.append(f"[{pname}] port={port} خارج از بازه")
        except (TypeError, ValueError):
            errors.append(f"[{pname}] port نامعتبر: {p.get('port')!r}")

        # REALITY short-id
        ro = p.get("reality-opts")
        if isinstance(ro, dict):
            sid = ro.get("short-id", "")
            if not is_valid_short_id(sid):
                errors.append(
                    f"[{pname}] REALITY short-id نامعتبر: {sid!r} "
                    f"(باید hex زوج ≤16 کاراکتر)"
                )

    # ── ۴. proxy-groups ────────────────────────────────────────────────────────
    groups = config.get("proxy-groups")
    if not isinstance(groups, list) or len(groups) == 0:
        warnings.append("proxy-groups خالی یا غایب است.")

    # ── ۵. rules ───────────────────────────────────────────────────────────────
    rules = config.get("rules")
    if not isinstance(rules, list) or len(rules) == 0:
        warnings.append("rules خالی یا غایب است.")

    is_ok = len(errors) == 0
    return is_ok, errors, warnings


def print_report(yaml_path: Path) -> bool:
    """اجرای validate و چاپ گزارش. برمی‌گرداند True اگر فایل سالم باشد."""
    is_ok, errors, warnings = validate(yaml_path)

    print(f"\n{'━'*52}")
    print(f"  🔍  YAML Validator — {yaml_path.name}")
    print(f"{'━'*52}")

    if errors:
        print(f"  ❌  {len(errors)} خطا:")
        for e in errors:
            print(f"       • {e}")
    else:
        print("  ✅  هیچ خطایی نیست.")

    if warnings:
        print(f"  ⚠   {len(warnings)} هشدار:")
        for w in warnings:
            print(f"       • {w}")

    print(f"{'━'*52}\n")
    return is_ok
