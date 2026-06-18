#!/usr/bin/env python3
"""main.py — orchestrator اصلی."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

CONFIGS_TXT  = Path("output/configs.txt")
PROFILE_YAML = Path("output/profile.yaml")

from core.deduplicator import DedupConfig
DEDUP_CFG = DedupConfig(
    uuid_dedup=False,
    server_port_dedup=True,
    name_dedup=False,
    tcp_test=True,
    tcp_timeout=3.0,
    tcp_workers=120,
)


def _banner(step: str, n: int = 0) -> None:
    suffix = f"  ({n:,})" if n else ""
    print(f"\n{'─'*52}")
    print(f"  {step}{suffix}")
    print(f"{'─'*52}")


def main() -> int:
    start = datetime.now(timezone.utc)
    print(f"🚀  clash-lite pipeline — {start.strftime('%Y-%m-%d %H:%M UTC')}")

    from core.fetcher import fetch_all
    from core.parser import parse_many
    from core.deduplicator import deduplicate, tcp_filter_and_sort, unique_names
    from core.fixer import fix_all, post_fix_filter
    from core.sanitizer import sanitize_all
    from core.mihomo_tester import http_test_all
    from core.converter import build_config, write_yaml
    from core.validator import print_report

    # خواندن URL از متغیر محیطی یا متغیر secret
    url = os.environ.get("URL", "").strip()
    if not url:
        print("❌ متغیر URL تنظیم نشده است.", file=sys.stderr)
        print("   در GitHub Actions باید secret به نام URL تعریف شود.", file=sys.stderr)
        return 1

    urls = [url]
    _banner("① FETCH", len(urls))
    raw_uris = fetch_all(urls)
    print(f"  جمع URI : {len(raw_uris):,}")
    if not raw_uris:
        return 1

    _banner("② PARSE", len(raw_uris))
    proxies, parse_errors = parse_many(raw_uris)
    print(f"  پارس موفق : {len(proxies):,} | رد شده : {parse_errors:,}")

    _banner("③ DEDUP")
    before = len(proxies)
    proxies = deduplicate(proxies, DEDUP_CFG)
    print(f"  {before:,} → {len(proxies):,}  (−{before - len(proxies):,})")

    _banner("④ FIX")
    proxies, n_fixes = fix_all(proxies)
    print(f"  اصلاحات: {n_fixes}")

    _banner("④-b SANITIZE")
    proxies, n_san = sanitize_all(proxies)
    print(f"  پاکسازی: {n_san}")

    before_filter = len(proxies)
    proxies, removed = post_fix_filter(proxies)
    print(f"  [post-filter] حذف شد: {len(removed)} (از {before_filter})")

    if DEDUP_CFG.tcp_test:
        _banner("⑤ TCP TEST + SORT", len(proxies))
        alive, dead = tcp_filter_and_sort(
            proxies,
            timeout=DEDUP_CFG.tcp_timeout,
            workers=DEDUP_CFG.tcp_workers,
        )
        print(f"  زنده: {len(alive):,} | مرده: {len(dead):,}")
        proxies = alive

    if not proxies:
        return 1

    # ⑥ HTTP TEST واقعی با Mihomo (5-8 دقیقه)
    _banner("⑥ MIHOMO HTTP TEST (5-8 min)", len(proxies))
    proxies = http_test_all(proxies)
    if not proxies:
        print("⚠ هیچ proxy واقعاً زنده‌ای نموند.")
        return 1

    proxies = unique_names(proxies)

    _banner("⑦ SAVE configs.txt", len(proxies))
    CONFIGS_TXT.parent.mkdir(parents=True, exist_ok=True)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    uris_out = [p.get("_uri", "") for p in proxies if p.get("_uri")]
    CONFIGS_TXT.write_text(
        f"# Updated: {now_str} | Count: {len(uris_out)}\n"
        + "\n".join(uris_out) + "\n",
        encoding="utf-8",
    )

    _banner("⑧ CONVERT → YAML")
    config = build_config(proxies)
    write_yaml(config, PROFILE_YAML, len(proxies))

    _banner("⑨ VALIDATE")
    ok = print_report(PROFILE_YAML)

    elapsed = (datetime.now(timezone.utc) - start).seconds
    print(f"\n✅ تمام شد در {elapsed}s | {len(proxies):,} proxy")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
