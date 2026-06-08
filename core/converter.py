"""
converter.py — ساخت Clash/Mihomo YAML با گروه‌های کشور.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml

from .geo import country_flag

_INTERNAL_KEYS = {"_uri", "_latency_ms", "_country", "_resolved_ip", "_is_cdn"}

def _clean_proxy(p: Dict) -> Dict:
    return {k: v for k, v in p.items() if k not in _INTERNAL_KEYS}


# ──────────────────────────────────────────────────────────────────────────────

def build_config(proxies: List[Dict]) -> Dict:
    """ساخت Clash config با گروه‌های کشور."""
    clean_proxies = [_clean_proxy(p) for p in proxies]
    names = [p["name"] for p in clean_proxies]

    # ── گروه‌بندی بر اساس کشور ─────────────────────────────────────────────
    country_groups = defaultdict(list)
    for p in proxies:
        country = p.get("_country", "XX")
        country_groups[country].append(p["name"])

    # حداقل 3 proxy برای ساخت گروه جداگانه
    MIN_PROXIES_PER_GROUP = 3

    big_countries = {
        c: ns for c, ns in country_groups.items()
        if len(ns) >= MIN_PROXIES_PER_GROUP
    }
    small_countries = []
    for c, ns in country_groups.items():
        if len(ns) < MIN_PROXIES_PER_GROUP:
            small_countries.extend(ns)

    # ── DNS ─────────────────────────────────────────────────────────────────
    dns: Dict = {
        "enable": True,
        "ipv6": False,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": [
            "*.lan", "*.local",
            "+.stun.*.*", "+.stun.*.*.*",
        ],
        "nameserver": [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
        ],
        "fallback": [
            "https://1.0.0.1/dns-query",
            "tls://8.8.4.4:853",
        ],
    }

    # ── گروه ⚡ AUTO ─────────────────────────────────────────────────────────
    group_auto = {
        "name": "⚡ AUTO",
        "type": "url-test",
        "url": "http://1.1.1.1/generate_204",
        "interval": 180,
        "tolerance": 30,
        "lazy": False,
        "proxies": names if names else ["DIRECT"],
    }

    # ── گروه 🔧 MANUAL ───────────────────────────────────────────────────────
    group_manual = {
        "name": "🔧 MANUAL",
        "type": "select",
        "proxies": ["⚡ AUTO", "DIRECT"] + names,
    }

    # ── گروه‌های کشور ────────────────────────────────────────────────────────
    country_group_objs = []
    country_group_names = []

    # مرتب‌سازی: کشورها به ترتیب تعداد proxy
    for country in sorted(big_countries.keys(), key=lambda c: -len(big_countries[c])):
        c_names = big_countries[country]
        flag = country_flag(country)
        group_name = f"{flag} {country}"

        country_group_objs.append({
            "name": group_name,
            "type": "url-test",
            "url": "http://1.1.1.1/generate_204",
            "interval": 300,
            "tolerance": 50,
            "lazy": True,
            "proxies": c_names,
        })
        country_group_names.append(group_name)

    # گروه 🌍 OTHERS برای کشورهای کم تعداد
    if small_countries:
        country_group_objs.append({
            "name": "🌍 OTHERS",
            "type": "url-test",
            "url": "http://1.1.1.1/generate_204",
            "interval": 300,
            "tolerance": 50,
            "lazy": True,
            "proxies": small_countries,
        })
        country_group_names.append("🌍 OTHERS")

    # ── گروه اصلی PROXY ──────────────────────────────────────────────────────
    group_proxy = {
        "name": "PROXY",
        "type": "select",
        "proxies": ["⚡ AUTO", "🔧 MANUAL"] + country_group_names + ["DIRECT"],
    }

    # ── ترتیب نهایی گروه‌ها ─────────────────────────────────────────────────
    proxy_groups = [group_proxy, group_auto, group_manual] + country_group_objs

    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "global-client-fingerprint": "chrome",
        "dns": dns,
        "proxies": clean_proxies,
        "proxy-groups": proxy_groups,
        "rules": ["MATCH,PROXY"],
    }


# ──────────────────────────────────────────────────────────────────────────────

def write_yaml(config: Dict, path: Path, proxy_count: int) -> None:
    """سریالیزیشن config به YAML."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    header = (
        "# ══════════════════════════════════════════════════════\n"
        "# Clash / Mihomo / FClash — auto-generated profile\n"
        f"# Updated  : {now}\n"
        f"# Proxies  : {proxy_count}\n"
        "# Groups   : ⚡ AUTO  🔧 MANUAL  + Country groups\n"
        "# ══════════════════════════════════════════════════════\n\n"
    )

    # ── Quoted string برای فیلدهای حساس ──────────────────────────────────
    class QuotedStr(str):
        pass

    def quoted_str_representer(dumper, data):
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")

    yaml.add_representer(QuotedStr, quoted_str_representer)

    def wrap_sensitive(obj):
        if isinstance(obj, dict):
            new = {}
            for k, v in obj.items():
                if k in ("short-id", "public-key", "uuid", "password", "uri") and isinstance(v, str):
                    new[k] = QuotedStr(v)
                else:
                    new[k] = wrap_sensitive(v)
            return new
        elif isinstance(obj, list):
            return [wrap_sensitive(i) for i in obj]
        return obj

    safe_config = wrap_sensitive(config)

    body = yaml.dump(
        safe_config,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        indent=2,
        width=4096,
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + body, encoding="utf-8")
