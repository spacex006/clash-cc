"""
converter.py — ساخت Clash/Mihomo YAML از proxy dict ها.

گروه‌ها:
  ⚡ AUTO    →  url-test (Clash خودش سریع‌ترین را انتخاب می‌کند)
  🔧 MANUAL  →  select   (انتخاب دستی کاربر)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml

# ──────────────────────────────────────────────────────────────────────────────
# فیلدهای داخلی که نباید وارد YAML شوند
# ──────────────────────────────────────────────────────────────────────────────
_INTERNAL_KEYS = {"_uri", "_latency_ms"}


def _clean_proxy(p: Dict) -> Dict:
    """حذف فیلدهای داخلی از proxy dict."""
    return {k: v for k, v in p.items() if k not in _INTERNAL_KEYS}


# ──────────────────────────────────────────────────────────────────────────────
# ساخت config dict
# ──────────────────────────────────────────────────────────────────────────────

def build_config(proxies: List[Dict]) -> Dict:
    """
    ساخت کامل Clash/Mihomo config dict.
    proxies باید از قبل sorted-by-latency باشند (AUTO group از این ترتیب استفاده می‌کند).
    """
    clean_proxies = [_clean_proxy(p) for p in proxies]
    names         = [p["name"] for p in clean_proxies]

    # ── DNS ─────────────────────────────────────────────────────────────────
    dns: Dict = {
        "enable":        True,
        "ipv6":          False,
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

    # ── ⚡ AUTO (url-test) ────────────────────────────────────────────────────
    # Clash خودش latency می‌گیره و بهترین را انتخاب می‌کند.
    # ترتیب proxies در این group = اولویت اولیه (پس از اولین test تغییر می‌کند).
    group_auto: Dict = {
        "name":      "⚡ AUTO",
        "type":      "url-test",
        "url":       "http://1.1.1.1/generate_204",
        "interval":  180,          # هر ۳ دقیقه تست
        "tolerance": 30,           # حساسیت تعویض: 50۰ms
        "lazy":      False,        # همیشه در پس‌زمینه تست کند
        "proxies":   names if names else ["DIRECT"],
    }

    # ── 🔧 MANUAL (select) ────────────────────────────────────────────────────
    group_manual: Dict = {
        "name":    "🔧 MANUAL",
        "type":    "select",
        "proxies": ["⚡ AUTO", "DIRECT"] + names,
    }

    # ── PROXY (گروه اصلی) ────────────────────────────────────────────────────
    group_proxy: Dict = {
        "name":    "PROXY",
        "type":    "select",
        "proxies": ["⚡ AUTO", "🔧 MANUAL", "DIRECT"],
    }

    return {
        "mixed-port": 7890,
        "allow-lan":  True,
        "mode":       "rule",
        "log-level":  "warning",
        "ipv6":       True,
        "unified-delay":             True,
        "tcp-concurrent":            True,
        "global-client-fingerprint": "chrome",
        "dns":          dns,
        "proxies":      clean_proxies,
        "proxy-groups": [group_proxy, group_auto, group_manual],
        "rules":        ["MATCH,PROXY"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# نوشتن به فایل
# ──────────────────────────────────────────────────────────────────────────────

def write_yaml(config: Dict, path: Path, proxy_count: int) -> None:
    """سریالیزیشن config به YAML و نوشتن به فایل."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    header = (
        "# ══════════════════════════════════════════════════════\n"
        "# Clash / Mihomo / FClash — auto-generated profile\n"
        f"# Updated  : {now}\n"
        f"# Proxies  : {proxy_count}\n"
        "# Groups   : ⚡ AUTO (url-test)  🔧 MANUAL (select)\n"
        "# ══════════════════════════════════════════════════════\n\n"
    )

    # ── Custom representer: همه string ها رو با single-quote بنویس ────────
    class QuotedStr(str):
        pass

    def quoted_str_representer(dumper, data):
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")

    yaml.add_representer(QuotedStr, quoted_str_representer)

    # ── همه short-id ها و فیلدهای حساس رو wrap کن ────────────────────────
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
