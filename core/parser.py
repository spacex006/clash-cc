"""
parser.py — تبدیل URI خام به proxy dict برای Clash/Mihomo.

فرمت‌های پشتیبانی‌شده:
  vmess://   VLESS://   ss://   trojan://   hysteria2://   hy2://
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Dict, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# ابزارها
# ──────────────────────────────────────────────────────────────────────────────

def _b64d(s: str) -> str:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="replace")


def _hp(raw: str) -> Tuple[str, int]:
    """پارس host:port با پشتیبانی IPv6 براکت‌دار."""
    raw = raw.split("?")[0].split("#")[0].strip()
    if raw.startswith("["):
        end  = raw.index("]")
        host = raw[1:end]
        tail = raw[end + 1:].lstrip(":")
        port = int(tail) if tail.isdigit() else 443
        return host, port
    if ":" in raw:
        h, p = raw.rsplit(":", 1)
        return h.strip(), int(p.strip())
    return raw, 443


def _name(raw: str, fallback: str, maxlen: int = 80) -> str:
    """پاکسازی و محدودسازی نام."""
    s = (raw or fallback).strip()
    s = re.sub(r"[\x00-\x1f\x7f]", "", s)
    return (s or fallback)[:maxlen]


def _int(val, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


# ──────────────────────────────────────────────────────────────────────────────
# پارسرها
# ──────────────────────────────────────────────────────────────────────────────

def _vmess(uri: str) -> Optional[Dict]:
    try:
        d = json.loads(_b64d(uri[8:]))
        host = str(d.get("add") or "").strip()
        uuid = str(d.get("id")  or "").strip()
        if not host or not uuid:
            return None

        port = _int(d.get("port"), 443)
        p: Dict = {
            "_uri":   uri,
            "name":   _name(d.get("ps") or d.get("remarks") or "", f"vmess-{host}:{port}"),
            "type":   "vmess",
            "server": host,
            "port":   port,
            "uuid":   uuid,
            "alterId": max(0, _int(d.get("aid") or d.get("alterId"), 0)),
            "cipher": str(d.get("scy") or d.get("security") or "auto"),
            "udp":    True,
        }

        # TLS
        if str(d.get("tls", "")).lower() in ("tls", "1", "true"):
            p["tls"] = True
            sni = str(d.get("sni") or "").strip()
            if sni:
                p["servername"] = sni
            fp = str(d.get("fp") or "").strip()
            if fp and fp != "none":
                p["client-fingerprint"] = fp

        # Transport
        net = str(d.get("net") or "tcp").lower()
        _add_transport(p, net, d.get("path", ""), d.get("host", ""))

        return p
    except Exception:
        return None


def _vless(uri: str) -> Optional[Dict]:
    try:
        rest = uri[8:]

        name_raw = ""
        if "#" in rest:
            rest, name_raw = rest.rsplit("#", 1)
            name_raw = urllib.parse.unquote(name_raw)

        qs = ""
        if "?" in rest:
            rest, qs = rest.split("?", 1)

        if "@" not in rest:
            return None
        uuid, hp_raw = rest.split("@", 1)
        uuid = uuid.strip()

        host, port = _hp(hp_raw)
        if not host or not uuid:
            return None

        q = dict(urllib.parse.parse_qsl(qs, keep_blank_values=False))
        p: Dict = {
            "_uri":   uri,
            "name":   _name(name_raw, f"vless-{host}:{port}"),
            "type":   "vless",
            "server": host,
            "port":   port,
            "uuid":   uuid,
            "udp":    True,
        }

        sec = q.get("security", "none").lower()
        if sec in ("tls", "reality"):
            p["tls"] = True
            sni = q.get("sni", "").strip()
            if sni:
                p["servername"] = sni
            fp = q.get("fp", "").strip()
            if fp and fp != "none":
                p["client-fingerprint"] = fp
            alpn = q.get("alpn", "").strip()
            if alpn:
                p["alpn"] = [a for a in alpn.split(",") if a]

            if sec == "reality":
                pbk = q.get("pbk", "").strip()
                sid = q.get("sid", "").strip()
                # اگر pbk یا sid نباشه، اصلاً reality-opts نساز
                # (post_fix_filter بعداً این proxy رو حذف می‌کنه)
                if pbk and sid:
                    ro: Dict = {
                        "public-key": pbk,
                        "short-id":   sid,
                    }
                    spx = q.get("spx", "").strip()
                    if spx:
                        ro["spider-x"] = spx
                    p["reality-opts"] = ro
                else:
                    # REALITY بدون pbk/sid نامعتبر است → علامت‌گذاری برای حذف
                    p["reality-opts"] = {"public-key": pbk, "short-id": sid}

        flow = q.get("flow", "").strip()
        if flow:
            p["flow"] = flow

        net = q.get("type", "tcp").lower()
        path = urllib.parse.unquote(q.get("path", ""))
        host_h = q.get("host", "")
        _add_transport(p, net, path, host_h, q)

        return p
    except Exception:
        return None


def _ss(uri: str) -> Optional[Dict]:
    try:
        rest = uri[5:]
        name_raw = ""
        if "#" in rest:
            rest, name_raw = rest.rsplit("#", 1)
            name_raw = urllib.parse.unquote(name_raw)
        if "?" in rest:
            rest = rest.split("?")[0]

        if "@" in rest:
            ui_b64, hp_raw = rest.rsplit("@", 1)
            try:
                ui = _b64d(ui_b64)
            except Exception:
                ui = urllib.parse.unquote(ui_b64)
        else:
            decoded = _b64d(rest)
            if "@" not in decoded:
                return None
            ui, hp_raw = decoded.rsplit("@", 1)

        if ":" not in ui:
            return None
        method, password = ui.split(":", 1)
        host, port = _hp(hp_raw)
        if not host:
            return None

        return {
            "_uri":     uri,
            "name":     _name(name_raw, f"ss-{host}:{port}"),
            "type":     "ss",
            "server":   host,
            "port":     port,
            "cipher":   method.strip(),
            "password": password.strip(),
            "udp":      True,
        }
    except Exception:
        return None


def _trojan(uri: str) -> Optional[Dict]:
    try:
        rest = uri[9:]
        name_raw = ""
        if "#" in rest:
            rest, name_raw = rest.rsplit("#", 1)
            name_raw = urllib.parse.unquote(name_raw)
        qs = ""
        if "?" in rest:
            rest, qs = rest.split("?", 1)
        if "@" not in rest:
            return None
        password, hp_raw = rest.rsplit("@", 1)
        password = urllib.parse.unquote(password).strip()
        host, port = _hp(hp_raw)
        if not host or not password:
            return None

        q = dict(urllib.parse.parse_qsl(qs, keep_blank_values=False))
        p: Dict = {
            "_uri":     uri,
            "name":     _name(name_raw, f"trojan-{host}:{port}"),
            "type":     "trojan",
            "server":   host,
            "port":     port,
            "password": password,
            "udp":      True,
            "tls":      True,
        }
        sni = q.get("sni", "").strip()
        if sni: p["sni"] = sni
        fp = q.get("fp", "").strip()
        if fp and fp != "none": p["client-fingerprint"] = fp
        alpn = q.get("alpn", "").strip()
        if alpn: p["alpn"] = [a for a in alpn.split(",") if a]

        net = q.get("type", "tcp").lower()
        path = urllib.parse.unquote(q.get("path", ""))
        _add_transport(p, net, path, q.get("host", ""), q)

        return p
    except Exception:
        return None


def _hy2(uri: str) -> Optional[Dict]:
    try:
        scheme = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
        rest   = uri[len(scheme):]
        name_raw = ""
        if "#" in rest:
            rest, name_raw = rest.rsplit("#", 1)
            name_raw = urllib.parse.unquote(name_raw)
        qs = ""
        if "?" in rest:
            rest, qs = rest.split("?", 1)
        auth = ""
        if "@" in rest:
            auth, hp_raw = rest.rsplit("@", 1)
            auth = urllib.parse.unquote(auth).strip()
        else:
            hp_raw = rest

        host, port = _hp(hp_raw)
        if not host:
            return None

        q = dict(urllib.parse.parse_qsl(qs, keep_blank_values=False))
        password = auth or q.get("auth") or q.get("password") or ""
        p: Dict = {
            "_uri":     uri,
            "name":     _name(name_raw, f"hy2-{host}:{port}"),
            "type":     "hysteria2",
            "server":   host,
            "port":     port,
            "password": str(password).strip(),
            "udp":      True,
        }
        sni = q.get("sni", "").strip()
        if sni: p["sni"] = sni
        if q.get("insecure", "0") in ("1", "true"):
            p["skip-cert-verify"] = True
        obfs = q.get("obfs", "").strip()
        if obfs:
            p["obfs"] = obfs
            obfs_pwd = q.get("obfs-password", "").strip()
            if obfs_pwd: p["obfs-password"] = obfs_pwd

        return p
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# کمکی: اضافه‌کردن transport بر اساس نوع شبکه
# ──────────────────────────────────────────────────────────────────────────────

def _add_transport(p: Dict, net: str, path: str = "", host_h: str = "",
                   q: Optional[Dict] = None) -> None:
    q = q or {}
    if net == "ws":
        p["network"] = "ws"
        wo: Dict = {}
        if path:    wo["path"]    = path
        if host_h:  wo["headers"] = {"Host": host_h}
        if wo:      p["ws-opts"]  = wo
    elif net == "grpc":
        p["network"] = "grpc"
        svc = (q.get("serviceName") or q.get("service-name") or path or "").strip()
        if svc: p["grpc-opts"] = {"grpc-service-name": svc}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        h2o: Dict = {}
        if host_h: h2o["host"] = [host_h]
        if path:   h2o["path"] = path
        if h2o:    p["h2-opts"] = h2o
    elif net in ("splithttp", "xhttp"):
        p["network"] = "splithttp"
        so: Dict = {}
        if path:   so["path"]    = path
        if host_h: so["headers"] = {"Host": host_h}
        if so:     p["splithttp-opts"] = so
    elif net == "quic":
        p["network"] = "quic"
    # tcp: نیازی به تنظیم network نیست


# ──────────────────────────────────────────────────────────────────────────────
# دیسپچر اصلی
# ──────────────────────────────────────────────────────────────────────────────

_PARSERS = {
    "vmess://":     _vmess,
    "vless://":     _vless,
    "ss://":        _ss,
    "trojan://":    _trojan,
    "hysteria2://": _hy2,
    "hy2://":       _hy2,
}


def parse_uri(uri: str) -> Optional[Dict]:
    """تبدیل یک URI خام به proxy dict. در صورت خطا None برمی‌گرداند."""
    for prefix, fn in _PARSERS.items():
        if uri.startswith(prefix):
            return fn(uri)
    return None


def parse_many(uris: list) -> list:
    """پارس لیست URI ها؛ موارد نامعتبر رها می‌شوند."""
    proxies = []
    errors  = 0
    for uri in uris:
        p = parse_uri(uri)
        if p and _is_valid(p):
            proxies.append(p)
        else:
            errors += 1
    return proxies, errors


def _is_valid(p: Dict) -> bool:
    try:
        return (
            bool(p.get("server"))
            and 1 <= int(p.get("port", 0)) <= 65535
            and bool(p.get("type"))
        )
    except (TypeError, ValueError):
        return False
