#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Config Server (Option A): HTTPS-выдача RAW VLESS + админ-API.
Эндпоинты:
- POST /admin/keys/upload  (X-Auth-Token) — загрузка ключей trial/month/year
- POST /admin/assign       (X-Auth-Token) — привязка ключа к user_id
- GET  /sub/<token>        (public)       — отдаёт RAW VLESS (token = base64url("<uid>_<type>"))
- GET  /health

Изменение: если t=trial и подписки нет/неактивна — сервер сам выдаёт первый свободный trial-ключ и создаёт активную подписку.
"""

from __future__ import annotations
import os, re, json, base64, logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple
from flask import Flask, request, Response, jsonify, abort

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpn_config_server")

# Хранилище
DATA_DIR = os.environ.get("DATA_DIR", os.path.abspath("./data"))
os.makedirs(DATA_DIR, exist_ok=True)
KEYS_FILE = os.path.join(DATA_DIR, "keys_store.json")
SUBS_FILE = os.path.join(DATA_DIR, "subscriptions.json")

AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "").strip()

# ---------- helpers ----------
def _load_json(path: str, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"read {path} error: {e}")
    return default

def _save_json(path: str, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"write {path} error: {e}")

def load_keys_store() -> Dict[str, List[str]]:
    d = _load_json(KEYS_FILE, {})
    return {
        "trial": d.get("trial", []) or [],
        "month": d.get("month", []) or [],
        "year": d.get("year", []) or [],
        "used": d.get("used", []) or [],
    }

def save_keys_store(store: Dict[str, List[str]]):
    _save_json(KEYS_FILE, store)

def load_subscriptions() -> Dict[str, Dict]:
    return _load_json(SUBS_FILE, {})

def save_subscriptions(subs: Dict[str, Dict]):
    _save_json(SUBS_FILE, subs)

def b64url_decode_to_str(token: str) -> str:
    pad = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode((token + pad).encode("ascii")).decode("utf-8")

def normalize_vless_for_v2raytun(vless_key: str) -> str:
    try:
        if not vless_key.startswith("vless://"):
            return vless_key
        m = re.match(r"vless://([^@]+)@([^:]+):(\d+)\?(.+?)(?:#(.*))?$", vless_key)
        if not m:
            return vless_key
        uuid, host, port, params_str, fragment = m.group(1), m.group(2), m.group(3), m.group(4), (m.group(5) or "")
        from urllib.parse import parse_qs, unquote
        params = parse_qs(params_str)
        norm = {}
        for k, vals in params.items():
            if k == "authority":
                continue
            norm[k] = vals[0] if vals else ""
        if "encryption" not in norm:
            norm["encryption"] = "none"
        q = "&".join([f"{k}={v}" if v else k for k, v in norm.items()])
        res = f"vless://{uuid}@{host}:{port}?{q}"
        if fragment:
            frag = re.sub(r"[^\w\-]", "", unquote(fragment))
            if frag:
                res += f"#{frag}"
        return res
    except Exception:
        key = re.sub(r"[&?]authority=[^&]*(?=&|$)", "", vless_key)
        key = re.sub(r"[?&]&+", "?", key); key = re.sub(r"&+", "&", key); key = re.sub(r"[?&]$", "", key)
        return key

def _require_auth():
    if not AUTH_TOKEN or request.headers.get("X-Auth-Token", "") != AUTH_TOKEN:
        abort(401, description="Unauthorized")

# ---------- admin ----------
@app.route("/admin/keys/upload", methods=["POST"])
def admin_keys_upload():
    _require_auth()
    payload = request.get_json(silent=True) or {}
    incoming = {
        "trial": payload.get("trial", []) or [],
        "month": payload.get("month", []) or [],
        "year": payload.get("year", []) or [],
    }
    store = load_keys_store()
    used = set(store.get("used", []))
    added = {"trial": 0, "month": 0, "year": 0}
    for t in ("trial", "month", "year"):
        bucket = set(store.get(t, []))
        for raw in incoming[t]:
            if not (isinstance(raw, str) and raw.startswith("vless://")):
                continue
            nk = normalize_vless_for_v2raytun(raw)
            if nk not in bucket and nk not in used:
                bucket.add(nk); added[t] += 1
        store[t] = sorted(bucket)
    save_keys_store(store)
    return jsonify({"success": True, "added": added, "total": {t: len(store[t]) for t in ("trial", "month", "year")}})

@app.route("/admin/assign", methods=["POST"])
def admin_assign():
    _require_auth()
    d = request.get_json(silent=True) or {}
    user_id = d.get("user_id")
    sub_type = (d.get("type") or "").strip()
    key = (d.get("key") or "").strip()
    end_date = (d.get("end_date") or "").strip()
    if not user_id or sub_type not in ("trial", "month", "year") or not key.startswith("vless://"):
        return jsonify({"success": False, "error": "user_id/type/key required"}), 400

    key = normalize_vless_for_v2raytun(key)
    subs = load_subscriptions()
    subs[str(user_id)] = {
        "type": sub_type,
        "key": key,
        "end_date": end_date,
        "active": True,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_subscriptions(subs)

    store = load_keys_store()
    for t in ("trial", "month", "year"):
        if key in store.get(t, []):
            store[t].remove(key)
    used = set(store.get("used", [])); used.add(key); store["used"] = sorted(used)
    save_keys_store(store)
    return jsonify({"success": True})

# ---------- public /sub ----------
def _parse_token(token: str) -> Tuple[str, str] | None:
    try:
        decoded = b64url_decode_to_str(token)
        uid_str, sub_type = decoded.split("_", 1)
        return uid_str.strip(), sub_type.strip()
    except Exception:
        return None

def _auto_issue_trial(uid_str: str) -> bool:
    """Выдаёт trial-ключ и создаёт активную подписку, если есть свободные ключи."""
    try:
        store = load_keys_store()
        used = set(store.get("used", []))
        for key in store.get("trial", []):
            if key and key.startswith("vless://") and key not in used:
                key_norm = normalize_vless_for_v2raytun(key)
                # помечаем использованным и удаляем из trial
                used.add(key_norm)
                if key in store["trial"]:
                    store["trial"].remove(key)
                store["used"] = sorted(used)
                save_keys_store(store)
                # создаём подписку на 13 дней
                subs = load_subscriptions()
                start_iso = datetime.now(timezone.utc).isoformat()
                end_iso = (datetime.now(timezone.utc) + timedelta(days=13)).isoformat()
                subs[uid_str] = {
                    "type": "trial",
                    "key": key_norm,
                    "end_date": end_iso,
                    "active": True,
                    "updated_at": start_iso,
                }
                save_subscriptions(subs)
                logger.info(f"Auto-issued trial for user {uid_str}")
                return True
    except Exception as e:
        logger.error(f"auto_issue_trial error: {e}")
    return False

@app.route("/sub/<token>", methods=["GET"])
def get_subscription(token: str):
    parsed = _parse_token(token)
    if not parsed:
        return Response("Bad token", status=400, mimetype="text/plain")
    uid_str, sub_type = parsed

    # грузим подписку
    subs = load_subscriptions()
    sub = subs.get(uid_str)

    # автотрил: если trial и нет активной подписки — выдаём ключ и перечитываем
    if (not sub or not sub.get("active")) and sub_type == "trial":
        if _auto_issue_trial(uid_str):
            subs = load_subscriptions()
            sub = subs.get(uid_str)

    if not sub or not sub.get("active"):
        return Response("Subscription inactive", status=403, mimetype="text/plain")

    if (sub.get("type") or "").strip() != sub_type:
        return Response("Wrong subscription type", status=400, mimetype="text/plain")

    end_iso = (sub.get("end_date") or "").strip()
    if end_iso:
        try:
            end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > end_dt.replace(tzinfo=timezone.utc):
                return Response("Subscription expired", status=403, mimetype="text/plain")
        except Exception:
            pass

    key = (sub.get("key") or "").strip()
    if not key.startswith("vless://"):
        return Response("Key not found", status=404, mimetype="text/plain")

    key = normalize_vless_for_v2raytun(key)
    return Response(
        key,
        status=200,
        mimetype="text/plain",
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Disposition": 'inline; filename="config.sub"',
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Access-Control-Allow-Origin": "*",
        },
    )

# ---------- health ----------
@app.route("/health")
def health():
    return Response("OK", status=200, mimetype="text/plain")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
