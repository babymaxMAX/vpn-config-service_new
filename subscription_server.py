#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Config Server (Option A): HTTPS-выдача "сырого" VLESS + админ-API.

Эндпоинты:
- POST /admin/keys/upload  (X-Auth-Token) — загрузка/обновление ключей trial/month/year
- POST /admin/assign       (X-Auth-Token) — привязка конкретного ключа к user_id и тарифу
- GET  /sub/<token>        (public)       — возвращает RAW VLESS для пользователя по токену
- GET  /health                           — healthcheck

Токен /sub:
- token = base64url("<user_id>_<type>"), где type ∈ {trial, month, year}, без символов '=' в конце

Пример ссылки в боте (через deeplink.website):
- https://deeplink.website/?url=https%3A%2F%2F<your-app>.onrender.com%2Fsub%2F<token>

Хранилище:
- DATA_DIR (env, по умолчанию ./data), файлы:
  - keys_store.json: { "trial":[], "month":[], "year":[], "used":[] }
  - subscriptions.json: { "<uid>": { "type": "...", "key": "vless://...", "end_date": "...", "active": true } }

ENV:
- AUTH_TOKEN — общий секрет для админ-роутов (обязательно на проде)
- DATA_DIR   — путь к каталогу данных (на Render — укажите на persist-диск)
"""

from __future__ import annotations

import os
import re
import json
import base64
import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from flask import Flask, request, Response, jsonify, abort

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpn_config_server")

# ---------------------- Конфигурация/пути ----------------------
DATA_DIR = os.environ.get("DATA_DIR", os.path.abspath("./data"))
os.makedirs(DATA_DIR, exist_ok=True)

KEYS_FILE = os.path.join(DATA_DIR, "keys_store.json")
SUBS_FILE = os.path.join(DATA_DIR, "subscriptions.json")

AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "").strip()  # ОБЯЗАТЕЛЬНО задать на проде


# ---------------------- Утилиты ----------------------
def _load_json(path: str, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Ошибка чтения {path}: {e}")
    return default


def _save_json(path: str, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Ошибка записи {path}: {e}")


def load_keys_store() -> Dict[str, List[str]]:
    data = _load_json(KEYS_FILE, {})
    return {
        "trial": data.get("trial", []) or [],
        "month": data.get("month", []) or [],
        "year": data.get("year", []) or [],
        "used": data.get("used", []) or [],
    }


def save_keys_store(store: Dict[str, List[str]]):
    _save_json(KEYS_FILE, store)


def load_subscriptions() -> Dict[str, Dict]:
    return _load_json(SUBS_FILE, {})


def save_subscriptions(subs: Dict[str, Dict]):
    _save_json(SUBS_FILE, subs)


def b64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).rstrip(b"=").decode("ascii")


def b64url_decode_to_str(token: str) -> str:
    pad = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode((token + pad).encode("ascii")).decode("utf-8")


# ---------------------- Нормализация VLESS ----------------------
def normalize_vless_for_v2raytun(vless_key: str) -> str:
    """
    Нормализует VLESS:
    - убирает authority
    - добавляет encryption=none (если отсутствует)
    - чистит fragment от не-алфанумерических символов
    """
    try:
        if not vless_key.startswith("vless://"):
            return vless_key

        m = re.match(r"vless://([^@]+)@([^:]+):(\d+)\?(.+?)(?:#(.*))?$", vless_key)
        if not m:
            return vless_key

        uuid = m.group(1)
        host = m.group(2)
        port = m.group(3)
        params_str = m.group(4)
        fragment = (m.group(5) or "").strip()

        from urllib.parse import parse_qs, unquote
        params = parse_qs(params_str)

        normalized = {}
        for k, values in params.items():
            if k == "authority":
                continue
            normalized[k] = values[0] if values else ""

        if "encryption" not in normalized:
            normalized["encryption"] = "none"

        # Сборка query
        parts = [f"{k}={v}" if v else k for k, v in normalized.items()]
        new_params = "&".join(parts)

        new_key = f"vless://{uuid}@{host}:{port}?{new_params}"

        if fragment:
            frag_decoded = unquote(fragment)
            frag_clean = re.sub(r"[^\w\-]", "", frag_decoded)
            if frag_clean:
                new_key += f"#{frag_clean}"

        return new_key
    except Exception as e:
        logger.warning(f"normalize_vless_for_v2raytun fallback: {e}")
        # Минимальный fallback — убираем authority и дубликаты амперсандов
        key = re.sub(r"[&?]authority=[^&]*(?=&|$)", "", vless_key)
        key = re.sub(r"[?&]&+", "?", key)
        key = re.sub(r"&+", "&", key)
        key = re.sub(r"[?&]$", "", key)
        return key


def _require_auth():
    token = request.headers.get("X-Auth-Token", "")
    if not AUTH_TOKEN or token != AUTH_TOKEN:
        abort(401, description="Unauthorized")


# ---------------------- Админ-API: загрузка ключей ----------------------
@app.route("/admin/keys/upload", methods=["POST"])
def admin_keys_upload():
    """
    Защита: X-Auth-Token: <AUTH_TOKEN>
    Принимает JSON:
    {
      "trial": ["vless://...", ...],
      "month": ["vless://...", ...],
      "year":  ["vless://...", ...]
    }
    Ключи нормализуются, дубликаты и уже использованные отбрасываются.
    """
    _require_auth()

    payload = request.get_json(silent=True) or {}
    incoming = {
        "trial": payload.get("trial", []) or [],
        "month": payload.get("month", []) or [],
        "year": payload.get("year", []) or [],
    }

    store = load_keys_store()
    used = set(store.get("used", []))
    changed = {"trial": 0, "month": 0, "year": 0}

    for t in ("trial", "month", "year"):
        bucket = set(store.get(t, []))
        for raw in incoming[t]:
            if not raw.startswith("vless://"):
                continue
            nk = normalize_vless_for_v2raytun(raw)
            if nk not in bucket and nk not in used:
                bucket.add(nk)
                changed[t] += 1
        store[t] = sorted(bucket)

    save_keys_store(store)
    return jsonify({"success": True, "added": changed, "total": {t: len(store[t]) for t in ("trial", "month", "year")}})


# ---------------------- Админ-API: привязка ключа к пользователю ----------------------
@app.route("/admin/assign", methods=["POST"])
def admin_assign():
    """
    Защита: X-Auth-Token: <AUTH_TOKEN>
    JSON:
    {
      "user_id": 7741189969,
      "type": "trial" | "month" | "year",
      "key": "vless://...",
      "end_date": "2025-12-31T23:59:59"  // опционально
    }
    Создает/обновляет подписку в subscriptions.json и помечает ключ как использованный.
    """
    _require_auth()

    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    sub_type = (data.get("type") or "").strip()
    key = (data.get("key") or "").strip()
    end_date = (data.get("end_date") or "").strip()

    if not user_id or sub_type not in ("trial", "month", "year") or not key.startswith("vless://"):
        return jsonify({"success": False, "error": "user_id/type/key required"}), 400

    key = normalize_vless_for_v2raytun(key)

    # Обновляем подписку
    subs = load_subscriptions()
    subs[str(user_id)] = {
        "type": sub_type,
        "key": key,
        "end_date": end_date,           # если пусто — считаем бессрочной
        "active": True,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    save_subscriptions(subs)

    # Переносим ключ в used
    store = load_keys_store()
    for t in ("trial", "month", "year"):
        if key in store.get(t, []):
            store[t].remove(key)
    used = set(store.get("used", []))
    used.add(key)
    store["used"] = sorted(used)
    save_keys_store(store)

    return jsonify({"success": True})


# ---------------------- Публичный /sub: выдача RAW VLESS по токену ----------------------
def _parse_sub_token(token: str) -> Tuple[str, str] | None:
    """
    token = base64url("<user_id>_<type>"), без '='.
    Вернёт (user_id_str, sub_type) либо None.
    """
    try:
        decoded = b64url_decode_to_str(token)
        parts = decoded.split("_", 1)
        if len(parts) != 2:
            return None
        user_id_str, sub_type = parts[0].strip(), parts[1].strip()
        return user_id_str, sub_type
    except Exception:
        return None


@app.route("/sub/<token>", methods=["GET"])
def get_subscription(token: str):
    """
    Возвращает "сырой" VLESS (text/plain; inline; no-store) для пользователя.
    Требует token = base64url("<uid>_<type>"), где type ∈ {trial, month, year}.
    """
    try:
        parsed = _parse_sub_token(token)
        if not parsed:
            return Response("Bad token", status=400, mimetype="text/plain")
        user_id_str, sub_type = parsed

        subs = load_subscriptions()
        sub = subs.get(user_id_str)
        if not sub or not sub.get("active"):
            return Response("Subscription inactive", status=403, mimetype="text/plain")

        # Проверяем тип
        if (sub.get("type") or "").strip() != sub_type:
            return Response("Wrong subscription type", status=400, mimetype="text/plain")

        # Проверяем срок (если задан)
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

        # Нормализуем для максимальной совместимости
        key = normalize_vless_for_v2raytun(key)

        # Отдаём RAW VLESS
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
            }
        )
    except Exception as e:
        logger.error(f"/sub error: {e}")
        return Response("Internal server error", status=500, mimetype="text/plain")


# ---------------------- Health ----------------------
@app.route("/health")
def health():
    return Response("OK", status=200, mimetype="text/plain")


# ---------------------- Запуск локально ----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    logger.info(f"DATA_DIR: {DATA_DIR}")
    logger.info(f"Keys file: {KEYS_FILE}")
    logger.info(f"Subs file: {SUBS_FILE}")
    app.run(host="0.0.0.0", port=port, debug=False)
