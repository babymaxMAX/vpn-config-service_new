#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subscription сервер для авто-подключения V2Ray (совместим с V2RayTun).

Ключевые особенности исправленной версии:
- .sub возвращает СЫРОЙ vless (text/plain), без редиректов и без base64 — важно для iOS V2RayTun.
- ?b64=1 остаётся как опция для клиентов, ожидающих base64.
- Поддержка двух типов токенов: legacy (base64url("<uid>_<type>")) и HMAC-SHA256 (короткоживущий).
- Эндпоинты /open и /go для надёжного открытия deeplink из Telegram/WebView.
- Совместимость с локальным форматом бота (subscriptions.json, key_data.json, optional KeyManager).

Эндпоинты:
- POST /admin/keys/upload        (X-Auth-Token)
- POST /admin/assign             (X-Auth-Token)
- GET  /sub/<token>              — RAW vless или base64 (по ?b64)
- GET  /sub/<token>.sub          — СЫРОЙ vless (без редиректа и без base64)
- GET  /open?url=...             — HTTPS-мост для v2raytun://
- GET  /go/<token>               — HTML-страница с вариантами deeplink
- GET  /health
"""

from __future__ import annotations

from flask import Flask, Response, request, jsonify
import json
import logging
import base64
import hmac
import hashlib
import os
import time
import re
import urllib.parse

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Секрет для HMAC и админ-операций
_SIGN_SECRET = os.environ.get('AUTH_TOKEN', '') or 'dev-secret'

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.environ.get('DATA_DIR', '').strip() or os.path.join(_PROJECT_ROOT, 'data')
try:
    os.makedirs(_DATA_DIR, exist_ok=True)
except Exception:
    pass

_SUBS_JSON_PATH = os.environ.get('SUBS_JSON_PATH', '').strip() or os.path.join(_PROJECT_ROOT, 'subscriptions.json')
_SUBS_JSON_FALLBACK = os.path.join(_DATA_DIR, 'subscriptions.json')


# =============== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===============

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(data: str) -> bytes:
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _sign_dict(payload: dict, ttl_seconds: int) -> str:
    body = dict(payload)
    body['exp'] = int(time.time()) + int(ttl_seconds)
    body_json = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    sig = hmac.new(_SIGN_SECRET.encode('utf-8'), body_json, hashlib.sha256).digest()
    return _b64url_encode(body_json) + '.' + _b64url_encode(sig)


def _verify_token(token: str) -> dict:
    if '.' not in token:
        raise ValueError('bad_format')
    b64_body, b64_sig = token.split('.', 1)
    body = _b64url_decode(b64_body)
    sig = _b64url_decode(b64_sig)
    try:
        payload = json.loads(body.decode('utf-8'))
    except Exception:
        raise ValueError('bad_body')
    exp = int(payload.get('exp', 0) or 0)
    if exp < int(time.time()):
        raise ValueError('expired')
    calc = hmac.new(_SIGN_SECRET.encode('utf-8'), body, hashlib.sha256).digest()
    if not hmac.compare_digest(calc, sig):
        raise ValueError('bad_signature')
    return payload


def _parse_legacy_token(token: str) -> dict:
    """base64url('<uid>_<type>') → {'uid': int, 't': str}"""
    pad = '=' * (-len(token) % 4)
    raw = base64.urlsafe_b64decode((token + pad).encode('ascii')).decode('utf-8')
    if '_' in raw:
        uid_str, tariff = raw.split('_', 1)
    elif '-' in raw:
        uid_str, tariff = raw.split('-', 1)
    else:
        raise ValueError('bad_legacy_format')
    return {'uid': int(uid_str), 't': str(tariff).strip()}


def _load_json_safe(path: str, default):
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return default


def _load_subscriptions_compat() -> dict:
    data = _load_json_safe(_SUBS_JSON_PATH, default=None)
    if isinstance(data, dict):
        if 'subscriptions' in data and isinstance(data['subscriptions'], dict):
            return data['subscriptions'] or {}
        return data or {}
    data = _load_json_safe(_SUBS_JSON_FALLBACK, default={})
    if isinstance(data, dict) and 'subscriptions' in data and isinstance(data['subscriptions'], dict):
        return data['subscriptions'] or {}
    return data or {}


def init_key_manager():
    """Мягкая инициализация KeyManager, если есть в проекте."""
    global key_manager
    try:
        from key_manager import KeyManager
        import config
        key_manager = KeyManager(config.KEYS_FOLDERS)
        logger.info("Key manager initialized")
    except Exception as e:
        key_manager = None
        logger.info(f"KeyManager not available: {e}")


def _load_used_keys_state() -> dict:
    try:
        p = os.path.join(_PROJECT_ROOT, 'used_keys.json')
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f) or {}
    except Exception:
        pass
    return {}


def _get_user_subscription_from_files(user_id: int) -> dict | None:
    data = _load_used_keys_state()
    subs = data.get('user_subscriptions', {}) or {}
    return subs.get(str(user_id)) or subs.get(user_id)


def normalize_vless_for_v2raytun(vless_key: str) -> str:
    try:
        if not vless_key.startswith('vless://'):
            return vless_key
        # vless://uuid@host:port?params#fragment
        match = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?(.+?)(?:#(.*))?$', vless_key)
        if not match:
            return vless_key
        uuid = match.group(1)
        host = match.group(2)
        port = match.group(3)
        params_str = match.group(4)
        fragment = match.group(5) or ''

        params = urllib.parse.parse_qs(params_str)
        normalized_params = {}
        for key, values in params.items():
            if key == 'authority':
                continue
            normalized_params[key] = values[0] if values else ''
        if 'encryption' not in normalized_params:
            normalized_params['encryption'] = 'none'

        pairs = []
        for k, v in normalized_params.items():
            if v:
                pairs.append(f"{k}={v}")
            else:
                pairs.append(k)
        params_string = '&'.join(pairs)

        out = f"vless://{uuid}@{host}:{port}?{params_string}"
        if fragment:
            clean_fragment = re.sub(r'[^\w\-]', '', fragment)
            if clean_fragment:
                out += f"#{clean_fragment}"
        return out
    except Exception:
        key = re.sub(r'[&?]authority=(?=&|$)', '', vless_key)
        key = re.sub(r'[&?]authority=[^&]*(?=&|$)', '', key)
        key = re.sub(r'[?&]&+', '?', key)
        key = re.sub(r'&+', '&', key)
        key = re.sub(r'[?&]$', '', key)
        return key


# =============== АДМИН ЭНДПОИНТЫ ===============

@app.route('/admin/keys/upload', methods=['POST'])
def admin_upload_keys():
    auth = request.headers.get('X-Auth-Token', '')
    if not _SIGN_SECRET or auth != _SIGN_SECRET:
        return Response('Unauthorized', status=401, mimetype='text/plain')

    data = request.get_json(silent=True) or {}
    added_total = 0
    totals = {}

    def append_unique(path: str, new_items: list[str]) -> int:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        existing = []
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                existing = [line.strip() for line in f if line.strip()]
        existing_set = set(existing)
        to_add = [x.strip() for x in new_items if x and x.strip() and x.strip().startswith('vless://') and x.strip() not in existing_set]
        if not to_add:
            return 0
        with open(path, 'a', encoding='utf-8') as f:
            for item in to_add:
                f.write(item + '\n')
        return len(to_add)

    mapping = {
        'trial': os.path.join(_PROJECT_ROOT, 'keys', 'trial_keys.txt'),
        'month': os.path.join(_PROJECT_ROOT, 'keys', 'month_keys.txt'),
        'year':  os.path.join(_PROJECT_ROOT, 'keys', 'year_keys.txt'),
    }

    for k in ('trial', 'month', 'year'):
        count = append_unique(mapping[k], data.get(k, []) or [])
        added_total += count
        try:
            with open(mapping[k], 'r', encoding='utf-8') as f:
                totals[k] = sum(1 for _ in f)
        except Exception:
            totals[k] = 0

    return Response(json.dumps({'added': added_total, 'total': totals}, ensure_ascii=False), status=200, mimetype='application/json')


@app.route('/admin/assign', methods=['POST'])
def admin_assign():
    auth = request.headers.get('X-Auth-Token', '')
    if not _SIGN_SECRET or auth != _SIGN_SECRET:
        return Response('Unauthorized', status=401, mimetype='text/plain')

    data = request.get_json(silent=True) or {}
    try:
        user_id = int(data.get('user_id'))
    except Exception:
        return Response('Bad user_id', status=400, mimetype='text/plain')

    sub_type = (data.get('type') or 'trial').strip()
    key = (data.get('key') or '').strip()
    end_date = (data.get('end_date') or '').strip()
    if sub_type not in ('trial', 'month', 'year') or not key.startswith('vless://'):
        return Response('Bad request', status=400, mimetype='text/plain')

    key = normalize_vless_for_v2raytun(key)

    # Синхронизация с key_data.json при наличии
    try:
        kd_path = os.path.join(_PROJECT_ROOT, 'key_data.json')
        kd = {}
        if os.path.exists(kd_path):
            with open(kd_path, 'r', encoding='utf-8') as f:
                kd = json.load(f) or {}
        used_keys = set(kd.get('used_keys', []))
        key_assignments = kd.get('key_assignments', {})
        used_keys.add(key)
        key_assignments[key] = int(user_id)
        with open(kd_path, 'w', encoding='utf-8') as f:
            json.dump({'used_keys': list(used_keys), 'key_assignments': key_assignments}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # Обновляем subscriptions.json (совместимый формат)
    try:
        subs_root = _load_json_safe(_SUBS_JSON_PATH, {}) or {}
        if 'subscriptions' in subs_root and isinstance(subs_root['subscriptions'], dict):
            subs = subs_root['subscriptions']
        elif subs_root and isinstance(subs_root, dict):
            subs = subs_root
        else:
            subs_root = {}
            subs = subs_root

        from datetime import datetime, timedelta
        start_iso = datetime.utcnow().isoformat()
        if not end_date:
            end_iso = (datetime.utcnow() + timedelta(days=30)).isoformat()
        else:
            end_iso = end_date

        subs[str(user_id)] = {
            'type': sub_type,
            'key': key,
            'end_date': end_iso,
            'days': 0,
            'active': True,
            'updated_at': start_iso
        }

        if subs is not subs_root:
            subs_root['subscriptions'] = subs
        with open(_SUBS_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(subs_root, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    return Response('OK', status=200, mimetype='text/plain')


# =============== ОТДАЧА ПОДПИСКИ ===============

key_manager = None


def _resolve_user_key(user_id: int) -> tuple[str | None, dict | None]:
    """Возвращает (vless_key, user_sub_record)."""
    global key_manager
    if key_manager is None:
        init_key_manager()

    # 1) KeyManager
    if key_manager is not None:
        try:
            k = key_manager.get_user_key(user_id)
            if k:
                return k, _get_user_subscription_from_files(user_id)
        except Exception:
            pass

    # 2) key_data.json
    try:
        kd_path = os.path.join(_PROJECT_ROOT, 'key_data.json')
        if os.path.exists(kd_path):
            with open(kd_path, 'r', encoding='utf-8') as f:
                kd = json.load(f)
            key_assignments = kd.get('key_assignments', {})
            for k, uid in key_assignments.items():
                try:
                    if int(uid) == int(user_id):
                        return k, _get_user_subscription_from_files(user_id)
                except Exception:
                    continue
    except Exception:
        pass

    # 3) subscriptions.json
    subs_map = _load_subscriptions_compat()
    rec = subs_map.get(str(user_id)) or subs_map.get(user_id)
    if isinstance(rec, dict):
        k = str(rec.get('key') or '').strip()
        if k.startswith('vless://'):
            return k, rec
    return None, rec


def _is_active_subscription(rec: dict | None) -> bool:
    if not isinstance(rec, dict):
        return False
    try:
        from datetime import datetime, timezone
        end_iso = str(rec.get('end_date') or '').replace('Z', '+00:00')
        active = bool(rec.get('active', True))
        if end_iso:
            end_dt = datetime.fromisoformat(end_iso)
            return active and (datetime.now(tz=end_dt.tzinfo or timezone.utc) <= end_dt)
        return active
    except Exception:
        return bool(rec)


def _extract_payload(token: str) -> dict:
    try:
        return _verify_token(token)
    except Exception:
        return _parse_legacy_token(token)


def _build_body_for_client(user_key: str, b64: bool) -> str:
    norm = normalize_vless_for_v2raytun(user_key)
    if b64:
        try:
            return base64.b64encode(norm.encode('utf-8')).decode('ascii')
        except Exception:
            return norm
    return norm


@app.route('/sub/<token>')
def get_subscription(token: str):
    """
    Возвращает RAW vless для <token>.
    Поддерживает HMAC и legacy. ?b64=1 — вернёт base64.
    """
    try:
        payload = _extract_payload(token)
        user_id = int(payload.get('uid'))
        tariff = str(payload.get('t') or '')
    except Exception:
        return Response('Bad or expired token', status=400, mimetype='text/plain')

    user_key, rec = _resolve_user_key(user_id)
    if not user_key:
        return Response('Key not found', status=404, mimetype='text/plain')

    if not _is_active_subscription(rec):
        return Response('Subscription inactive', status=403, mimetype='text/plain')

    if tariff and isinstance(rec, dict) and str(rec.get('type') or '') != tariff:
        return Response('Subscription type mismatch', status=403, mimetype='text/plain')

    want_b64 = str(request.args.get('b64') or '').lower() in ('1', 'true', 'yes', 'b64')
    body_text = _build_body_for_client(user_key, want_b64)

    headers = {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': f'inline; filename="{user_id}_{tariff or "vpn"}.sub"',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
        'subscription-userinfo': 'upload=0; download=0; total=0; expire=0'
    }
    return Response(body_text, status=200, mimetype='text/plain', headers=headers)


@app.route('/sub/<token>.sub')
def get_subscription_file(token: str):
    """
    ВАЖНО: .sub отдаёт СЫРОЙ vless текст без редиректов и без base64 —
    это требование клиентов на iOS (V2RayTun), которые не следуют 302 и не принимают base64.
    """
    try:
        payload = _extract_payload(token)
        user_id = int(payload.get('uid'))
        # тип тарифа на .sub не проверяем строго, чтобы не ломать импорт
    except Exception:
        return Response('Bad or expired token', status=400, mimetype='text/plain')

    user_key, rec = _resolve_user_key(user_id)
    if not user_key:
        return Response('Key not found', status=404, mimetype='text/plain')
    if not _is_active_subscription(rec):
        return Response('Subscription inactive', status=403, mimetype='text/plain')

    body_text = _build_body_for_client(user_key, b64=False)  # СЫРОЙ vless
    headers = {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': f'inline; filename="{user_id}.sub"',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*'
    }
    return Response(body_text, status=200, mimetype='text/plain', headers=headers)


# =============== УТИЛИТЫ: /open и /go ===============

@app.route('/open')
def open_scheme():
    try:
        raw = (request.args.get('url') or '').strip()
        if not raw:
            return Response('Missing url', status=400, mimetype='text/plain')
        try:
            decoded = urllib.parse.unquote(raw)
        except Exception:
            decoded = raw
        if not decoded.lower().startswith('v2raytun://'):
            return Response('Unsupported scheme', status=400, mimetype='text/plain')

        safe_href = json.dumps(decoded)
        html = ("<!DOCTYPE html>"
                "<html lang=\"ru\"><head>"
                "<meta charset=\"UTF-8\"/>"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
                "<title>Открытие V2RayTun</title>"
                "<script>"
                "  (function(){"
                "    var t=" + safe_href + ";"
                "    try{ window.location.replace(t); }catch(e){ window.location.href=t; }"
                "    setTimeout(function(){ document.getElementById('fallback').style.display='block'; }, 900);"
                "  })();"
                "</script>"
                "<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial;max-width:760px;margin:24px auto;padding:0 16px}a.btn{display:inline-block;background:#111827;color:#fff;text-decoration:none;border-radius:8px;padding:10px 14px}</style>"
                "</head><body>"
                "  <h3>Открываем V2RayTun…</h3>"
                "  <div id=\"fallback\" style=\"display:none\">Если приложение не открылось автоматически, нажмите кнопку:</div>"
                "  <p><a class=\"btn\" href=\"" + decoded + "\">Открыть приложение</a></p>"
                "</body></html>")
        return Response(html, status=200, mimetype='text/html')
    except Exception as e:
        logger.error(f"/open error: {e}")
        return Response('Internal error', status=500, mimetype='text/plain')


@app.route('/go/<token>')
def go_launcher(token: str):
    try:
        payload = _verify_token(token)
        user_id = int(payload.get('uid'))
        tariff = str(payload.get('t') or '')
    except Exception as e:
        logger.error(f"/go error (token): {e}")
        return Response('Bad or expired token', status=400, mimetype='text/plain')

    try:
        # генерируем свежий HMAC для подписки (коротко живёт, но годится для редиректов)
        signed_id = _sign_dict({'uid': user_id, 't': tariff}, ttl_seconds=300)
        base = request.url_root.rstrip('/')
        sub_url = f"{base}/sub/{signed_id}"
        sub_b64_url = f"{sub_url}?b64=1"
        sub_sub_url = f"{sub_url}.sub"  # сырой текст
        enc = urllib.parse.quote

        candidates = [
            f"v2raytun://import-config?url={enc(sub_sub_url, safe='')}",  # .sub сырой
            f"v2raytun://import?url={enc(sub_b64_url, safe='')}&autostart=1",
            f"v2raytun://subscribe?url={enc(sub_url, safe='')}",
        ]

        open_bridge = f"{base}/open?url={urllib.parse.quote(candidates[0], safe='')}"
        html = f"""<!doctype html>
<html lang="ru">
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Открываем V2RayTun…</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; max-width: 640px; margin: 40px auto; padding: 0 16px; }}
    .btn {{ display: inline-block; padding: 12px 16px; border-radius: 12px; border: 1px solid #ddd; text-decoration: none; color: #111; }}
    .row {{ margin-top: 14px; }}
    .muted {{ color: #666; }}
  </style>
  <body>
    <h2>Открываем V2RayTun…</h2>
    <p class="muted">Если приложение не открылось автоматически, используйте кнопки ниже.</p>
    <div class="row"><a class="btn" href="{open_bridge}">Через HTTPS‑мост (.sub)</a></div>
    <div class="row"><a class="btn" href="{candidates[0]}">Открыть (.sub)</a></div>
    <div class="row"><a class="btn" href="{candidates[1]}">Открыть (import b64)</a></div>
    <div class="row"><a class="btn" href="{candidates[2]}">Открыть (subscribe)</a></div>
    <script>
      const links = {json.dumps(candidates)};
      let idx = 0;
      function openNext() {{
        if (idx >= links.length) return;
        try {{ window.location.href = links[idx++]; }} catch(e) {{}}
        setTimeout(openNext, 900);
      }}
      setTimeout(openNext, 150);
    </script>
  </body>
</html>"""
        return Response(html, status=200, mimetype='text/html')
    except Exception as e:
        logger.error(f"/go error: {e}")
        return Response('Internal error', status=500, mimetype='text/plain')


@app.route('/health')
def health_check():
    return Response('OK', status=200, mimetype='text/plain')


@app.route('/')
def index():
    return (
        "<h1>LsJ VPN Subscription Server</h1>"
        "<p>Сервер для автоимпорта V2Ray (V2RayTun).</p>"
        "<p>Используйте: /sub/&lt;token&gt; или /sub/&lt;token&gt;.sub</p>"
    )


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
