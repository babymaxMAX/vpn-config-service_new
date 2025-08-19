#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subscription сервер для автоматического подключения V2Ray
Возвращает .sub файлы с vless ключами для deeplink подключения
"""

from flask import Flask, Response, request
import re
import urllib.parse
import json
import logging
import base64
import hmac
import hashlib
import time
import os
import sys
from datetime import datetime, timedelta

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Для локальной разработки (модуль может отсутствовать на сервере)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Опциональный key_manager (если есть)
key_manager = None

# Секрет для подписи и админ-роутов
_SIGN_SECRET = os.environ.get('AUTH_TOKEN', '') or 'dev-secret'


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
        exp = int(payload.get('exp', 0))
    except Exception:
        raise ValueError('bad_body')
    if exp < int(time.time()):
        raise ValueError('expired')
    calc = hmac.new(_SIGN_SECRET.encode('utf-8'), body, hashlib.sha256).digest()
    if not hmac.compare_digest(calc, sig):
        raise ValueError('bad_signature')
    return payload


def init_key_manager():
    """Инициализация key_manager (мягкая). Если модуль отсутствует — используем файловый фолбэк."""
    global key_manager
    try:
        from key_manager import KeyManager
        import config
        key_manager = KeyManager(config.KEYS_FOLDERS)
        logger.info("Key manager инициализирован успешно")
    except Exception as e:
        key_manager = None
        logger.warning(f"KeyManager недоступен, используем файловый фолбэк: {e}")


def _path(*parts) -> str:
    return os.path.join(os.path.dirname(__file__), *parts)


def _read_json(path: str, default):
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f) or default
    except Exception:
        pass
    return default


def _write_json(path: str, data) -> None:
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _load_used_keys_state() -> dict:
    return _read_json(_path('used_keys.json'), {})


def _get_user_subscription_from_files(user_id: int) -> dict | None:
    data = _load_used_keys_state()
    subs = data.get('user_subscriptions', {}) or {}
    return subs.get(str(user_id)) or subs.get(user_id)


def _keys_file_for_type(t: str) -> str:
    t = (t or '').lower()
    mapping = {'trial': 'trial_keys.txt', 'month': 'month_keys.txt', 'year': 'year_keys.txt'}
    return _path('keys', mapping.get(t, 'trial_keys.txt'))


def _read_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        return [ln.strip() for ln in f if ln.strip()]


def _auto_assign_key(user_id: int, sub_type: str) -> str | None:
    """
    Автоматически выдаёт первый свободный ключ из файла тарифа,
    помечает использованным и создаёт активную подписку.
    """
    uk = _load_used_keys_state()
    used = set(uk.get('used_keys', []))
    keys_path = _keys_file_for_type(sub_type)

    for key in _read_lines(keys_path):
        if key and key.startswith('vless://') and key not in used:
            used.add(key)
            uk['used_keys'] = list(used)

            subs = uk.get('user_subscriptions', {}) or {}
            days_map = {'trial': 13, 'month': 30, 'year': 365}
            days = days_map.get((sub_type or 'trial').lower(), 13)
            start_iso = datetime.utcnow().isoformat()
            end_iso = (datetime.utcnow() + timedelta(days=days)).isoformat()
            subs[str(user_id)] = {
                'type': sub_type or 'trial',
                'start_date': start_iso,
                'end_date': end_iso,
                'days': days,
                'active': True,
                'current_key': key
            }
            uk['user_subscriptions'] = subs

            hist = uk.get('user_key_history', {}) or {}
            h = hist.get(str(user_id), [])
            h.append({'key': key, 'type': sub_type or 'trial', 'issued_date': start_iso, 'active': True})
            hist[str(user_id)] = h
            uk['user_key_history'] = hist
            _write_json(_path('used_keys.json'), uk)

            kd = _read_json(_path('key_data.json'), {})
            kd_used = set(kd.get('used_keys', [])); kd_used.add(key)
            kd_assign = kd.get('key_assignments', {}) or {}; kd_assign[key] = int(user_id)
            _write_json(_path('key_data.json'), {'used_keys': list(kd_used), 'key_assignments': kd_assign})

            logger.info(f"Автовыдача ключа '{sub_type}' пользователю {user_id}")
            return key

    return None


def normalize_vless_for_v2raytun(vless_key: str) -> str:
    """
    Нормализует VLESS ключ (убирает authority, чистит fragment).
    """
    try:
        if not vless_key.startswith('vless://'):
            return vless_key

        m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?(.+?)(?:#(.*))?$', vless_key)
        if not m:
            return vless_key

        uuid = m.group(1)
        host = m.group(2)
        port = m.group(3)
        params_str = m.group(4)
        fragment = m.group(5) or ''

        params = urllib.parse.parse_qs(params_str)
        normalized = {}
        for k, v in params.items():
            if k == 'authority':
                continue
            normalized[k] = v[0] if v else ''

        parts = [f"{k}={v}" if v else k for k, v in normalized.items()]
        result = f"vless://{uuid}@{host}:{port}?{'&'.join(parts)}"
        if fragment:
            clean = re.sub(r'[^\w\-]', '', fragment)
            if clean:
                result += f"#{clean}"
        return result
    except Exception:
        fallback = re.sub(r'[&?]authority=[^&]*(?=&|$)', '', vless_key)
        fallback = re.sub(r'[?&]&+', '?', fallback)
        fallback = re.sub(r'&+', '&', fallback)
        fallback = re.sub(r'[?&]$', '', fallback)
        return fallback


@app.route('/admin/assign', methods=['POST'])
def admin_assign():
    try:
        if request.headers.get('X-Auth-Token', '') != _SIGN_SECRET:
            return Response('Unauthorized', 401)

        d = request.get_json(silent=True) or {}
        user_id = int(d.get('user_id'))
        sub_type = (d.get('type') or 'trial').strip()
        key = (d.get('key') or '').strip()
        end_date = (d.get('end_date') or '').strip()
        if not user_id or not key or not key.startswith('vless://'):
            return Response('Bad request', 400)

        kd = _read_json(_path('key_data.json'), {})
        kd_used = set(kd.get('used_keys', [])); kd_used.add(key)
        kd_ass = kd.get('key_assignments', {}) or {}; kd_ass[key] = user_id
        _write_json(_path('key_data.json'), {'used_keys': list(kd_used), 'key_assignments': kd_ass})

        uk = _read_json(_path('used_keys.json'), {})
        used = set(uk.get('used_keys', [])); used.add(key); uk['used_keys'] = list(used)
        subs = uk.get('user_subscriptions', {}) or {}
        start_iso = datetime.utcnow().isoformat()
        if not end_date:
            end_iso = (datetime.utcnow() + timedelta(days={'trial': 13, 'month': 30, 'year': 365}.get(sub_type, 30))).isoformat()
        else:
            end_iso = end_date
        subs[str(user_id)] = {'type': sub_type, 'start_date': start_iso, 'end_date': end_iso, 'days': 0, 'active': True, 'current_key': key}
        hist = uk.get('user_key_history', {}) or {}
        h = hist.get(str(user_id), []); h.append({'key': key, 'type': sub_type, 'issued_date': start_iso, 'active': True})
        hist[str(user_id)] = h
        uk['user_subscriptions'] = subs; uk['user_key_history'] = hist
        _write_json(_path('used_keys.json'), uk)

        return Response('OK', 200)
    except Exception as e:
        logger.error(f"/admin/assign error: {e}")
        return Response('Internal error', 500)


@app.route('/admin/keys/upload', methods=['POST'])
def admin_upload_keys():
    try:
        if request.headers.get('X-Auth-Token', '') != _SIGN_SECRET:
            return Response('Unauthorized', 401)

        data = request.get_json(silent=True) or {}
        added_total, totals = 0, {}

        def append_unique(path: str, new_items: list[str]) -> int:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            existing = _read_lines(path); s = set(existing)
            to_add = [x.strip() for x in (new_items or []) if x and x.strip().startswith('vless://') and x.strip() not in s]
            if to_add:
                with open(path, 'a', encoding='utf-8') as f:
                    for item in to_add:
                        f.write(item + '\n')
            return len(to_add)

        mapping = {'trial': _keys_file_for_type('trial'), 'month': _keys_file_for_type('month'), 'year': _keys_file_for_type('year')}
        for k in ('trial', 'month', 'year'):
            added_total += append_unique(mapping[k], data.get(k, []))
            try:
                with open(mapping[k], 'r', encoding='utf-8') as f:
                    totals[k] = sum(1 for _ in f)
            except Exception:
                totals[k] = 0

        return Response(json.dumps({'added': added_total, 'total': totals}), 200, mimetype='application/json')
    except Exception as e:
        logger.error(f"Ошибка /admin/keys/upload: {e}")
        return Response('Internal error', 500)


@app.route('/sub/<signed_id>')
def get_subscription(signed_id):
    if key_manager is None:
        init_key_manager()
    try:
        payload = _verify_token(signed_id)
        user_id = int(payload.get('uid'))
        subscription_type = str(payload.get('t') or '')
        logger.info(f"Запрос подписки для пользователя {user_id}, тип: {subscription_type}")

        # Привязанный ключ
        user_key = None
        if key_manager is not None:
            try:
                user_key = key_manager.get_user_key(user_id)
            except Exception:
                user_key = None

        if not user_key:
            kd = _read_json(_path('key_data.json'), {})
            for k, uid in (kd.get('key_assignments', {}) or {}).items():
                try:
                    if int(uid) == user_id:
                        user_key = k
                        break
                except Exception:
                    pass

        # Автовыдача при отсутствии привязки
        if not user_key:
            user_key = _auto_assign_key(user_id, subscription_type)

        if not user_key:
            logger.error(f"Ключ не найден для пользователя {user_id}")
            return Response("Key not found", 404)

        # Проверяем активность и соответствие тарифу
        user_sub, is_active = None, False
        if key_manager is not None:
            try:
                user_sub = key_manager.get_user_subscription(user_id)
                is_active = bool(key_manager.is_subscription_active(user_id))
            except Exception:
                user_sub, is_active = None, False
        if user_sub is None:
            user_sub = _get_user_subscription_from_files(user_id)
            try:
                if user_sub and user_sub.get('end_date'):
                    end_dt = datetime.fromisoformat(user_sub['end_date'])
                    is_active = datetime.utcnow() < end_dt and bool(user_sub.get('active', True))
            except Exception:
                is_active = bool(user_sub)

        if not user_sub or not is_active:
            return Response("Subscription inactive", 403)
        current_type = str((user_sub or {}).get('type') or '')
        if subscription_type and current_type and current_type != subscription_type:
            return Response("Subscription type mismatch", 403)

        normalized_key = normalize_vless_for_v2raytun(user_key)

        # Поддержка base64-режима: /sub/<token>?b64=1
        want_b64 = str(request.args.get('b64') or '').lower() in ('1', 'true', 'yes', 'b64')
        body_text = base64.b64encode(normalized_key.encode()).decode('ascii') if want_b64 else normalized_key

        safe_name = f"{user_id}_{subscription_type or 'vpn'}.sub"
        resp = Response(
            body_text, 200, mimetype='text/plain',
            headers={
                'Content-Type': 'text/plain; charset=utf-8',
                'Content-Disposition': f'inline; filename="{safe_name}"',
                'Cache-Control': 'no-store',
                'Access-Control-Allow-Origin': '*',
                'subscription-userinfo': 'upload=0; download=0; total=0; expire=0'
            }
        )
        return resp
    except Exception as e:
        logger.error(f"/sub error: {e}")
        return Response("Internal server error", 500)


@app.route('/open')
def open_scheme():
    """
    HTTPS‑мост для custom-схем (v2raytun://), безопасен для Telegram WebView.
    Использование: /open?url=<urlencoded_v2raytun_scheme>
    """
    try:
        raw = (request.args.get('url') or '').strip()
        if not raw:
            return Response("Missing url", 400)
        import urllib.parse as _up
        decoded = raw
        try:
            decoded = _up.unquote(raw)
        except Exception:
            pass
        if not decoded.lower().startswith('v2raytun://'):
            return Response("Unsupported scheme", 400)

        safe_href = json.dumps(decoded)
        html = f"""<!doctype html><html lang="ru"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Открытие V2RayTun</title>
<script>
  (function(){{
    var t={safe_href};
    try{{ window.location.replace(t); }}catch(e){{ window.location.href=t; }}
    setTimeout(function(){{ document.getElementById('fallback').style.display='block'; }}, 800);
  }})();
</script>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial;max-width:760px;margin:24px auto;padding:0 16px}}a.btn{{display:inline-block;background:#111827;color:#fff;text-decoration:none;border-radius:8px;padding:10px 14px}}</style>
</head><body>
  <h3>Открываем V2RayTun…</h3>
  <div id="fallback" style="display:none">Если не открылось автоматически, нажмите кнопку:</div>
  <p><a class="btn" href="{decoded}">Открыть приложение</a></p>
</body></html>"""
        return Response(html, 200, mimetype='text/html')
    except Exception as e:
        logger.error(f"Ошибка в /open: {e}")
        return Response("Internal error", 500)


@app.route('/admin/go', methods=['GET'])
def admin_generate_go():
    """Генерация ссылки /go для диагностики на стороне сервера."""
    try:
        if request.headers.get('X-Auth-Token', '') != _SIGN_SECRET:
            return Response('Unauthorized', 401)
        user_id = int(request.args.get('uid') or '0')
        tariff = (request.args.get('t') or 'trial').strip()
        ttl = int(request.args.get('ttl') or '600')
        if not user_id:
            return Response('Bad request', 400)
        token = _sign_dict({'uid': user_id, 't': tariff}, ttl)
        base = request.url_root.rstrip('/')
        url = f"{base}/go/{token}"
        return Response(json.dumps({'url': url, 'token': token}, ensure_ascii=False), 200, mimetype='application/json')
    except Exception as e:
        logger.error(f"/admin/go error: {e}")
        return Response('Internal error', 500)


@app.route('/go/<token>')
def go_launcher(token: str):
    """
    HTML‑лаунчер (200 OK) c вариантами deeplink, безопасный для Telegram WebView.
    """
    try:
        payload = _verify_token(token)
        user_id = int(payload.get('uid'))
        tariff = str(payload.get('t') or '')

        # Подписываем короткий id для /sub (5 минут)
        signed_id = _sign_dict({'uid': user_id, 't': tariff}, 300)

        base = request.url_root.rstrip('/')
        sub_url = f"{base}/sub/{signed_id}"
        enc_sub_url = urllib.parse.quote(sub_url, safe='')
        sub_b64_url = f"{sub_url}?b64=1"
        enc_sub_b64_url = urllib.parse.quote(sub_b64_url, safe='')

        # Пытаемся подготовить add?config= (RAW vless)
        add_config = ''
        try:
            raw_resp = app.test_client().get(f"/sub/{signed_id}")
            if raw_resp.status_code == 200:
                vless_raw = raw_resp.get_data(as_text=True)
                if isinstance(vless_raw, str) and vless_raw.strip().startswith('vless://'):
                    add_config = f"v2raytun://add?config={urllib.parse.quote(vless_raw.strip(), safe='')}"
        except Exception:
            add_config = ''

        candidates = [
            f"v2raytun://import?url={enc_sub_url}&autostart=1",
            f"v2raytun://import?url={enc_sub_b64_url}&autostart=1",
            f"v2raytun://import-config?url={enc_sub_url}",
            f"v2raytun://import-config?url={enc_sub_b64_url}",
            f"v2raytun://subscribe?url={enc_sub_url}",
            f"v2raytun://subscribe?url={enc_sub_b64_url}",
            f"v2raytun://add?url={enc_sub_url}",
        ]
        if add_config:
            candidates.append(add_config)
        candidates.append(f"intent://import?url={enc_sub_url}#Intent;scheme=v2raytun;package=com.v2raytun.android;end")

        open_bridge_import = f"{base}/open?url={urllib.parse.quote(candidates[0], safe='')}"
        open_bridge_add = (f"{base}/open?url={urllib.parse.quote(add_config, safe='')}" if add_config else '')

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
    <div class="row"><a id="retry" class="btn" href="#">Открыть снова</a></div>
    <div class="row"><a id="sys" class="btn" href="{candidates[-1]}">Открыть через систему (Android)</a></div>
    <div class="row"><a class="btn" href="{open_bridge_import}">Через HTTPS‑мост (import)</a></div>
    <div class="row"><a class="btn" href="https://deeplink.website/?url={urllib.parse.quote(candidates[0], safe='')}">Через deeplink.website (import)</a></div>
    <div class="row"><a class="btn" href="https://deeplink.website/?url={urllib.parse.quote(candidates[1], safe='')}">Через deeplink.website (import-config)</a></div>
    {('<div class="row"><a class="btn" href="'+open_bridge_add+'">Через HTTPS‑мост (add?config)</a></div>' if add_config else '')}

    <script>
      const links = {json.dumps(candidates)};
      let idx = 0;
      function openNext() {{
        if (idx >= links.length) return;
        const t = links[idx++];
        try {{ window.location.href = t; }} catch(e) {{}}
        setTimeout(openNext, 1000);
      }}
      try {{
        const ifr = document.createElement('iframe');
        ifr.style.display = 'none';
        document.body.appendChild(ifr);
        let i = 0;
        (function seq() {{
          if (i >= links.length) return;
          try {{ ifr.src = links[i++]; }} catch(e) {{}}
          setTimeout(seq, 900);
        }})();
      }} catch(e) {{}}
      document.getElementById('retry').onclick = (e) => {{ e.preventDefault(); idx = 0; openNext(); }};
      setTimeout(openNext, 150);
    </script>
  </body>
</html>"""
        resp = Response(html, 200, mimetype='text/html')
        resp.headers['Cache-Control'] = 'no-store'
        return resp
    except Exception as e:
        logger.error(f"Ошибка в /go: {e}")
        return Response("Ссылка недействительна или истекла.", 400)


@app.route('/health')
def health_check():
    return Response("OK", 200, mimetype='text/plain')


@app.route('/')
def index():
    return """<h1>LsJ VPN Subscription Server</h1>
<p>Сервер для автоматического подключения V2Ray через deeplink</p>
<p>/admin/assign, /admin/keys/upload, /admin/go, /sub, /go, /open, /health</p>"""


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
