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

app = Flask(__name__)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Импорт для локальной разработки (модуль может отсутствовать на сервере)
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Глобальная переменная для key_manager (опционально)
key_manager = None

# Безопасные токены (HMAC-SHA256 base64url) для /go и /sub
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

@app.route('/admin/keys/upload', methods=['POST'])
def admin_upload_keys():
    """
    Принимает JSON {"trial":[...], "month":[...], "year":[...]} и добавляет в keys/*.txt.
    Требуется заголовок X-Auth-Token == AUTH_TOKEN.
    """
    try:
        auth = request.headers.get('X-Auth-Token', '')
        if not _SIGN_SECRET or auth != _SIGN_SECRET:
            return Response('Unauthorized', status=401, mimetype='text/plain')

        data = request.get_json(silent=True) or {}
        added_total, totals = 0, {}

        def append_unique(path: str, new_items: list[str]) -> int:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            existing = []
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    existing = [line.strip() for line in f if line.strip()]
            existing_set = set(existing)
            to_add = [x.strip() for x in new_items
                      if x and x.strip().startswith('vless://') and x.strip() not in existing_set]
            if not to_add:
                return 0
            with open(path, 'a', encoding='utf-8') as f:
                for item in to_add:
                    f.write(item + '\n')
            return len(to_add)

        mapping = {
            'trial': os.path.join(os.path.dirname(__file__), 'keys', 'trial_keys.txt'),
            'month': os.path.join(os.path.dirname(__file__), 'keys', 'month_keys.txt'),
            'year':  os.path.join(os.path.dirname(__file__), 'keys', 'year_keys.txt'),
        }

        for k in ('trial', 'month', 'year'):
            count = append_unique(mapping[k], data.get(k, []) or [])
            added_total += count
            try:
                with open(mapping[k], 'r', encoding='utf-8') as f:
                    totals[k] = sum(1 for _ in f)
            except Exception:
                totals[k] = 0

        return Response(json.dumps({'added': added_total, 'total': totals}), status=200, mimetype='application/json')
    except Exception as e:
        logger.error(f"Ошибка /admin/keys/upload: {e}")
        return Response('Internal error', status=500, mimetype='text/plain')

def init_key_manager():
    """Инициализация key_manager (мягкая): если модуль отсутствует — используем файловый фолбэк."""
    global key_manager
    try:
        from key_manager import KeyManager
        import config
        key_manager = KeyManager(config.KEYS_FOLDERS)
        logger.info("Key manager инициализирован успешно")
    except Exception as e:
        key_manager = None
        logger.warning(f"KeyManager недоступен, используем файловый фолбэк: {e}")

def _load_used_keys_state() -> dict:
    """Читает used_keys.json (подписки/история), если есть."""
    try:
        path = os.path.join(os.path.dirname(__file__), 'used_keys.json')
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f) or {}
    except Exception:
        pass
    return {}

def _get_user_subscription_from_files(user_id: int) -> dict | None:
    """Возвращает подписку пользователя из used_keys.json, если найдена."""
    data = _load_used_keys_state()
    subs = data.get('user_subscriptions', {}) or {}
    return subs.get(str(user_id)) or subs.get(user_id)

def normalize_vless_for_v2raytun(vless_key: str) -> str:
    """
    Нормализует VLESS ключ для корректной работы с V2RayTun:
    - удаляет параметр authority
    - чистит fragment от недопустимых символов
    """
    try:
        if not vless_key.startswith('vless://'):
            return vless_key
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

        params_list = []
        for key, value in normalized_params.items():
            params_list.append(f"{key}={value}" if value else key)
        params_string = '&'.join(params_list)

        normalized_key = f"vless://{uuid}@{host}:{port}?{params_string}"
        if fragment:
            clean_fragment = re.sub(r'[^\w\-]', '', fragment)
            if clean_fragment:
                normalized_key += f"#{clean_fragment}"
        return normalized_key
    except Exception as e:
        logger.error(f"Ошибка нормализации VLESS: {e}")
        # Fallback — простое удаление authority и чистка хвостов
        fallback = re.sub(r'[&?]authority=[^&]*(?=&|$)', '', vless_key)
        fallback = re.sub(r'[?&]&+', '?', fallback)
        fallback = re.sub(r'&+', '&', fallback)
        fallback = re.sub(r'[?&]$', '', fallback)
        return fallback

@app.route('/sub/<signed_id>')
def get_subscription(signed_id):
    """
    Возвращает RAW VLESS для пользователя по подписанному ID.
    Проверяет активность подписки и соответствие тарифа.
    """
    global key_manager
    if key_manager is None:
        init_key_manager()
    try:
        payload = _verify_token(signed_id)
        user_id = int(payload.get('uid'))
        subscription_type = str(payload.get('t') or '')

        logger.info(f"Запрос подписки: uid={user_id} type={subscription_type}")

        # Ключ: сначала key_manager, затем key_data.json
        user_key = None
        try:
            if key_manager is not None:
                user_key = key_manager.get_user_key(user_id)
        except Exception:
            user_key = None

        if not user_key:
            try:
                kd_path = os.path.join(os.path.dirname(__file__), 'key_data.json')
                if os.path.exists(kd_path):
                    with open(kd_path, 'r', encoding='utf-8') as f:
                        kd = json.load(f)
                    for k, uid in (kd.get('key_assignments', {}) or {}).items():
                        try:
                            if int(uid) == int(user_id):
                                user_key = k
                                break
                        except Exception:
                            continue
            except Exception:
                user_key = None

        if not user_key:
            return Response("Key not found", status=404, mimetype='text/plain')

        # Подписка: key_manager или used_keys.json
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
                    from datetime import datetime
                    end_dt = datetime.fromisoformat(user_sub['end_date'])
                    is_active = datetime.utcnow() < end_dt and bool(user_sub.get('active', True))
            except Exception:
                is_active = bool(user_sub)

        if not user_sub or not is_active:
            return Response("Subscription inactive", status=403, mimetype='text/plain')

        current_type = str((user_sub or {}).get('type') or '')
        if subscription_type and current_type and current_type != subscription_type:
            return Response("Subscription type mismatch", status=403, mimetype='text/plain')

        normalized_key = normalize_vless_for_v2raytun(user_key)
        safe_name = f"{user_id}_{subscription_type or 'vpn'}.sub"
        resp = Response(
            normalized_key,
            status=200,
            mimetype='text/plain',
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
        return Response("Internal server error", status=500, mimetype='text/plain')

@app.route('/health')
def health_check():
    return Response("OK", status=200, mimetype='text/plain')

@app.route('/copy')
def copy_page():
    try:
        text = request.args.get('text', '').strip()
        preview = (text[:140] + '…') if len(text) > 140 else text
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Копирование ключа</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial;max-width:760px;margin:24px auto;padding:0 16px}}.mono{{font-family:ui-monospace, SFMono-Regular, Menlo, monospace;background:#f6f8fa;border:1px solid #e5e7eb;border-radius:8px;padding:10px;word-break:break-all}}.btn{{display:inline-block;background:#111827;color:#fff;text-decoration:none;border-radius:8px;padding:10px 14px}}</style>
<script>async function doCopy(){{try{{await navigator.clipboard.writeText({json.dumps(text)});document.getElementById('res').textContent='✅ Ключ скопирован';}}catch(e){{document.getElementById('res').textContent='Скопируйте вручную';}}}}window.addEventListener('load',()=>{{setTimeout(doCopy,50);}});</script>
</head>
<body>
<h3>Ключ для копирования</h3>
<div class="mono">{preview}</div>
<p id="res">Пытаемся скопировать…</p>
<a class="btn" href="#" onclick="doCopy();return false;">📋 Скопировать</a>
</body>
</html>"""
        return Response(html, status=200, mimetype='text/html')
    except Exception:
        return Response("Error", status=500, mimetype='text/plain')

@app.route('/open')
def open_scheme():
    """
    HTTPS‑мост для custom-схем (v2raytun://), безопасен для Telegram WebView.
    Использование: /open?url=<urlencoded_v2raytun_scheme>
    """
    try:
        raw = (request.args.get('url') or '').strip()
        if not raw:
            return Response("Missing url", status=400, mimetype='text/plain')
        import urllib.parse as _up
        decoded = raw
        try:
            decoded = _up.unquote(raw)
        except Exception:
            pass
        if not decoded.lower().startswith('v2raytun://'):
            return Response("Unsupported scheme", status=400, mimetype='text/plain')

        safe_href = json.dumps(decoded)
        html = f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
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
        return Response(html, status=200, mimetype='text/html')
    except Exception as e:
        logger.error(f"Ошибка в /open: {e}")
        return Response("Internal error", status=500, mimetype='text/plain')

@app.route('/admin/assign', methods=['POST'])
def admin_assign():
    """
    Привязка ключа к пользователю (idempotent), используется ботом.
    Требуется заголовок X-Auth-Token == AUTH_TOKEN.
    Body: { user_id, type, key, end_date? }
    """
    try:
        auth = request.headers.get('X-Auth-Token', '')
        if not _SIGN_SECRET or auth != _SIGN_SECRET:
            return Response('Unauthorized', status=401, mimetype='text/plain')

        data = request.get_json(silent=True) or {}
        user_id = int(data.get('user_id'))
        sub_type = str(data.get('type') or '').strip() or 'trial'
        key = str(data.get('key') or '').strip()
        end_date = str(data.get('end_date') or '').strip()
        if not user_id or not key:
            return Response('Bad request', status=400, mimetype='text/plain')

        # key_data.json (key -> user_id)
        kd_path = os.path.join(os.path.dirname(__file__), 'key_data.json')
        try:
            kd = {}
            if os.path.exists(kd_path):
                with open(kd_path, 'r', encoding='utf-8') as f:
                    kd = json.load(f) or {}
            used_keys = set(kd.get('used_keys', []))
            key_assignments = kd.get('key_assignments', {}) or {}
            used_keys.add(key)
            key_assignments[key] = int(user_id)
            with open(kd_path, 'w', encoding='utf-8') as f:
                json.dump({'used_keys': list(used_keys), 'key_assignments': key_assignments}, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        # used_keys.json (минимально совместимо с KeyManager)
        try:
            uk_path = os.path.join(os.path.dirname(__file__), 'used_keys.json')
            uk = {}
            if os.path.exists(uk_path):
                with open(uk_path, 'r', encoding='utf-8') as f:
                    uk = json.load(f) or {}
            used = set(uk.get('used_keys', [])); used.add(key); uk['used_keys'] = list(used)
            user_subscriptions = uk.get('user_subscriptions', {}) or {}
            from datetime import datetime, timedelta
            start_iso = datetime.utcnow().isoformat()
            end_iso = end_date or (datetime.utcnow() + timedelta(days=30)).isoformat()
            user_subscriptions[str(user_id)] = {
                'type': sub_type, 'start_date': start_iso, 'end_date': end_iso,
                'days': 0, 'active': True, 'current_key': key
            }
            # history (опционально)
            user_key_history = uk.get('user_key_history', {}) or {}
            hist = user_key_history.get(str(user_id), [])
            hist.append({'key': key, 'type': sub_type, 'issued_date': start_iso, 'active': True})
            user_key_history[str(user_id)] = hist
            uk['user_subscriptions'] = user_subscriptions
            uk['user_key_history'] = user_key_history
            with open(uk_path, 'w', encoding='utf-8') as f:
                json.dump(uk, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        return Response('OK', status=200, mimetype='text/plain')
    except Exception as e:
        logger.error(f"Ошибка в /admin/assign: {e}")
        return Response('Internal error', status=500, mimetype='text/plain')

@app.route('/admin/go', methods=['GET'])
def admin_generate_go():
    """Генерация ссылки /go на стороне сервера (для диагностики)."""
    try:
        auth = request.headers.get('X-Auth-Token', '')
        if not _SIGN_SECRET or auth != _SIGN_SECRET:
            return Response('Unauthorized', status=401, mimetype='text/plain')

        try:
            user_id = int(request.args.get('uid') or '0')
        except Exception:
            user_id = 0
        tariff = (request.args.get('t') or 'trial').strip()
        try:
            ttl = int(request.args.get('ttl') or '600')
        except Exception:
            ttl = 600
        if not user_id:
            return Response('Bad request', status=400, mimetype='text/plain')

        token = _sign_dict({'uid': user_id, 't': tariff}, ttl_seconds=ttl)
        base = request.url_root.rstrip('/')
        url = f"{base}/go/{token}"
        return Response(json.dumps({'url': url, 'token': token}, ensure_ascii=False), status=200, mimetype='application/json')
    except Exception as e:
        logger.error(f"/admin/go error: {e}")
        return Response('Internal error', status=500, mimetype='text/plain')

@app.route('/go/<token>')
def go_launcher(token: str):
    """
    HTML‑лаунчер (200 OK) с несколькими вариантами deeplink, безопасный для Telegram WebView.
    """
    try:
        _ = int(time.time())
        payload = _verify_token(token)
        user_id = int(payload.get('uid'))
        tariff = str(payload.get('t') or '')

        signed_id = _sign_dict({'uid': user_id, 't': tariff}, ttl_seconds=300)
        base = request.url_root.rstrip('/')
        sub_url = f"{base}/sub/{signed_id}"
        enc_sub_url = urllib.parse.quote(sub_url, safe='')

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
            f"v2raytun://import-config?url={enc_sub_url}",
            f"v2raytun://subscribe?url={enc_sub_url}",
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
        (function seq(){{
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
        resp = Response(html, status=200, mimetype='text/html')
        resp.headers['Cache-Control'] = 'no-store'
        return resp
    except Exception as e:
        logger.error(f"Ошибка в /go: {e}")
        return Response("Ссылка недействительна или истекла.", status=400, mimetype='text/plain')

@app.route('/')
def index():
    return """
    <h1>LsJ VPN Subscription Server</h1>
    <p>Сервер для автоматического подключения V2Ray через deeplink</p>
    <p>/admin/assign, /admin/keys/upload, /admin/go, /sub, /go, /open, /health</p>
    """

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
