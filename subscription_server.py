#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subscription/Deeplink сервер для автоимпорта V2RayTun.

Что умеет:
- /go/<token>            — HTML-лаунчер, который открывает v2raytun:// разными способами
- /sub/<signed_id>       — отдаёт RAW VLESS (text/plain; inline; no-store)
- /open?url=...          — безопасный мост для custom-схем (v2raytun://)
- /copy?text=...         — страница быстрого копирования текста (ключа)
- /health                — healthcheck
- /admin/assign          — привязка ключа к user_id от бота (X-Auth-Token)
- /admin/keys/upload     — заливка ключей на сервер (trial/month/year) (X-Auth-Token)

Ожидается переменная окружения:
- AUTH_TOKEN — секрет для подписи токенов и админ-эндпоинтов
"""

from flask import Flask, Response, request
import re
import urllib.parse as _up
from urllib.parse import quote
import json
import logging
import base64
import hmac
import hashlib
import time
import os

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Секрет для HMAC и админ-эндпоинтов (одинаковый с ботом)
_SIGN_SECRET = os.environ.get('AUTH_TOKEN', '') or 'dev-secret'

# Память одноразовых go-токенов
_USED_GO_TOKENS = {}  # token -> used_at (epoch seconds)


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
    payload = json.loads(body.decode('utf-8'))
    exp = int(payload.get('exp', 0))
    if exp < int(time.time()):
        raise ValueError('expired')
    calc = hmac.new(_SIGN_SECRET.encode('utf-8'), body, hashlib.sha256).digest()
    if not hmac.compare_digest(calc, sig):
        raise ValueError('bad_signature')
    return payload


def _key_data_path() -> str:
    return os.path.join(os.path.dirname(__file__), 'key_data.json')


def _load_key_data() -> dict:
    try:
        path = _key_data_path()
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f) or {}
    except Exception:
        pass
    return {'used_keys': [], 'key_assignments': {}}


def _save_key_data(data: dict) -> None:
    try:
        with open(_key_data_path(), 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def normalize_vless_for_v2raytun(vless_key: str) -> str:
    """Нормализует VLESS: удаляет authority и чистит фрагмент."""
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

        params = _up.parse_qs(params_str)
        normalized = {}
        for k, v in params.items():
            if k == 'authority':
                continue
            normalized[k] = v[0] if v else ''

        parts = []
        for k, v in normalized.items():
            parts.append(f"{k}={v}" if v else k)
        params_str2 = '&'.join(parts)

        result = f"vless://{uuid}@{host}:{port}?{params_str2}"
        if fragment:
            clean = re.sub(r'[^\w\-]', '', fragment)
            if clean:
                result += f"#{clean}"
        return result
    except Exception:
        # Fallback: грубая очистка authority
        fallback = re.sub(r'[&?]authority=(?=&|$)', '', vless_key)
        fallback = re.sub(r'[&?]authority=[^&]*(?=&|$)', '', fallback)
        fallback = re.sub(r'[?&]&+', '?', fallback)
        fallback = re.sub(r'&+', '&', fallback)
        fallback = re.sub(r'[?&]$', '', fallback)
        return fallback


@app.route('/admin/assign', methods=['POST'])
def admin_assign():
    """Привязка ключа к пользователю от бота. Требует X-Auth-Token."""
    try:
        auth = request.headers.get('X-Auth-Token', '')
        if not _SIGN_SECRET or auth != _SIGN_SECRET:
            return Response('Unauthorized', status=401, mimetype='text/plain')

        data = request.get_json(silent=True) or {}
        user_id = int(data.get('user_id'))
        key = str(data.get('key') or '').strip()
        if not user_id or not key.startswith('vless://'):
            return Response('Bad request', status=400, mimetype='text/plain')

        kd = _load_key_data()
        used = set(kd.get('used_keys', []))
        assigns = kd.get('key_assignments', {})
        used.add(key)
        assigns[key] = int(user_id)
        kd['used_keys'] = list(used)
        kd['key_assignments'] = assigns
        _save_key_data(kd)
        return Response('OK', status=200, mimetype='text/plain')
    except Exception as e:
        logger.error(f"/admin/assign error: {e}")
        return Response('Internal error', status=500, mimetype='text/plain')


@app.route('/admin/keys/upload', methods=['POST'])
def admin_upload_keys():
    """Принимает JSON {'trial':[], 'month':[], 'year':[]} и добавляет строки в keys/*.txt (X-Auth-Token)."""
    try:
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
            to_add = [x.strip() for x in new_items if x and x.strip().startswith('vless://') and x.strip() not in existing_set]
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


@app.route('/sub/<signed_id>')
def get_subscription(signed_id):
    """Отдаёт нормализованный VLESS для пользователя (по подписанному ID)."""
    try:
        payload = _verify_token(signed_id)
        user_id = int(payload.get('uid'))
        tariff = str(payload.get('t') or '')

        kd = _load_key_data()
        key = None
        for k, uid in kd.get('key_assignments', {}).items():
            try:
                if int(uid) == user_id:
                    key = k
                    break
            except Exception:
                continue

        if not key:
            return Response("Key not found", status=404, mimetype='text/plain')

        normalized_key = normalize_vless_for_v2raytun(key)
        safe_name = f"{user_id}_{tariff or 'vpn'}.sub"
        resp = Response(
            normalized_key,
            status=200,
            mimetype='text/plain',
            headers={
                'Content-Type': 'text/plain; charset=utf-8',
                'Content-Disposition': f'inline; filename="{safe_name}"',
                'Cache-Control': 'no-store',
                'Access-Control-Allow-Origin': '*',
            }
        )
        try:
            logger.info(json.dumps({
                'event': 'sub_served',
                'uid': user_id,
                'tariff': tariff,
                'ip': request.remote_addr,
                'ua': request.headers.get('User-Agent', '')[:180]
            }, ensure_ascii=False))
        except Exception:
            pass
        return resp
    except Exception as e:
        logger.error(f"/sub error: {e}")
        return Response("Internal server error", status=500, mimetype='text/plain')


@app.route('/open')
def open_scheme():
    """HTTPS-мост для custom-схем (v2raytun://)"""
    try:
        raw = (request.args.get('url') or '').strip()
        if not raw:
            return Response("Missing url", status=400, mimetype='text/plain')
        decoded = raw
        try:
            decoded = _up.unquote(raw)
        except Exception:
            pass
        if not decoded.lower().startswith('v2raytun://'):
            return Response("Unsupported scheme", status=400, mimetype='text/plain')

        safe = json.dumps(decoded)
        html = f"""<!doctype html><html lang="ru"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Открытие V2RayTun</title>
<script>
(function(){{
  var t={safe};
  try{{ window.location.replace(t); }}catch(e){{ window.location.href=t; }}
  setTimeout(function(){{
    document.getElementById('fallback').style.display='block';
  }}, 800);
}})();
</script>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,Arial;max-width:760px;margin:24px auto;padding:0 16px}}a.btn{{display:inline-block;background:#111827;color:#fff;text-decoration:none;border-radius:8px;padding:10px 14px}}</style>
</head><body>
<h3>Открываем V2RayTun…</h3>
<div id="fallback" style="display:none">Если не открылось, нажмите кнопку:</div>
<p><a class="btn" href="{decoded}">Открыть приложение</a></p>
</body></html>"""
        return Response(html, status=200, mimetype='text/html')
    except Exception as e:
        logger.error(f"/open error: {e}")
        return Response("Internal error", status=500, mimetype='text/plain')


@app.route('/copy')
def copy_page():
    """Страница для быстрого копирования текста (ключа)."""
    try:
        text = (request.args.get('text') or '').strip()
        preview = (text[:140] + '…') if len(text) > 140 else text
        html = f"""<!doctype html><html lang="ru"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Копирование ключа</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,Arial;max-width:760px;margin:24px auto;padding:0 16px}}.mono{{font-family:ui-monospace,Menlo,monospace;background:#f6f8fa;border:1px solid #e5e7eb;border-radius:8px;padding:10px;word-break:break-all}}.btn{{display:inline-block;background:#111827;color:#fff;text-decoration:none;border-radius:8px;padding:10px 14px}}</style>
<script>
async function doCopy(){{try{{await navigator.clipboard.writeText({json.dumps(text)});document.getElementById('res').textContent='✅ Ключ скопирован';}}catch(e){{document.getElementById('res').textContent='Скопируйте вручную';}}}}
window.addEventListener('load',()=>{{setTimeout(doCopy,50);}});
</script>
</head><body>
<h3>Ключ для копирования</h3>
<div class="mono">{preview}</div>
<p id="res">Пытаемся скопировать…</p>
<a class="btn" href="#" onclick="doCopy();return false;">📋 Скопировать</a>
</body></html>"""
        return Response(html, status=200, mimetype='text/html')
    except Exception:
        return Response("Error", status=500, mimetype='text/plain')


@app.route('/go/<token>')
def go_launcher(token: str):
    """HTML-лаунчер для открытия V2RayTun с несколькими вариантами deeplink."""
    try:
        now = int(time.time())
        used_at = _USED_GO_TOKENS.get(token)
        if used_at and now - used_at < 600:
            return Response("Ссылка уже использована.", status=410, mimetype='text/plain')

        payload = _verify_token(token)
        user_id = int(payload.get('uid'))
        tariff = str(payload.get('t') or '')

        # Подписываем короткий id для /sub (5 минут)
        signed_id = _sign_dict({'uid': user_id, 't': tariff}, ttl_seconds=300)

        base = request.url_root.rstrip('/')
        sub_url = f"{base}/sub/{signed_id}"
        enc_sub = quote(sub_url, safe='')

        # Пробуем также RAW vless для add?config
        add_config = ''
        try:
            raw_resp = app.test_client().get(f"/sub/{signed_id}")
            if raw_resp.status_code == 200:
                vless_raw = raw_resp.get_data(as_text=True)
                if isinstance(vless_raw, str) and vless_raw.strip().startswith('vless://'):
                    add_config = f"v2raytun://add?config={quote(vless_raw.strip(), safe='')}"
        except Exception:
            add_config = ''

        candidates = [
            f"v2raytun://import?url={enc_sub}&autostart=1",
            f"v2raytun://import-config?url={enc_sub}",
            f"v2raytun://subscribe?url={enc_sub}",
            f"v2raytun://add?url={enc_sub}",
        ]
        if add_config:
            candidates.append(add_config)
        candidates.append(f"intent://import?url={enc_sub}#Intent;scheme=v2raytun;package=com.v2raytun;end")

        _USED_GO_TOKENS[token] = now

        try:
            logger.info(json.dumps({
                'event': 'go_opened',
                'uid': user_id,
                'tariff': tariff,
                'ip': request.remote_addr,
                'ua': request.headers.get('User-Agent', '')[:180]
            }, ensure_ascii=False))
        except Exception:
            pass

        html = f"""<!doctype html>
<html lang="ru">
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Открываем V2RayTun…</title>
  <style>
    body {{ font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial; max-width: 640px; margin: 40px auto; padding: 0 16px; }}
    .btn {{ display:inline-block; padding:12px 16px; border-radius:12px; border:1px solid #ddd; text-decoration:none; color:#111; }}
    .row {{ margin-top:14px; }}
    .muted {{ color:#666; }}
  </style>
  <body>
    <h2>Открываем V2RayTun…</h2>
    <p class="muted">Если приложение не открылось автоматически, используйте кнопки ниже.</p>
    <div class="row"><a id="retry" class="btn" href="#">Открыть снова</a></div>
    <div class="row"><a id="sys" class="btn" href="{candidates[-1]}">Открыть через систему (Android)</a></div>
    <div class="row"><a class="btn" href="https://deeplink.website/?url={quote(candidates[0], safe='')}">Через deeplink.website (import)</a></div>
    <div class="row"><a class="btn" href="https://deeplink.website/?url={quote(candidates[1], safe='')}">Через deeplink.website (import-config)</a></div>
    {('<div class="row"><a class="btn" href="https://deeplink.website/?url='+quote(add_config, safe='')+'">Через deeplink.website (add?config)</a></div>' if add_config else '')}

    <script>
      const links = {json.dumps(candidates)};
      let idx = 0;
      function openNext() {{
        if (idx >= links.length) return;
        const t = links[idx++];
        try {{ window.location.href = t; }} catch(e) {{}}
        setTimeout(openNext, 1000);
      }}
      document.getElementById('retry').onclick = (e) => {{ e.preventDefault(); idx = 0; openNext(); }};
      // Дополнительно скрытый iframe — помогает в некоторых WebView
      try {{
        var ifr = document.createElement('iframe');
        ifr.style.display = 'none';
        document.body.appendChild(ifr);
        let i = 0;
        (function seq(){{
          if (i >= links.length) return;
          try {{ ifr.src = links[i++]; }} catch(e) {{}}
          setTimeout(seq, 900);
        }})();
      }} catch(e) {{}}
      setTimeout(openNext, 150);
    </script>
  </body>
</html>"""
        resp = Response(html, status=200, mimetype='text/html')
        resp.headers['Cache-Control'] = 'no-store'
        return resp
    except Exception as e:
        logger.error(f"/go error: {e}")
        return Response("Ссылка недействительна или истекла.", status=400, mimetype='text/plain')


@app.route('/health')
def health():
    return Response("OK", status=200, mimetype='text/plain')


@app.route('/')
def index():
    return """<h1>VPN Config Service</h1>
<p>Сервис для автоимпорта V2RayTun</p>
<p>Эндпоинты: /go, /sub, /open, /admin/assign, /admin/keys/upload</p>"""


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
