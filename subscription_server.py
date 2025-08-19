#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, Response, request
import re, urllib.parse, json, logging, base64, hmac, hashlib, time, os, sys
from datetime import datetime, timedelta

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

key_manager = None
_SIGN_SECRET = os.environ.get('AUTH_TOKEN', '') or 'dev-secret'

def _b64url_encode(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')
def _b64url_decode(s: str) -> bytes: return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
def _sign_dict(payload: dict, ttl: int) -> str:
    body = dict(payload); body['exp'] = int(time.time()) + int(ttl)
    body_json = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    sig = hmac.new(_SIGN_SECRET.encode('utf-8'), body_json, hashlib.sha256).digest()
    return _b64url_encode(body_json) + '.' + _b64url_encode(sig)
def _verify_token(token: str) -> dict:
    b64_body, b64_sig = token.split('.', 1)
    body, sig = _b64url_decode(b64_body), _b64url_decode(b64_sig)
    payload = json.loads(body.decode('utf-8')); exp = int(payload.get('exp', 0))
    if exp < int(time.time()): raise ValueError('expired')
    calc = hmac.new(_SIGN_SECRET.encode('utf-8'), body, hashlib.sha256).digest()
    if not hmac.compare_digest(calc, sig): raise ValueError('bad_signature')
    return payload

def init_key_manager():
    global key_manager
    try:
        from key_manager import KeyManager; import config
        key_manager = KeyManager(config.KEYS_FOLDERS)
        logger.info("Key manager инициализирован")
    except Exception as e:
        key_manager = None
        logger.warning(f"KeyManager недоступен, используем файловый фолбэк: {e}")

def _path(*parts): return os.path.join(os.path.dirname(__file__), *parts)
def _read_json(path, default):
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f: return json.load(f) or default
    except Exception: pass
    return default
def _write_json(path, data):
    try:
        with open(path, 'w', encoding='utf-8') as f: json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception: pass

def _load_used_keys_state() -> dict: return _read_json(_path('used_keys.json'), {})
def _get_user_subscription_from_files(uid: int):
    data = _load_used_keys_state(); subs = data.get('user_subscriptions', {}) or {}
    return subs.get(str(uid)) or subs.get(uid)

def _keys_file_for_type(t: str) -> str:
    t = (t or '').lower()
    return _path('keys', {'trial':'trial_keys.txt','month':'month_keys.txt','year':'year_keys.txt'}.get(t,'trial_keys.txt'))

def _read_lines(path: str):
    if not os.path.exists(path): return []
    with open(path,'r',encoding='utf-8') as f: return [ln.strip() for ln in f if ln.strip()]

def _auto_assign_key(user_id: int, sub_type: str) -> str | None:
    """Берет первый свободный ключ из файла тарифа, отмечает использованным и создает подписку."""
    uk = _load_used_keys_state()
    used = set(uk.get('used_keys', []))
    keys_path = _keys_file_for_type(sub_type)
    for key in _read_lines(keys_path):
        if key and key.startswith('vless://') and key not in used:
            # помечаем использованным
            used.add(key)
            uk['used_keys'] = list(used)
            subs = uk.get('user_subscriptions', {}) or {}
            days_map = {'trial': 13, 'month': 30, 'year': 365}
            days = days_map.get((sub_type or 'trial').lower(), 13)
            start_iso = datetime.utcnow().isoformat()
            end_iso = (datetime.utcnow() + timedelta(days=days)).isoformat()
            subs[str(user_id)] = {
                'type': sub_type or 'trial', 'start_date': start_iso, 'end_date': end_iso,
                'days': days, 'active': True, 'current_key': key
            }
            uk['user_subscriptions'] = subs
            hist = uk.get('user_key_history', {}) or {}
            h = hist.get(str(user_id), [])
            h.append({'key': key, 'type': sub_type or 'trial', 'issued_date': start_iso, 'active': True})
            hist[str(user_id)] = h
            uk['user_key_history'] = hist
            _write_json(_path('used_keys.json'), uk)
            # синхронизируем key_data.json (key -> user_id)
            kd = _read_json(_path('key_data.json'), {})
            kd_used = set(kd.get('used_keys', [])); kd_used.add(key)
            kd_assign = kd.get('key_assignments', {}) or {}; kd_assign[key] = int(user_id)
            _write_json(_path('key_data.json'), {'used_keys': list(kd_used), 'key_assignments': kd_assign})
            logger.info(f"Автовыдача ключа {sub_type} пользователю {user_id}")
            return key
    return None

def normalize_vless_for_v2raytun(vless_key: str) -> str:
    try:
        if not vless_key.startswith('vless://'): return vless_key
        m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?(.+?)(?:#(.*))?$', vless_key)
        if not m: return vless_key
        uuid, host, port, params_str, frag = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5) or ''
        params = urllib.parse.parse_qs(params_str); norm={}
        for k,v in params.items():
            if k=='authority': continue
            norm[k] = v[0] if v else ''
        parts=[f"{k}={v}" if v else k for k,v in norm.items()]
        res=f"vless://{uuid}@{host}:{port}?{'&'.join(parts)}"
        if frag:
            clean=re.sub(r'[^\w\\-]','',frag)
            if clean: res+=f"#{clean}"
        return res
    except Exception:
        fb=re.sub(r'[&?]authority=[^&]*(?=&|$)','',vless_key)
        fb=re.sub(r'[?&]&+','?',fb); fb=re.sub(r'&+','&',fb); fb=re.sub(r'[?&]$','',fb)
        return fb

@app.route('/admin/assign', methods=['POST'])
def admin_assign():
    try:
        if request.headers.get('X-Auth-Token','') != _SIGN_SECRET:
            return Response('Unauthorized', 401)
        d = request.get_json(silent=True) or {}
        user_id = int(d.get('user_id')); sub_type = (d.get('type') or 'trial').strip(); key = (d.get('key') or '').strip()
        end_date = (d.get('end_date') or '').strip()
        if not user_id or not key or not key.startswith('vless://'): return Response('Bad request',400)
        kd=_read_json(_path('key_data.json'),{}); kd_used=set(kd.get('used_keys',[])); kd_ass=kd.get('key_assignments',{}) or {}
        kd_used.add(key); kd_ass[key]=user_id; _write_json(_path('key_data.json'),{'used_keys':list(kd_used),'key_assignments':kd_ass})
        uk=_read_json(_path('used_keys.json'),{}); used=set(uk.get('used_keys',[])); used.add(key); uk['used_keys']=list(used)
        subs=uk.get('user_subscriptions',{}) or {}
        start_iso = datetime.utcnow().isoformat()
        end_iso = end_date or (datetime.utcnow()+timedelta(days={'trial':13,'month':30,'year':365}.get(sub_type,30))).isoformat()
        subs[str(user_id)]={'type':sub_type,'start_date':start_iso,'end_date':end_iso,'days':0,'active':True,'current_key':key}
        hist=uk.get('user_key_history',{}) or {}; h=hist.get(str(user_id),[]); h.append({'key':key,'type':sub_type,'issued_date':start_iso,'active':True}); hist[str(user_id)]=h
        uk['user_subscriptions']=subs; uk['user_key_history']=hist; _write_json(_path('used_keys.json'),uk)
        return Response('OK',200)
    except Exception as e:
        logger.error(f"/admin/assign error: {e}"); return Response('Internal error',500)

@app.route('/admin/keys/upload', methods=['POST'])
def admin_upload_keys():
    try:
        if request.headers.get('X-Auth-Token','') != _SIGN_SECRET: return Response('Unauthorized',401)
        data = request.get_json(silent=True) or {}; added_total=0; totals={}
        def append_unique(path,new_items):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            existing = _read_lines(path); s=set(existing)
            to_add=[x.strip() for x in (new_items or []) if x and x.strip().startswith('vless://') and x.strip() not in s]
            if to_add:
                with open(path,'a',encoding='utf-8') as f:
                    for item in to_add: f.write(item+'\n')
            return len(to_add)
        mapping={'trial':_keys_file_for_type('trial'),'month':_keys_file_for_type('month'),'year':_keys_file_for_type('year')}
        for k in ('trial','month','year'):
            added_total += append_unique(mapping[k], data.get(k,[]))
            try:
                with open(mapping[k],'r',encoding='utf-8') as f: totals[k]=sum(1 for _ in f)
            except Exception: totals[k]=0
        return Response(json.dumps({'added':added_total,'total':totals}),200, mimetype='application/json')
    except Exception as e:
        logger.error(f"Ошибка /admin/keys/upload: {e}"); return Response('Internal error',500)

@app.route('/sub/<signed_id>')
def get_subscription(signed_id):
    if key_manager is None: init_key_manager()
    try:
        payload=_verify_token(signed_id); uid=int(payload.get('uid')); sub_type=str(payload.get('t') or '')
        logger.info(f"Запрос подписки для пользователя {uid}, тип: {sub_type}")
        # 1) пробуем привязку
        user_key=None
        if key_manager is not None:
            try: user_key = key_manager.get_user_key(uid)
            except Exception: user_key=None
        if not user_key:
            kd=_read_json(_path('key_data.json'),{})
            for k, u in (kd.get('key_assignments',{}) or {}).items():
                try:
                    if int(u)==uid: user_key=k; break
                except Exception: pass
        # 2) если ключ не найден — авто-выдача из файла тарифа
        if not user_key:
            user_key=_auto_assign_key(uid, sub_type)
        if not user_key:
            logger.error(f"Ключ не найден для пользователя {uid}")
            return Response("Key not found",404)
        # активность/тип
        user_sub=None; is_active=False
        if key_manager is not None:
            try: user_sub=key_manager.get_user_subscription(uid); is_active=bool(key_manager.is_subscription_active(uid))
            except Exception: user_sub=None; is_active=False
        if user_sub is None:
            user_sub=_get_user_subscription_from_files(uid)
            try:
                if user_sub and user_sub.get('end_date'):
                    end_dt=datetime.fromisoformat(user_sub['end_date'])
                    is_active = datetime.utcnow()<end_dt and bool(user_sub.get('active',True))
            except Exception:
                is_active=bool(user_sub)
        if not user_sub or not is_active: return Response("Subscription inactive",403)
        current_type=str((user_sub or {}).get('type') or '')
        if sub_type and current_type and current_type!=sub_type: return Response("Subscription type mismatch",403)
        normalized = normalize_vless_for_v2raytun(user_key)
        want_b64 = str(request.args.get('b64') or '').lower() in ('1','true','yes','b64')
        body_text = base64.b64encode(normalized.encode()).decode('ascii') if want_b64 else normalized
        safe_name=f"{uid}_{sub_type or 'vpn'}.sub"
        return Response(body_text,200, mimetype='text/plain', headers={
            'Content-Type':'text/plain; charset=utf-8',
            'Content-Disposition':f'inline; filename="{safe_name}"',
            'Cache-Control':'no-store',
            'Access-Control-Allow-Origin':'*',
            'subscription-userinfo':'upload=0; download=0; total=0; expire=0'
        })
    except Exception as e:
        logger.error(f"/sub error: {e}"); return Response("Internal server error",500)

@app.route('/open')
def open_scheme():
    try:
        raw=(request.args.get('url') or '').strip()
        if not raw: return Response("Missing url",400)
        import urllib.parse as _up
        dec=raw
        try: dec=_up.unquote(raw)
        except Exception: pass
        if not dec.lower().startswith('v2raytun://'): return Response("Unsupported scheme",400)
        safe=json.dumps(dec)
        html=f"""<!doctype html><html lang="ru"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Открытие V2RayTun</title>
<script>(function(){{
  var t={safe};
  try{{window.location.replace(t);}}catch(e){{window.location.href=t;}}
  setTimeout(function(){{document.getElementById('fallback').style.display='block';}},800);
}})();</script>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial;max-width:760px;margin:24px auto;padding:0 16px}}a.btn{{display:inline-block;background:#111827;color:#fff;text-decoration:none;border-radius:8px;padding:10px 14px}}</style>
</head><body><h3>Открываем V2RayTun…</h3><div id="fallback" style="display:none">Если не открылось, нажмите кнопку:</div>
<p><a class="btn" href="{dec}">Открыть приложение</a></p></body></html>"""
        return Response(html,200, mimetype='text/html')
    except Exception as e:
        logger.error(f"Ошибка в /open: {e}"); return Response("Internal error",500)

@app.route('/admin/go', methods=['GET'])
def admin_generate_go():
    try:
        if request.headers.get('X-Auth-Token','') != _SIGN_SECRET: return Response('Unauthorized',401)
        uid=int(request.args.get('uid') or '0'); t=(request.args.get('t') or 'trial').strip(); ttl=int(request.args.get('ttl') or '600')
        if not uid: return Response('Bad request',400)
        token=_sign_dict({'uid':uid,'t':t}, ttl); base=request.url_root.rstrip('/'); url=f"{base}/go/{token}"
        return Response(json.dumps({'url':url,'token':token}, ensure_ascii=False),200, mimetype='application/json')
    except Exception as e:
        logger.error(f"/admin/go error: {e}"); return Response('Internal error',500)

@app.route('/go/<token>')
def go_launcher(token: str):
    try:
        payload=_verify_token(token); uid=int(payload.get('uid')); t=str(payload.get('t') or '')
        signed_id=_sign_dict({'uid':uid,'t':t}, 300)
        base=request.url_root.rstrip('/')
        sub=f"{base}/sub/{signed_id}"; enc=urllib.parse.quote(sub, safe=''); sub_b64=f"{sub}?b64=1"; enc_b64=urllib.parse.quote(sub_b64, safe='')
        add_config=''
        try:
            raw=app.test_client().get(f"/sub/{signed_id}")
            if raw.status_code==200:
                v=raw.get_data(as_text=True)
                if isinstance(v,str) and v.strip().startswith('vless://'):
                    add_config=f"v2raytun://add?config={urllib.parse.quote(v.strip(), safe='')}"
        except Exception: pass
        cands=[
            f"v2raytun://import?url={enc}&autostart=1",
            f"v2raytun://import?url={enc_b64}&autostart=1",
            f"v2raytun://import-config?url={enc}",
            f"v2raytun://import-config?url={enc_b64}",
            f"v2raytun://subscribe?url={enc}",
            f"v2raytun://subscribe?url={enc_b64}",
            f"v2raytun://add?url={enc}",
        ]
        if add_config: cands.append(add_config)
        cands.append(f"intent://import?url={enc}#Intent;scheme=v2raytun;package=com.v2raytun.android;end")
        open_bridge_import=f"{base}/open?url={urllib.parse.quote(cands[0], safe='')}"
        html=f"""<!doctype html><html lang="ru"><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Открываем V2RayTun…</title>
<style>body {{ font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial; max-width:640px; margin:40px auto; padding:0 16px; }}
.btn {{ display:inline-block; padding:12px 16px; border-radius:12px; border:1px solid #ddd; text-decoration:none; color:#111; }}
.row {{ margin-top:14px; }} .muted {{ color:#666; }}</style>
<body><h2>Открываем V2RayTun…</h2><p class="muted">Если приложение не открылось автоматически, используйте кнопки ниже.</p>
<div class="row"><a id="retry" class="btn" href="#">Открыть снова</a></div>
<div class="row"><a id="sys" class="btn" href="{cands[-1]}">Открыть через систему (Android)</a></div>
<div class="row"><a class="btn" href="{open_bridge_import}">Через HTTPS‑мост (import)</a></div>
<div class="row"><a class="btn" href="https://deeplink.website/?url={urllib.parse.quote(cands[0], safe='')}">Через deeplink.website (import)</a></div>
<div class="row"><a class="btn" href="https://deeplink.website/?url={urllib.parse.quote(cands[2], safe='')}">Через deeplink.website (import-config)</a></div>
<script>
const links = {json.dumps(cands)};
let idx=0; function openNext(){ if(idx>=links.length) return; const t=links[idx++]; try{window.location.href=t;}catch(e){} setTimeout(openNext,1000); }
try{{ var ifr=document.createElement('iframe'); ifr.style.display='none'; document.body.appendChild(ifr); let i=0; (function seq(){{ if(i>=links.length) return; try{{ifr.src=links[i++];}}catch(e){{}} setTimeout(seq,900); }})(); }}catch(e){{}}
document.getElementById('retry').onclick=(e)=>{{ e.preventDefault(); idx=0; openNext(); }};
setTimeout(openNext,150);
</script></body></html>"""
        r=Response(html,200,mimetype='text/html'); r.headers['Cache-Control']='no-store'; return r
    except Exception as e:
        logger.error(f"Ошибка в /go: {e}"); return Response("Ссылка недействительна или истекла.",400)

@app.route('/health')
def health(): return Response("OK",200,mimetype='text/plain')

@app.route('/')
def index():
    return """<h1>LsJ VPN Subscription Server</h1>
<p>/admin/assign, /admin/keys/upload, /admin/go, /sub, /go, /open, /health</p>"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=False)
