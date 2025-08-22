import os
import html
import logging
import urllib.parse as up
from flask import Flask, request, render_template_string, abort

app = Flask(__name__)

APP_NAME = os.environ.get("APP_NAME", "VPN Config Service")
FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "1") == "1"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
ALLOWED_SCHEMES = set((os.environ.get("ALLOWED_SCHEMES") or "v2raytun").split(","))

logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
logger = logging.getLogger("vpn-config-service")

HTML_OPEN = """
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>{{ app_name }} — Открытие ссылки</title>
  {% if force_https %}<script>if(location.protocol!=="https:"){location.href="https:"+location.href.substring(location.protocol.length);}</script>{% endif %}
  <style>
    :root { color-scheme: dark; }
    body { font-family: system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif; margin:0; padding:24px; background:#0f172a; color:#e2e8f0; }
    .card { max-width:720px; margin:0 auto; background:#111827; padding:24px; border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.4); }
    .btn { display:inline-block; margin:12px 8px 0 0; padding:12px 16px; border-radius:8px; background:#2563eb; color:#fff; text-decoration:none; }
    .btn.secondary { background:#334155; }
    code,pre { white-space:pre-wrap; word-break:break-all; }
  </style>
</head>
<body>
  <div class="card">
    <h3>Открываем приложение…</h3>
    <p>Если приложение не открылось автоматически, нажмите кнопку ниже.</p>
    <p>
      <a class="btn" id="openBtn" href="{{ deep_link }}">Открыть сейчас</a>
      <a class="btn secondary" href="#" onclick="copyLink();return false;">Скопировать ссылку</a>
    </p>
    <p style="opacity:.8">Целевая ссылка:</p>
    <pre><code id="linkText">{{ deep_link }}</code></pre>
  </div>
  <script>
    const target = "{{ deep_link_js }}";
    function openNow(){ try { window.location.href = target; } catch(e) {} }
    function copyLink(){
      const el = document.createElement('textarea');
      el.value = target;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      alert('Ссылка скопирована');
    }
    setTimeout(openNow, 50);
  </script>
</body>
</html>
"""

def _is_allowed_scheme(url: str) -> bool:
    try:
        parsed = up.urlparse(url)
        return (parsed.scheme or "").lower() in ALLOWED_SCHEMES
    except Exception:
        return False

@app.get("/")
def index():
    return {"service": APP_NAME, "status": "ok"}, 200

@app.get("/healthz")
def healthz():
    return "ok", 200

@app.get("/open")
def open_link():
    url = (request.args.get("url") or "").strip()
    if not url:
        abort(400, "missing url")
    decoded_for_check = up.unquote(url)
    if not _is_allowed_scheme(decoded_for_check):
        abort(400, "unsupported scheme")
    logger.info("OPEN deeplink=%s", url)
    return render_template_string(
        HTML_OPEN,
        app_name=APP_NAME,
        deep_link=url,
        deep_link_js=url,
        force_https=FORCE_HTTPS,
    )

@app.get("/copy")
def copy_page():
    text = request.args.get("text") or ""
    page = f"""<!doctype html><meta charset="utf-8"><title>Copy</title>
    <textarea style="width:100%;height:70vh">{html.escape(text)}</textarea>"""
    return page

if name == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
