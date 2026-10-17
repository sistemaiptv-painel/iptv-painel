#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
DB_FILE = os.path.join(DATA_DIR, "db.json")
HOST = os.environ.get("IPTV_HOST", "0.0.0.0")
PORT = int(os.environ.get("IPTV_PORT", "8000"))
LOCK = threading.RLock()
SESSIONS = {}
RESET_TOKENS = {}

os.makedirs(DATA_DIR, exist_ok=True)

def read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def write_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def make_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210000)
    return {"salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(digest).decode(), "iterations": 210000}

def check_password(password, stored):
    try:
        salt = base64.b64decode(stored["salt"])
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(stored.get("iterations", 210000)))
        return hmac.compare_digest(base64.b64encode(digest).decode(), stored["hash"])
    except Exception:
        return False

def auth_data():
    return read_json(AUTH_FILE, {})

def valid_credentials(body):
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not email or "@" not in email:
        return None, "Informe um e-mail válido."
    if len(password) < 8:
        return None, "A senha deve ter pelo menos 8 caracteres."
    return (email, password), None

def json_response(handler, status, payload, extra_headers=None):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(data)))
    if extra_headers:
        for key, value in extra_headers.items(): handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(data)

def new_session(email):
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"email": email, "created": time.time()}
    return token

class Handler(BaseHTTPRequestHandler):
    server_version = "IPTVManagerLocal/1.0"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def cookies(self):
        c = SimpleCookie(); c.load(self.headers.get("Cookie", "")); return c

    def current_email(self):
        morsel = self.cookies().get("iptv_session")
        if not morsel: return None
        session = SESSIONS.get(morsel.value)
        return session.get("email") if session else None

    def require_auth(self):
        email = self.current_email()
        if not email:
            json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "Sessão expirada. Entre novamente."})
            return None
        return email

    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try: return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError: return {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/auth/status":
            auth = auth_data(); email = self.current_email()
            return json_response(self, HTTPStatus.OK, {"configured": bool(auth.get("email")), "authenticated": bool(email), "email": email or auth.get("email", "")})
        if path == "/api/db":
            if not self.require_auth(): return
            with LOCK: db = read_json(DB_FILE, {})
            return json_response(self, HTTPStatus.OK, db)
        if path in ("/", "/index.html"):
            return self.serve_file("index.html", "text/html; charset=utf-8")
        return self.serve_file(path.lstrip("/"), None)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.body()
        if path == "/api/auth/setup":
            with LOCK:
                if auth_data().get("email"):
                    return json_response(self, HTTPStatus.CONFLICT, {"error": "O acesso já foi cadastrado. Faça login."})
                creds, error = valid_credentials(body)
                if error: return json_response(self, HTTPStatus.BAD_REQUEST, {"error": error})
                email, password = creds; write_json(AUTH_FILE, {"email": email, "password": make_password(password), "createdAt": time.time()})
            return self.login_response(email)
        if path == "/api/auth/login":
            auth = auth_data(); creds, error = valid_credentials(body)
            if error or not auth.get("email") or not creds or creds[0] != auth.get("email") or not check_password(creds[1], auth.get("password", {})):
                return json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "E-mail ou senha incorretos."})
            return self.login_response(creds[0])
        if path == "/api/auth/logout":
            morsel = self.cookies().get("iptv_session")
            if morsel: SESSIONS.pop(morsel.value, None)
            return json_response(self, HTTPStatus.OK, {"ok": True}, {"Set-Cookie": "iptv_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"})
        if path == "/api/auth/change":
            email = self.require_auth()
            if not email: return
            creds, error = valid_credentials(body)
            if error: return json_response(self, HTTPStatus.BAD_REQUEST, {"error": error})
            new_email, password = creds
            with LOCK:
                write_json(AUTH_FILE, {"email": new_email, "password": make_password(password), "updatedAt": time.time()})
            return json_response(self, HTTPStatus.OK, {"email": new_email})
        if path == "/api/auth/forgot":
            auth = auth_data(); email = str(body.get("email", "")).strip().lower()
            if not auth.get("email") or email != auth.get("email"):
                return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "E-mail não encontrado."})
            token = secrets.token_urlsafe(24); RESET_TOKENS[token] = {"email": email, "expires": time.time() + 3600}
            print("\nLINK LOCAL DE RECUPERAÇÃO (válido por 1 hora): http://localhost:%d/?reset=%s\n" % (PORT, token))
            return json_response(self, HTTPStatus.OK, {"message": "Link de recuperação gerado. Veja o endereço no terminal do servidor."})
        if path == "/api/auth/reset":
            token = str(body.get("token", "")); item = RESET_TOKENS.get(token)
            creds, error = valid_credentials(body)
            if not item or item["expires"] < time.time(): return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Link inválido ou expirado."})
            if error: return json_response(self, HTTPStatus.BAD_REQUEST, {"error": error})
            with LOCK: write_json(AUTH_FILE, {"email": item["email"], "password": make_password(creds[1]), "updatedAt": time.time()})
            RESET_TOKENS.pop(token, None)
            return json_response(self, HTTPStatus.OK, {"ok": True})
        if path == "/api/db":
            if not self.require_auth(): return
            if not isinstance(body, dict): return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Banco inválido."})
            body.setdefault("meta", {})["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            with LOCK: write_json(DB_FILE, body)
            return json_response(self, HTTPStatus.OK, {"ok": True})
        return json_response(self, HTTPStatus.NOT_FOUND, {"error": "Rota não encontrada."})

    def login_response(self, email):
        token = new_session(email)
        return json_response(self, HTTPStatus.OK, {"ok": True, "email": email}, {"Set-Cookie": f"iptv_session={token}; Max-Age=2592000; Path=/; HttpOnly; SameSite=Lax"})

    def serve_file(self, name, content_type):
        if name not in ("index.html", "favicon.ico") or not os.path.isfile(os.path.join(ROOT, name)):
            return json_response(self, HTTPStatus.NOT_FOUND, {"error": "Arquivo não encontrado."})
        path = os.path.join(ROOT, name)
        with open(path, "rb") as f: data = f.read()
        self.send_response(HTTPStatus.OK); self.send_header("Content-Type", content_type or "application/octet-stream"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

if __name__ == "__main__":
    print("IPTV Manager local ativo em http://localhost:%d" % PORT)
    print("Os dados ficam em: %s" % DATA_DIR)
    print("Para abrir em outro computador da mesma rede, use o IP deste PC e a porta %d." % PORT)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
