"""SecureShare: end-to-end encrypted file sharing with accounts and a dashboard.

Encryption happens in the browser (static/crypto.js, Web Crypto AES-256-GCM).
The server only ever stores an opaque ciphertext blob: it never sees the file,
its name, or the key. The key lives in the share link's #fragment, which
browsers never send to the server. With a password, the AES key is derived
from the password (PBKDF2) with the fragment key as salt, so the link alone
is not enough to decrypt.

Accounts: you must be signed in to upload. Downloading needs only the link.
The server enforces expiry and download limits and keeps an audit log that
owners can see on their dashboard.
"""
import base64
import functools
import hashlib
import io
import json
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request, send_file,
                   session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).parent


def env(name: str, default: str = "") -> str:
    """Environment variable with a default; empty values count as unset (docker compose passes empty strings)."""
    return os.environ.get(name) or default


def load_dotenv(path: Path) -> None:
    """Minimal .env loader for local runs. Real environment variables win; Docker passes those instead."""
    if os.environ.get("SKIP_DOTENV") or not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


load_dotenv(BASE / ".env")

# Everything the app writes (database, encrypted files, session key, dev mail) lives under DATA_DIR.
DATA = Path(env("DATA_DIR", str(BASE)))
STORAGE = DATA / "storage"
DB_PATH = DATA / "secureshare.db"
SECRET_PATH = DATA / "secret.key"
MAX_BYTES = 25 * 1024 * 1024
MAX_EXPIRY_HOURS = 24 * 7
MAX_DOWNLOADS = 100
ANON_MAX_HOURS = 24
ANON_MAX_DOWNLOADS = 10
# Storage quotas for anonymous-tier uploads (anonymous and unverified users), in megabytes.
ANON_TOTAL_QUOTA = int(float(env("ANON_TOTAL_QUOTA_MB", "1024")) * 2**20)  # all anonymous files together
ANON_IP_QUOTA = int(float(env("ANON_IP_QUOTA_MB", "100")) * 2**20)         # per uploader IP
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD = 8
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VERIFY_TTL = 24 * 3600
RESET_TTL = 3600
TOKEN_COOLDOWN = 60  # seconds between emails of the same kind for one account
OUTBOX_PATH = DATA / "outbox.log"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
# Verified against when a username does not exist, so timing doesn't reveal valid usernames.
DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


def load_secret() -> bytes:
    if env("SECRET_KEY"):
        return env("SECRET_KEY").encode()
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(secrets.token_bytes(32))
        try:
            os.chmod(SECRET_PATH, 0o600)
        except OSError:
            pass
    return SECRET_PATH.read_bytes()


STORAGE.mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret(),
    MAX_CONTENT_LENGTH=MAX_BYTES + 4096,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(env("SECURE_COOKIES")),  # set when served over HTTPS
    PERMANENT_SESSION_LIFETIME=7 * 24 * 3600,
)
if env("TRUST_PROXY"):
    # Behind one reverse proxy: use its X-Forwarded-* headers so rate limits and quotas see the real client IP.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"], storage_uri="memory://")


# ---------- database ----------
def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.executescript("""
            CREATE TABLE IF NOT EXISTS users(
              id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL, created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS blobs(
              token TEXT PRIMARY KEY, delete_token TEXT NOT NULL, size INTEGER NOT NULL,
              expires_at REAL NOT NULL, max_downloads INTEGER NOT NULL,
              downloads INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS audit(
              id INTEGER PRIMARY KEY, ts REAL, token TEXT, event TEXT, ip TEXT);
            CREATE TABLE IF NOT EXISTS tokens(
              token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT NOT NULL, email TEXT,
              expires_at REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL);
        """)
        # Migrate databases created by earlier versions.
        for table, col, decl in (("blobs", "user_id", "INTEGER"), ("audit", "user_id", "INTEGER"),
                                 ("users", "email", "TEXT"),
                                 ("users", "email_verified", "INTEGER NOT NULL DEFAULT 0"),
                                 ("users", "session_version", "INTEGER NOT NULL DEFAULT 0"), ("users", "google_sub", "TEXT"),
                                 ("blobs", "anon", "INTEGER NOT NULL DEFAULT 0"), ("blobs", "uploader_ip", "TEXT")):
            cols = [r["name"] for r in g.db.execute(f"PRAGMA table_info({table})")]
            if col not in cols:
                g.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        g.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users(email COLLATE NOCASE)")
        g.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_google ON users(google_sub)")
        g.db.commit()
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def log(token: str, event: str, user_id=None):
    db().execute("INSERT INTO audit(ts,token,event,ip,user_id) VALUES(?,?,?,?,?)",
                 (time.time(), token, event, request.remote_addr, user_id))
    db().commit()


def remove(token: str):
    (STORAGE / token).unlink(missing_ok=True)
    db().execute("DELETE FROM blobs WHERE token=?", (token,))
    db().commit()


def purge_expired():
    for r in db().execute("SELECT token FROM blobs WHERE expires_at<? OR downloads>=max_downloads",
                          (time.time(),)).fetchall():
        remove(r["token"])


def get_blob(token: str):
    purge_expired()
    row = db().execute("SELECT * FROM blobs WHERE token=?", (token,)).fetchone()
    if not row:
        abort(404)
    return row


# ---------- auth & CSRF ----------
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST" and request.endpoint not in ("download_blob",):
        sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = db().execute("SELECT id, username, email, email_verified, session_version FROM users WHERE id=?",
                              (uid,)).fetchone()
        # A password reset bumps session_version, signing out every existing session.
        if g.user is None or g.user["session_version"] != session.get("sv"):
            g.user = None
            session.pop("uid", None)


app.jinja_env.globals["current_user"] = lambda: g.user


def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            if request.endpoint == "upload":
                return jsonify(error="Please sign in to upload."), 401
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*a, **kw)
    return wrapped


def safe_next(target: str) -> str:
    """Only allow same-site relative redirects."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("dashboard")


def start_session(user_id: int, version: int = 0):
    session.clear()
    session["uid"] = user_id
    session["sv"] = version
    session.permanent = True


# ---------- email ----------
def send_message(to: str, subject: str, body: str):
    """Sends via SMTP when SMTP_HOST is set; otherwise writes to outbox.log (development)."""
    host = env("SMTP_HOST")
    if not host:
        with OUTBOX_PATH.open("a", encoding="utf-8") as fh:
            fh.write(f"--- {datetime.now(timezone.utc).isoformat()} ---\nTo: {to}\nSubject: {subject}\n\n{body}\n\n")
        print(f"[dev mail] to={to} subject={subject!r} (see outbox.log)", flush=True)
        return
    msg = EmailMessage()
    msg["From"] = env("SMTP_FROM", env("SMTP_USER", "noreply@localhost"))
    msg["To"], msg["Subject"] = to, subject
    msg.set_content(body)
    port = int(env("SMTP_PORT", "587"))
    if env("SMTP_TLS", "starttls") == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        server = smtplib.SMTP(host, port, timeout=15)
    with server:
        if env("SMTP_TLS", "starttls") == "starttls":
            server.starttls()
        if env("SMTP_USER"):
            server.login(env("SMTP_USER"), env("SMTP_PASSWORD").replace(" ", ""))
        server.send_message(msg)


def dispatch_email(to: str, subject: str, body: str):
    """Sends in the background so response time doesn't reveal whether an address exists."""
    def run():
        try:
            send_message(to, subject, body)
        except Exception as exc:  # never let a mail failure break the request
            print(f"[mail error] {exc!r}", flush=True)
    if app.config.get("EMAIL_SYNC"):
        run()
    else:
        threading.Thread(target=run, daemon=True).start()


def base_url() -> str:
    """Absolute site URL for email links. Never trust the Host header for these."""
    configured = env("BASE_URL")
    if configured:
        return configured.rstrip("/")
    if request.host.split(":")[0] in ("127.0.0.1", "localhost", "[::1]"):
        return request.host_url.rstrip("/")
    raise RuntimeError("Set the BASE_URL environment variable (for example https://share.example.com) "
                       "before serving on a non-local address.")


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_token(user_id: int, kind: str, ttl: int, email=None):
    """Returns a raw single-use token, or None while inside the resend cooldown."""
    now = time.time()
    db().execute("DELETE FROM tokens WHERE expires_at<?", (now - 86400,))
    recent = db().execute("SELECT 1 FROM tokens WHERE user_id=? AND kind=? AND created_at>?",
                          (user_id, kind, now - TOKEN_COOLDOWN)).fetchone()
    if recent:
        return None
    raw = secrets.token_urlsafe(32)
    db().execute("INSERT INTO tokens(token_hash,user_id,kind,email,expires_at,created_at) VALUES(?,?,?,?,?,?)",
                 (hash_token(raw), user_id, kind, email, now + ttl, now))
    db().commit()
    return raw


def find_token(raw: str, kind: str):
    return db().execute("SELECT * FROM tokens WHERE token_hash=? AND kind=? AND used=0 AND expires_at>?",
                        (hash_token(raw), kind, time.time())).fetchone()


def send_verification(user_id: int, username: str, email: str) -> bool:
    raw = create_token(user_id, "verify", VERIFY_TTL, email)
    if raw is None:
        return False
    link = base_url() + url_for("verify", token=raw)
    dispatch_email(email, "Verify your SecureShare email",
                   f"Hi {username},\n\nConfirm this email address to unlock higher sharing limits:\n\n{link}\n\n"
                   "The link works once and expires in 24 hours. If you didn't create this account, ignore this email.\n")
    return True


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = None
        if not USERNAME_RE.match(username):
            error = "Username must be 3-32 characters: letters, numbers, . _ -"
        elif not EMAIL_RE.match(email) or len(email) > 254:
            error = "Enter a valid email address."
        elif len(password) < MIN_PASSWORD:
            error = f"Password must be at least {MIN_PASSWORD} characters."
        elif password != request.form.get("confirm", ""):
            error = "Passwords do not match."
        elif db().execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            error = "That username is taken."
        elif db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            error = "That email is already registered. Try signing in or resetting your password."
        if error:
            return render_template("register.html", error=error, username=username, email=email), 400
        cur = db().execute("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                           (username, email, generate_password_hash(password), time.time()))
        db().commit()
        start_session(cur.lastrowid, 0)
        send_verification(cur.lastrowid, username, email)
        flash("Account created. Check your email for a verification link to unlock higher sharing limits.")
        return redirect(url_for("dashboard"))
    return render_template("register.html", error=None, username="", email="")


@app.get("/verify/<token>")
def verify(token):
    row = find_token(token, "verify")
    if row:
        user = db().execute("SELECT email FROM users WHERE id=?", (row["user_id"],)).fetchone()
        # Only valid if the account's email hasn't changed since this link was sent.
        if user and user["email"] == row["email"]:
            db().execute("UPDATE users SET email_verified=1 WHERE id=?", (row["user_id"],))
            db().execute("UPDATE tokens SET used=1 WHERE token_hash=?", (hash_token(token),))
            db().commit()
            load_user()  # refresh g.user so the "verify your email" banner disappears on this page
            return render_template("message.html", title="Email verified",
                                   text="Thanks! Your email is verified: you now get longer expiry and higher download limits.", ok=True)
    return render_template("message.html", title="Link not valid",
                           text="This verification link is invalid, already used, or expired. Request a new one from your account page.",
                           ok=False), 400


@app.route("/account", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def account():
    """Email status, resend verification, and change email."""
    error = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "resend":
            u = g.user
            if u["email"] and not u["email_verified"]:
                sent = send_verification(u["id"], u["username"], u["email"])
                flash("Verification email sent." if sent else "An email was sent a moment ago. Please wait a minute.")
            return redirect(url_for("account"))
        if action == "change":
            email = request.form.get("email", "").strip().lower()
            row = db().execute("SELECT password_hash FROM users WHERE id=?", (g.user["id"],)).fetchone()
            if not check_password_hash(row["password_hash"], request.form.get("password", "")):
                error = "Wrong password."
            elif not EMAIL_RE.match(email) or len(email) > 254:
                error = "Enter a valid email address."
            elif db().execute("SELECT 1 FROM users WHERE email=? AND id<>?", (email, g.user["id"])).fetchone():
                error = "That email is already registered."
            else:
                db().execute("UPDATE users SET email=?, email_verified=0 WHERE id=?", (email, g.user["id"]))
                db().execute("UPDATE tokens SET used=1 WHERE user_id=? AND kind='verify'", (g.user["id"],))
                db().commit()
                send_verification(g.user["id"], g.user["username"], email)
                flash("Email updated. Check your inbox for a verification link.")
                return redirect(url_for("account"))
    return render_template("account.html", error=error), (400 if error else 200)


@app.route("/forgot", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db().execute("SELECT id, username, email FROM users WHERE email=?", (email,)).fetchone() if email else None
        if user:
            raw = create_token(user["id"], "reset", RESET_TTL)
            if raw:
                link = base_url() + url_for("reset", token=raw)
                dispatch_email(user["email"], "Reset your SecureShare password",
                               f"Hi {user['username']},\n\nSomeone asked to reset your password. To choose a new one, open:\n\n{link}\n\n"
                               "The link works once and expires in 1 hour. If this wasn't you, ignore this email: "
                               "your password has not changed.\n")
        # Same answer whether or not the address exists.
        return render_template("message.html", title="Check your email",
                               text="If that address belongs to an account, a reset link is on its way. It expires in 1 hour.",
                               ok=True)
    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def reset(token):
    row = find_token(token, "reset")
    if not row:
        return render_template("message.html", title="Link not valid",
                               text="This reset link is invalid, already used, or expired.", ok=False,
                               link=("/forgot", "Request a new link")), 400
    if request.method == "POST":
        password = request.form.get("password", "")
        if len(password) < MIN_PASSWORD:
            error = f"Password must be at least {MIN_PASSWORD} characters."
        elif password != request.form.get("confirm", ""):
            error = "Passwords do not match."
        else:
            # Receiving the email proves control of it; bump session_version to sign out all sessions.
            db().execute("UPDATE users SET password_hash=?, email_verified=1, session_version=session_version+1 WHERE id=?",
                         (generate_password_hash(password), row["user_id"]))
            db().execute("UPDATE tokens SET used=1 WHERE user_id=? AND kind='reset'", (row["user_id"],))
            db().commit()
            session.clear()
            flash("Password updated. Sign in with your new password.")
            return redirect(url_for("login"))
        return render_template("reset.html", token=token, error=error), 400
    return render_template("reset.html", token=token, error=None)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute;50 per hour", methods=["POST"])
def login():
    nxt = request.args.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, request.form.get("password", ""))
        if user and ok:
            start_session(user["id"], user["session_version"])
            return redirect(safe_next(request.form.get("next", "")))
        return render_template("login.html", error="Wrong username or password.", next=request.form.get("next", ""),
                               username=username), 401
    return render_template("login.html", error=None, next=nxt, username="")


# ---------- Sign in with Google (OAuth 2.0 authorization code flow + PKCE) ----------
def google_enabled() -> bool:
    return bool(env("GOOGLE_CLIENT_ID") and env("GOOGLE_CLIENT_SECRET"))


app.jinja_env.globals["google_enabled"] = google_enabled


def http_json(url: str, data=None, headers=None) -> dict:
    """POST (when data is given) or GET a URL and parse the JSON reply. Separate so tests can replace it."""
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers or {})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


def google_redirect_uri() -> str:
    return base_url() + url_for("google_callback")


@app.get("/auth/google")
@limiter.limit("30 per hour")
def google_login():
    if not google_enabled():
        abort(404)
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    session["g_state"], session["g_verifier"] = state, verifier
    session["g_next"] = safe_next(request.args.get("next", ""))
    query = urllib.parse.urlencode({
        "client_id": env("GOOGLE_CLIENT_ID"), "redirect_uri": google_redirect_uri(), "response_type": "code",
        "scope": "openid email profile", "state": state, "code_challenge": challenge,
        "code_challenge_method": "S256", "prompt": "select_account"})
    return redirect(f"{GOOGLE_AUTH_URL}?{query}")


def username_from(email: str, name: str = "") -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]", "", email.split("@")[0])[:24]
    if len(base) < 3:
        base = (re.sub(r"[^A-Za-z0-9_.-]", "", name)[:24] + "user")[:24]
    candidate = base
    while db().execute("SELECT 1 FROM users WHERE username=?", (candidate,)).fetchone():
        candidate = f"{base}{secrets.randbelow(10000):04d}"
    return candidate


def google_fail(message: str, status: int = 400):
    return render_template("message.html", title="Google sign-in failed", text=message, ok=False,
                           link=("/login", "Back to sign in")), status


@app.get("/auth/google/callback")
@limiter.limit("30 per hour")
def google_callback():
    if not google_enabled():
        abort(404)
    state, verifier = session.pop("g_state", None), session.pop("g_verifier", None)
    nxt = session.pop("g_next", None) or url_for("dashboard")
    if request.args.get("error"):
        return google_fail("Google sign-in was cancelled or refused.")
    if not state or not verifier or not secrets.compare_digest(request.args.get("state", ""), state):
        return google_fail("The sign-in request expired or didn't match. Please try again.")
    code = request.args.get("code")
    if not code:
        return google_fail("Google didn't return a sign-in code.")
    try:
        token = http_json(GOOGLE_TOKEN_URL, data={
            "client_id": env("GOOGLE_CLIENT_ID"), "client_secret": env("GOOGLE_CLIENT_SECRET"), "code": code,
            "code_verifier": verifier, "redirect_uri": google_redirect_uri(), "grant_type": "authorization_code"})
        info = http_json(GOOGLE_USERINFO_URL, headers={"Authorization": "Bearer " + token["access_token"]})
    except (urllib.error.URLError, KeyError, ValueError, OSError):
        return google_fail("Couldn't complete sign-in with Google. Please try again.", 502)

    sub, email = str(info.get("sub") or ""), str(info.get("email") or "").strip().lower()
    if not sub or not email or info.get("email_verified") is not True:
        return google_fail("Your Google account doesn't have a verified email address, so we can't use it to sign in.")

    user = db().execute("SELECT * FROM users WHERE google_sub=?", (sub,)).fetchone()
    if user is None:
        user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user is not None:
            # Link Google to the existing account. If its email was never verified, someone else may have
            # registered it (and knows its password), so lock the password and sign out its sessions.
            if not user["email_verified"]:
                db().execute("UPDATE users SET password_hash=?, session_version=session_version+1 WHERE id=?",
                             (generate_password_hash(secrets.token_urlsafe(32)), user["id"]))
            db().execute("UPDATE users SET google_sub=?, email_verified=1 WHERE id=?", (sub, user["id"]))
        else:
            cur = db().execute(
                "INSERT INTO users(username,email,email_verified,google_sub,password_hash,created_at) VALUES(?,?,1,?,?,?)",
                (username_from(email, str(info.get("name") or "")), email, sub,
                 generate_password_hash(secrets.token_urlsafe(32)), time.time()))  # unusable until they reset it
            user = db().execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        db().commit()
        user = db().execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    start_session(user["id"], user["session_version"])
    return redirect(safe_next(nxt))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/healthz")
@limiter.exempt
def healthz():
    return "ok", 200, {"Content-Type": "text/plain"}


# ---------- sharing ----------
def limits():
    """Anonymous and unverified users get tighter limits than verified accounts."""
    if g.user is not None and g.user["email_verified"]:
        return MAX_EXPIRY_HOURS, MAX_DOWNLOADS
    return ANON_MAX_HOURS, ANON_MAX_DOWNLOADS


@app.get("/")
def index():
    max_hours, max_dl = limits()
    return render_template("index.html", max_mb=MAX_BYTES // 2**20, max_hours=max_hours, max_dl=max_dl,
                           limited=max_hours < MAX_EXPIRY_HOURS)


@app.post("/upload")
@limiter.limit(lambda: "20 per hour" if limits()[0] == MAX_EXPIRY_HOURS else "10 per hour")
def upload():
    """Receives an already-encrypted blob; returns the link and delete link. No account needed."""
    max_hours, max_downloads = limits()
    owner = g.user["id"] if g.user else None
    f = request.files.get("blob")
    if not f:
        abort(400, "No data")
    data = f.read()
    if not data or len(data) > MAX_BYTES + 4096:
        abort(413)
    anon_tier = max_hours < MAX_EXPIRY_HOURS
    if anon_tier:
        purge_expired()
        total, mine = db().execute(
            "SELECT COALESCE(SUM(size),0), COALESCE(SUM(CASE WHEN uploader_ip=? THEN size END),0)"
            " FROM blobs WHERE anon=1", (request.remote_addr,)).fetchone()
        if mine + len(data) > ANON_IP_QUOTA:
            return jsonify(error=f"Quota reached: anonymous sharing allows {ANON_IP_QUOTA / 2**20:g} MB of active files "
                                 "per person. Delete a file, wait for one to expire, or sign in with a verified account."), 413
        if total + len(data) > ANON_TOTAL_QUOTA:
            return jsonify(error="Anonymous storage is full right now. Try again later, or sign in with a verified account."), 507
    try:
        hours = min(max(float(request.form.get("hours", 24)), 0.1), max_hours)
        max_dl = min(max(int(request.form.get("max_downloads", 1)), 1), max_downloads)
    except ValueError:
        abort(400, "Bad options")

    token, delete_token = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    (STORAGE / token).write_bytes(data)
    now = time.time()
    db().execute("INSERT INTO blobs(token,delete_token,size,expires_at,max_downloads,downloads,created_at,user_id,anon,uploader_ip)"
                 " VALUES(?,?,?,?,?,0,?,?,?,?)",
                 (token, delete_token, len(data), now + hours * 3600, max_dl, now, owner,
                  int(anon_tier), request.remote_addr if anon_tier else None))
    db().commit()
    log(token, "upload", owner)
    return jsonify(
        link=url_for("download_page", token=token, _external=True),
        delete_link=url_for("delete", token=token, dt=delete_token, _external=True),
        hours=hours, max_downloads=max_dl)


@app.get("/d/<token>")
def download_page(token):
    return render_template("download.html", f=get_blob(token), token=token)


@app.post("/d/<token>/blob")
@limiter.limit("30 per hour")
def download_blob(token):
    """Hands out the ciphertext and counts one download. Decryption is client-side."""
    row = get_blob(token)
    data = (STORAGE / token).read_bytes()
    db().execute("UPDATE blobs SET downloads=downloads+1 WHERE token=?", (token,))
    db().commit()
    log(token, "download", row["user_id"])
    return send_file(io.BytesIO(data), mimetype="application/octet-stream")


@app.get("/delete/<token>")
def delete(token):
    """Secret delete link given to the uploader (works without signing in)."""
    row = get_blob(token)
    if not secrets.compare_digest(request.args.get("dt", ""), row["delete_token"]):
        abort(403)
    log(token, "deleted", row["user_id"])
    remove(token)
    return render_template("deleted.html")


# ---------- dashboard ----------
@app.template_filter("dt")
def fmt_dt(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@app.template_filter("kb")
def fmt_size(n):
    return f"{n / 1024:.1f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} MB"


@app.get("/dashboard")
@login_required
def dashboard():
    purge_expired()
    uid = g.user["id"]
    files = db().execute("SELECT * FROM blobs WHERE user_id=? ORDER BY created_at DESC", (uid,)).fetchall()
    activity = db().execute("SELECT ts, token, event FROM audit WHERE user_id=? ORDER BY ts DESC, id DESC LIMIT 15",
                            (uid,)).fetchall()
    stats = {
        "active": len(files),
        "bytes": sum(f["size"] for f in files),
        "downloads": sum(f["downloads"] for f in files),
    }
    return render_template("dashboard.html", files=files, activity=activity, stats=stats, now=time.time())


@app.post("/dashboard/delete/<token>")
@login_required
def dashboard_delete(token):
    row = db().execute("SELECT * FROM blobs WHERE token=? AND user_id=?", (token, g.user["id"])).fetchone()
    if not row:
        abort(404)
    log(token, "deleted", g.user["id"])
    remove(token)
    flash("File deleted.")
    return redirect(url_for("dashboard"))


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'")
    return resp


if __name__ == "__main__":
    app.run(debug=False)
