"""Server-side tests. Encryption itself is browser-side (static/crypto.js)."""
import io
import os
import re
import time

os.environ["SKIP_DOTENV"] = "1"  # never pick up a developer's real .env

import app as m

m.limiter.enabled = False
m.app.config["EMAIL_SYNC"] = True
BLOB = b"\x00opaque-ciphertext\xff" * 10
sent = []  # captured outgoing emails: (to, subject, body)
m.send_message = lambda to, subject, body: sent.append((to, subject, body))


def new_client():
    return m.app.test_client()


def csrf(c, path="/login"):
    html = c.get(path).get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def register(c, name, email=None, pw="correct-horse", confirm=None):
    return c.post("/register", data={
        "_csrf": csrf(c, "/register"), "username": name, "email": email or f"{name.lower()}@example.com",
        "password": pw, "confirm": pw if confirm is None else confirm})


def last_link(to):
    mails = [s for s in sent if s[0] == to]
    return re.search(r"https?://\S+", mails[-1][2]).group(0)


def expire_cooldown():
    with m.app.app_context():
        m.db().execute("UPDATE tokens SET created_at=created_at-1000")
        m.db().commit()


def up(c, **kw):
    d = {"blob": (io.BytesIO(BLOB), "data.bin"), "hours": "1", "max_downloads": "1", **kw}
    r = c.post("/upload", data=d, content_type="multipart/form-data", headers={"X-CSRF-Token": csrf(c, "/dashboard")})
    assert r.status_code == 200, (r.status_code, r.get_data(as_text=True))
    j = r.get_json()
    return j["link"].rsplit("/", 1)[1], j["delete_link"]


def sign_in(c, name, pw="correct-horse"):
    return c.post("/login", data={"_csrf": csrf(c), "username": name, "password": pw})


alice, bob, anon = new_client(), new_client(), new_client()

# --- registration validation
assert register(anon, "ab").status_code == 400                                  # username too short
assert register(anon, "valid_name", pw="short").status_code == 400
assert register(anon, "valid_name", confirm="different").status_code == 400
assert register(anon, "bad name!").status_code == 400
assert register(anon, "valid_name", email="not-an-email").status_code == 400
assert register(alice, "alice").status_code == 302
assert register(anon, "ALICE", email="other@example.com").status_code == 400   # usernames case-insensitive
assert register(anon, "alice2", email="ALICE@example.com").status_code == 400  # emails case-insensitive
assert register(bob, "bob").status_code == 302
with m.app.app_context():
    h = m.db().execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
    assert "correct-horse" not in h and h.startswith(("scrypt:", "pbkdf2:"))

# --- email verification
assert len([s for s in sent if s[0] == "alice@example.com"]) == 1
r = alice.post("/upload", data={"blob": (io.BytesIO(BLOB), "d"), "hours": "100", "max_downloads": "50"},
               content_type="multipart/form-data", headers={"X-CSRF-Token": csrf(alice, "/dashboard")})
assert r.status_code == 200 and r.get_json()["hours"] == 24 and r.get_json()["max_downloads"] == 10  # unverified: tighter limits
assert "Verify your email" in alice.get("/dashboard").get_data(as_text=True)
v_link = last_link("alice@example.com")
assert v_link.startswith("http://localhost/verify/")                               # built from trusted base URL
assert anon.get(v_link).status_code == 200                                        # no login needed to click the link
assert anon.get(v_link).status_code == 400                                        # single use
assert anon.get("/verify/not-a-real-token").status_code == 400
tok, _ = up(alice)                                                                # now allowed
assert (m.STORAGE / tok).exists()

# bob verifies too
assert anon.get(last_link("bob@example.com")).status_code == 200

# expired verification link
expire_cooldown()
assert alice.post("/account", data={"_csrf": csrf(alice, "/account"), "action": "change",
                                    "email": "alice.new@example.com", "password": "correct-horse"}).status_code == 302
with m.app.app_context():
    m.db().execute("UPDATE tokens SET expires_at=strftime('%s','now')-10 WHERE used=0 AND kind='verify'")
    m.db().commit()
assert anon.get(last_link("alice.new@example.com")).status_code == 400
# changing email requires the password, a valid unused address, and re-verification
assert alice.post("/account", data={"_csrf": csrf(alice, "/account"), "action": "change",
                                    "email": "x@example.com", "password": "wrong"}).status_code == 400
assert alice.post("/account", data={"_csrf": csrf(alice, "/account"), "action": "change",
                                    "email": "bob@example.com", "password": "correct-horse"}).status_code == 400
# resend: cooldown first, then a fresh working link
before = len(sent)
alice.post("/account", data={"_csrf": csrf(alice, "/account"), "action": "resend"})
assert len(sent) == before                                                        # inside cooldown: nothing sent
expire_cooldown()
alice.post("/account", data={"_csrf": csrf(alice, "/account"), "action": "resend"})
assert len(sent) == before + 1
assert anon.get(last_link("alice.new@example.com")).status_code == 200
j = alice.post("/upload", data={"blob": (io.BytesIO(BLOB), "d"), "hours": "100", "max_downloads": "50"},
               content_type="multipart/form-data", headers={"X-CSRF-Token": csrf(alice, "/dashboard")}).get_json()
assert j["hours"] == 100 and j["max_downloads"] == 50                             # verified: full limits
# an old link can't verify a newer address
assert anon.get(v_link).status_code == 400


# --- login / logout / open redirect
c = new_client()
assert c.post("/login", data={"_csrf": csrf(c), "username": "alice", "password": "wrong"}).status_code == 401
assert c.post("/login", data={"_csrf": csrf(c), "username": "nobody", "password": "x"}).status_code == 401
r = c.post("/login", data={"_csrf": csrf(c), "username": "alice", "password": "correct-horse", "next": "//evil.com"})
assert r.status_code == 302 and "evil.com" not in r.headers["Location"]
assert c.get("/dashboard").status_code == 200
assert c.post("/logout", data={"_csrf": csrf(c, "/dashboard")}).status_code == 302
assert c.get("/dashboard").status_code == 302

# --- password reset
n = len(sent)
unknown = anon.post("/forgot", data={"_csrf": csrf(anon, "/forgot"), "email": "nobody@example.com"})
known = anon.post("/forgot", data={"_csrf": csrf(anon, "/forgot"), "email": "Bob@Example.com"})
assert unknown.status_code == known.status_code == 200
assert unknown.get_data() == known.get_data()                                     # no account enumeration
assert len(sent) == n + 1 and sent[-1][0] == "bob@example.com"
reset_link = last_link("bob@example.com")
assert reset_link.startswith("http://localhost/reset/")
assert bob.get("/dashboard").status_code == 200                                   # bob signed in before the reset
# cooldown: a second request right away sends nothing
anon.post("/forgot", data={"_csrf": csrf(anon, "/forgot"), "email": "bob@example.com"})
assert len(sent) == n + 1
# validation on the reset form
path = reset_link.replace("http://localhost", "")
assert anon.get(path).status_code == 200
assert anon.post(path, data={"_csrf": csrf(anon, path), "password": "short", "confirm": "short"}).status_code == 400
assert anon.post(path, data={"_csrf": csrf(anon, path), "password": "brand-new-pass",
                             "confirm": "mismatch-pass"}).status_code == 400
assert anon.post(path, data={"_csrf": csrf(anon, path), "password": "brand-new-pass",
                             "confirm": "brand-new-pass"}).status_code == 302
assert anon.get(path).status_code == 400                                          # single use
assert bob.get("/dashboard").status_code == 302                                   # old sessions are signed out
assert sign_in(new_client(), "bob", "correct-horse").status_code == 401           # old password dead
assert sign_in(new_client(), "bob", "brand-new-pass").status_code == 302
# expired reset link
expire_cooldown()
anon.post("/forgot", data={"_csrf": csrf(anon, "/forgot"), "email": "bob@example.com"})
with m.app.app_context():
    m.db().execute("UPDATE tokens SET expires_at=strftime('%s','now')-10 WHERE used=0 AND kind='reset'")
    m.db().commit()
assert anon.get(last_link("bob@example.com").replace("http://localhost", "")).status_code == 400
# a reset link is not a verify link and vice versa
assert anon.get("/verify/" + last_link("bob@example.com").rsplit("/", 1)[1]).status_code == 400

# --- host header poisoning can't redirect reset links
n = len(sent)
expire_cooldown()
anon.post("/forgot", data={"_csrf": csrf(anon, "/forgot"), "email": "bob@example.com"},
          headers={"Host": "evil.example"})
assert not any("evil.example" in s[2] for s in sent)

bob = new_client(); sign_in(bob, "bob", "brand-new-pass")

# --- CSRF: state-changing POSTs without a token are refused
assert alice.post("/logout").status_code == 400
assert alice.post("/upload", data={"blob": (io.BytesIO(BLOB), "d")}, content_type="multipart/form-data").status_code == 400
assert anon.post("/forgot", data={"email": "bob@example.com"}).status_code == 400

# --- anonymous quick sharing: no account, no verification, tighter limits
assert anon.get("/").status_code == 200
r = anon.post("/upload", data={"blob": (io.BytesIO(BLOB), "d"), "hours": "100", "max_downloads": "50"},
              content_type="multipart/form-data", headers={"X-CSRF-Token": csrf(anon)})
assert r.status_code == 200 and r.get_json()["hours"] == 24 and r.get_json()["max_downloads"] == 10
assert anon.post("/upload", data={"blob": (io.BytesIO(BLOB), "d")},
                 content_type="multipart/form-data").status_code == 400            # CSRF still enforced
atok = r.get_json()["link"].rsplit("/", 1)[1]
assert anon.get("/dashboard").status_code == 302                                  # dashboard still needs an account
assert atok not in alice.get("/dashboard").get_data(as_text=True)
assert anon.post(f"/d/{atok}/blob").data == BLOB                                  # anyone with the link can download
assert anon.get(r.get_json()["delete_link"]).status_code in (200, 404)

# --- upload, dashboard, public download (no account needed), limits
tok, _ = up(alice)
assert (m.STORAGE / tok).read_bytes() == BLOB
page = alice.get("/dashboard").get_data(as_text=True)
assert tok in page and "0 / 1" in page
assert anon.get(f"/d/{tok}").status_code == 200
assert anon.post(f"/d/{tok}/blob").data == BLOB
assert anon.get(f"/d/{tok}").status_code == 404                                   # limit reached, file purged
assert "download" in alice.get("/dashboard").get_data(as_text=True)

# --- isolation between users
tok_a, _ = up(alice, max_downloads="5")
assert tok_a not in bob.get("/dashboard").get_data(as_text=True)
assert bob.post(f"/dashboard/delete/{tok_a}", data={"_csrf": csrf(bob, "/dashboard")}).status_code == 404
assert (m.STORAGE / tok_a).exists()

# --- owner deletes from the dashboard
r = alice.post(f"/dashboard/delete/{tok_a}", data={"_csrf": csrf(alice, "/dashboard")})
assert r.status_code == 302 and not (m.STORAGE / tok_a).exists()
assert anon.get(f"/d/{tok_a}").status_code == 404

# --- secret delete link still works and needs the right token
tok, dl = up(alice)
assert anon.get(dl[:-3] + "bad").status_code == 403
assert anon.get(dl).status_code == 200 and anon.get(f"/d/{tok}").status_code == 404

# --- bad input
assert alice.post("/upload", data={}, content_type="multipart/form-data",
                  headers={"X-CSRF-Token": csrf(alice, "/dashboard")}).status_code == 400
# --- anonymous storage quotas
def anon_up(c, ip="127.0.0.1"):
    return c.post("/upload", data={"blob": (io.BytesIO(BLOB), "d"), "hours": "1"}, content_type="multipart/form-data",
                  headers={"X-CSRF-Token": csrf(c)}, environ_base={"REMOTE_ADDR": ip})


def usage():
    with m.app.app_context():
        return m.db().execute("SELECT COALESCE(SUM(size),0) FROM blobs WHERE anon=1").fetchone()[0]


old_ip, old_total = m.ANON_IP_QUOTA, m.ANON_TOTAL_QUOTA
try:
    # per-IP quota: room for exactly two more files from this IP
    with m.app.app_context():
        mine = m.db().execute("SELECT COALESCE(SUM(size),0) FROM blobs WHERE anon=1 AND uploader_ip='10.0.0.1'").fetchone()[0]
    m.ANON_IP_QUOTA = mine + 2 * (len(BLOB) + 0)
    assert anon_up(anon, "10.0.0.1").status_code == 200
    assert anon_up(anon, "10.0.0.1").status_code == 200
    r = anon_up(anon, "10.0.0.1")
    assert r.status_code == 413 and "Quota" in r.get_json()["error"]
    assert anon_up(anon, "10.0.0.2").status_code == 200                             # other IPs unaffected
    # a verified account is exempt from the anonymous quota
    assert alice.post("/upload", data={"blob": (io.BytesIO(BLOB), "d")}, content_type="multipart/form-data",
                      headers={"X-CSRF-Token": csrf(alice, "/dashboard")},
                      environ_base={"REMOTE_ADDR": "10.0.0.1"}).status_code == 200
    # deleting frees the space again
    with m.app.app_context():
        t = m.db().execute("SELECT token FROM blobs WHERE uploader_ip='10.0.0.1' AND anon=1").fetchone()[0]
    r = anon_up(anon, "10.0.0.3")
    j = r.get_json()
    anon.get(j["delete_link"])
    m.ANON_IP_QUOTA = old_ip
    # global quota: no room left at all for anonymous files
    m.ANON_TOTAL_QUOTA = usage()
    r = anon_up(anon, "10.0.0.4")
    assert r.status_code == 507 and "full" in r.get_json()["error"]
    assert anon.post("/upload", data={"blob": (io.BytesIO(BLOB), "d")}, content_type="multipart/form-data",
                     headers={"X-CSRF-Token": csrf(alice, "/dashboard")}).status_code == 400  # (csrf mismatch, still rejected)
    m.ANON_TOTAL_QUOTA = usage() + len(BLOB)
    assert anon_up(anon, "10.0.0.4").status_code == 200
    assert anon_up(anon, "10.0.0.4").status_code == 507
finally:
    m.ANON_IP_QUOTA, m.ANON_TOTAL_QUOTA = old_ip, old_total
# --- Sign in with Google (Google's servers are replaced by a fake)
import base64
import hashlib
import urllib.error
import urllib.parse

real_http_json = m.http_json
assert anon.get("/auth/google").status_code == 404                                # off until configured
assert "Continue with Google" not in anon.get("/login").get_data(as_text=True)
os.environ["GOOGLE_CLIENT_ID"], os.environ["GOOGLE_CLIENT_SECRET"] = "test-client-id", "test-client-secret"
assert "Continue with Google" in anon.get("/login").get_data(as_text=True)
assert "Continue with Google" in anon.get("/register").get_data(as_text=True)


def google_signin(c, info, nxt=None, code="good-code"):
    """Runs the whole flow; returns the callback response."""
    r = c.get("/auth/google" + (f"?next={nxt}" if nxt else ""))
    assert r.status_code == 302
    q = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["Location"]).query)
    assert r.headers["Location"].startswith(m.GOOGLE_AUTH_URL)
    assert q["client_id"] == ["test-client-id"] and q["code_challenge_method"] == ["S256"]
    assert q["redirect_uri"] == ["http://localhost/auth/google/callback"] and "email" in q["scope"][0]

    def fake(url, data=None, headers=None):
        if url == m.GOOGLE_TOKEN_URL:
            assert data["code"] == "good-code" and data["client_secret"] == "test-client-secret"
            challenge = base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"].encode()).digest()).rstrip(b"=")
            assert challenge.decode() == q["code_challenge"][0]                     # PKCE verifier matches
            assert data["redirect_uri"] == q["redirect_uri"][0]
            return {"access_token": "tok"}
        assert url == m.GOOGLE_USERINFO_URL and headers["Authorization"] == "Bearer tok"
        return info

    m.http_json = fake
    return c.get("/auth/google/callback", query_string={"state": q["state"][0], "code": code})


def info(sub, email, verified=True, name="Test Person"):
    return {"sub": sub, "email": email, "email_verified": verified, "name": name}


def user_row(email):
    with m.app.app_context():
        return m.db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()


# a brand-new Google user is created, verified, and gets the verified-account limits
dave = new_client()
r = google_signin(dave, info("sub-dave", "dave.smith@example.com"))
assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
row = user_row("dave.smith@example.com")
assert row["email_verified"] == 1 and row["google_sub"] == "sub-dave" and row["username"] == "dave.smith"
j = dave.post("/upload", data={"blob": (io.BytesIO(BLOB), "d"), "hours": "100"}, content_type="multipart/form-data",
              headers={"X-CSRF-Token": csrf(dave, "/dashboard")}).get_json()
assert j["hours"] == 100
assert not any(s[0] == "dave.smith@example.com" for s in sent)                    # no verification email needed
# signing in again with the same Google account reuses the user (even if the email changed on Google's side)
again = new_client()
assert google_signin(again, info("sub-dave", "renamed@example.com")).status_code == 302
assert again.get("/dashboard").status_code == 200
with m.app.app_context():
    assert m.db().execute("SELECT COUNT(*) FROM users WHERE google_sub='sub-dave'").fetchone()[0] == 1
# a Google-only account has no usable password
assert sign_in(new_client(), "dave.smith", "anything-at-all").status_code == 401
# username collisions get a suffix
other = new_client()
google_signin(other, info("sub-dave2", "dave.smith@other.org"))
assert user_row("dave.smith@other.org")["username"] not in ("dave.smith", "")

# unverified Google email, missing email, user cancelling and bad state are all refused
n_users = lambda: m.sqlite3.connect(m.DB_PATH).execute("SELECT COUNT(*) FROM users").fetchone()[0]
before = n_users()
assert google_signin(new_client(), info("sub-x", "x@example.com", verified=False)).status_code == 400
assert google_signin(new_client(), {"sub": "sub-y"}).status_code == 400
c = new_client()
c.get("/auth/google")
assert c.get("/auth/google/callback", query_string={"state": "forged", "code": "good-code"}).status_code == 400
assert new_client().get("/auth/google/callback", query_string={"state": "x", "code": "y"}).status_code == 400
assert c.get("/auth/google/callback", query_string={"error": "access_denied"}).status_code == 400
assert n_users() == before


def broken(url, data=None, headers=None):
    raise urllib.error.URLError("google unreachable")


c = new_client()
q = urllib.parse.parse_qs(urllib.parse.urlparse(c.get("/auth/google").headers["Location"]).query)
m.http_json = broken
assert c.get("/auth/google/callback", query_string={"state": q["state"][0], "code": "good-code"}).status_code == 502
# the state is single-use
assert c.get("/auth/google/callback", query_string={"state": q["state"][0], "code": "good-code"}).status_code == 400

# open redirect through ?next= is neutralised
r = google_signin(new_client(), info("sub-dave", "dave.smith@example.com"), nxt="//evil.example")
assert "evil.example" not in r.headers["Location"]

# account takeover protection: linking to an UNVERIFIED local account locks the squatter out
carol_squatter = new_client()
assert register(carol_squatter, "carol", email="carol@example.com").status_code == 302
assert carol_squatter.get("/dashboard").status_code == 200
real_carol = new_client()
assert google_signin(real_carol, info("sub-carol", "carol@example.com")).status_code == 302
assert user_row("carol@example.com")["email_verified"] == 1 and user_row("carol@example.com")["google_sub"] == "sub-carol"
assert carol_squatter.get("/dashboard").status_code == 302                          # squatter's session is dead
assert sign_in(new_client(), "carol", "correct-horse").status_code == 401           # squatter's password is dead
assert real_carol.get("/dashboard").status_code == 200

# linking to a VERIFIED local account keeps its password
assert google_signin(new_client(), info("sub-bob", "bob@example.com")).status_code == 302
assert user_row("bob@example.com")["google_sub"] == "sub-bob"
assert sign_in(new_client(), "bob", "brand-new-pass").status_code == 302

m.http_json = real_http_json
del os.environ["GOOGLE_CLIENT_ID"], os.environ["GOOGLE_CLIENT_SECRET"]
assert anon.get("/auth/google").status_code == 404

# --- deployment helpers
assert anon.get("/healthz").get_data(as_text=True) == "ok"
assert m.env("DEFINITELY_NOT_SET_VAR", "fallback") == "fallback"
import os
os.environ["EMPTY_VAR_FOR_TEST"] = ""
assert m.env("EMPTY_VAR_FOR_TEST", "fallback") == "fallback"                      # compose passes empty strings
print("all tests passed")
