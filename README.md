# SecureShare

End-to-end encrypted file sharing with controlled access. Files are encrypted in the sender's browser, so the server only ever stores unreadable bytes: it never sees the file, its name, or the key.

## Features

- **End-to-end encryption**: AES-256-GCM via the browser's Web Crypto API.
- **Key stays in the link**: the key is in the `#fragment` of the share link, which browsers never send to the server.
- **Optional password**: the AES key is derived from the password (PBKDF2-SHA256, 600,000 iterations) with the link key as salt, so the link alone cannot decrypt the file.
- **Quick sharing, no account**: anyone can pick a file and get a link straight away. Anonymous (and unverified) users get tighter limits: up to 24 hours, 10 downloads, and 10 uploads per hour per IP. Accounts that have verified their email get up to 7 days, 100 downloads and 20 uploads per hour.
- **Anonymous storage quotas**: active anonymous-tier files are capped at 100 MB per uploader IP and 1 GB in total (both configurable). Going over returns a clear error; space frees up as files expire, run out of downloads or are deleted. Verified accounts are exempt.
- **User accounts**: optional. They add a dashboard of your files, activity log and the higher limits; downloading never needs an account, only the link. Passwords are hashed with scrypt, sessions use signed HttpOnly SameSite cookies, and all state-changing requests are CSRF-protected.
- **Email verification**: registration requires an email and sends a single-use link (24 h). Verifying unlocks the higher limits. You can resend the link or change your email (needs your password, and re-verifies) on the Account page.
- **Password reset**: "Forgot your password?" emails a single-use link (1 h). The page gives the same answer whether or not the address has an account, and a successful reset signs out every existing session. Tokens are stored only as SHA-256 hashes, with a 60-second per-account resend cooldown.
- **Dashboard**: your active files (size, created, expiry, downloads used), totals, and a recent-activity log of uploads, downloads and deletions, with one-click delete.
- **Expiring links**: 6 minutes up to 7 days.
- **Download limits**: 1 to 100 downloads, then the file is deleted.
- **Delete link**: the uploader gets a private link to remove the file early.
- **Abuse protection**: rate limiting, 25 MB size cap, security headers (CSP, `nosniff`, no-referrer, `no-store`).
- **Audit log**: uploads, downloads and deletions are recorded in SQLite.

## Quick start

Requires Python 3.9+.

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000, pick a file, optionally set a password, expiry and download limit, and share the generated link (the whole link, including the part after `#`). Optionally register an account (and verify your email) for longer expiry, higher limits and a dashboard at `/dashboard`.

### Docker

```bash
docker compose up -d --build
```

Then open http://localhost:8000. To configure it, copy `.env.example` to `.env` and edit (compose reads it automatically): at minimum set `BASE_URL`, and `SMTP_*` to send real email.

- **Persistence**: the database, encrypted files and session key live in the `secureshare-data` volume (`/data` in the container). `docker compose down` keeps it; `docker compose down -v` deletes everything.
- **Server**: gunicorn with one worker and eight threads. Rate limits are in memory, so extra worker processes would each count separately; scale with threads, or move the limiter to Redis before adding workers.
- **Hardening**: runs as an unprivileged user with a read-only root filesystem, no capabilities and `no-new-privileges`. Only `/data` is writable.
- **Network**: published on `127.0.0.1:8000` only. For real use put a TLS-terminating reverse proxy (Caddy, nginx, Traefik) in front and set `BASE_URL=https://...`, `SECURE_COOKIES=1` and `TRUST_PROXY=1` so cookies are HTTPS-only and quotas and rate limits see real client IPs. The browser encryption API needs HTTPS (or localhost).
- **Health**: `/healthz` returns `ok`; the image has a built-in healthcheck.
- **Backups**: back up the whole volume (database and `storage/` must be kept together).

### Email in development

If `SMTP_HOST` is not set, no email is sent: each message is appended to `outbox.log` (git-ignored) and printed to the server console, so you can copy the verification or reset link from there.

### Configuration

All optional environment variables:

| Variable | Purpose |
|----------|---------|
| `DATA_DIR` | Where the database, encrypted files, session key and dev mail log are stored (default: the project folder; `/data` in Docker). |
| `TRUST_PROXY=1` | Trust one reverse proxy's `X-Forwarded-*` headers (real client IP for quotas and rate limits). Only set this behind a proxy. |
| `BASE_URL` | Public site URL used in email links, e.g. `https://share.example.com`. **Required when not served on localhost**: links are never built from the request's Host header, to prevent reset-link poisoning. |
| `ANON_IP_QUOTA_MB` (100), `ANON_TOTAL_QUOTA_MB` (1024) | Storage quotas for anonymous-tier uploads: per IP, and all anonymous files together. |
| `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | Outgoing mail server. |
| `SMTP_TLS` | `starttls` (default) or `ssl` (port 465). |
| `SECRET_KEY` | Session signing key (otherwise generated in `secret.key`). |
| `SECURE_COOKIES=1` | Mark cookies HTTPS-only; set this when served over HTTPS. |

Empty values are treated as unset.

## How it works

```
Sender's browser                         Server                     Recipient's browser
-----------------                        ------                     -------------------
random 256-bit link key K
[optional] AES key = PBKDF2(password, K)
encrypt(name + file) -> ciphertext  -->  stores ciphertext only
link = /d/<token>#k=K[&p=1]
                                                                    opens link; K is read from #
                                         <-- ciphertext (counts 1 download)
                                                                    decrypts locally, saves file
```

Stored blob layout: `IV (12 bytes) || AES-GCM( name length (4) || {"name": ...} || file bytes )`.

## Project layout

| Path | Purpose |
|------|---------|
| `app.py` | Flask server: stores blobs, enforces expiry and download limits, audit log |
| `static/crypto.js` | Browser-side encryption and decryption (`window.SS`) |
| `static/upload.js`, `static/download.js`, `static/dashboard.js` | Page logic for sharing, downloading and the dashboard |
| `templates/` | HTML pages |
| `test_app.py` | Server-side tests (`python test_app.py`) |

Runtime files `secureshare.db`, `secret.key` and `storage/` are created automatically and are git-ignored.

## Testing

A GitHub Actions workflow ([.github/workflows/tests.yml](.github/workflows/tests.yml)) runs the tests on Python 3.9 to 3.13 for every push to `main`/`master` and every pull request, then builds the Docker image and checks that the container starts and answers `/healthz`.

```bash
python test_app.py
```

This covers the server: registration and login rules, password hashing, email verification and password reset (single use, expiry, cooldown, session invalidation, no account enumeration, Host-header safety), open-redirect and CSRF protection, per-user isolation, opaque blob storage, download limits, deletion, and input validation. The encryption itself runs in the browser; to check it, call `SS.shareFile(...)` and `SS.decryptBlob(...)` from the browser console on the running app.

## Security notes and limitations

- **Browser requirement**: the Web Crypto API only works on `localhost` or over HTTPS. Sharing over a plain-HTTP network address will not work; put it behind HTTPS.
- **Trust in the served page**: as with any browser-based end-to-end encryption, whoever serves the JavaScript could serve a malicious version. Host it yourself and use HTTPS.
- **Whole files in memory**: encryption and decryption happen in memory, so uploads are capped at 25 MB.
- **Anonymous uploads**: anyone can upload encrypted blobs, limited by per-IP rate limits, a 25 MB cap per file and the storage quotas above. On a public deployment also consider a CAPTCHA. Quotas key on the client IP: behind a reverse proxy set `TRUST_PROXY=1` so the real client IP is seen, otherwise every user shares one per-IP quota. Anonymous uploads are not tied to any account; keep the delete link, because it is the only way to remove one early.
- **Dashboard names and links**: the server never knows file names or the key, so the dashboard shows names and "Copy link" only for files uploaded from the same browser (remembered in its `localStorage`, in plain text). Files uploaded elsewhere show as "Encrypted". Clearing browser data loses those links.
- **Open registration**: anyone with a working email address can create an account. Registration reports "email already registered", so it reveals which emails have accounts (the reset flow does not). Accounts created before email support have no address and must add one on the Account page before getting the higher limits. The account password protects your dashboard and uploads only; it is separate from file encryption, so a reset never affects shared files.
- **Not covered**: no two-factor authentication, and no bounce handling or per-address throttling beyond the 60-second cooldown and per-IP rate limits.
- **Metadata**: the server can see ciphertext size, upload and download times, IP addresses, expiry and download counts.
- **No password recovery**: a lost link key or password means the file cannot be recovered.
- **Development server**: `python app.py` uses Flask's built-in server. For real deployments use the Docker setup (gunicorn) or another production WSGI server, behind HTTPS, and use a shared store (such as Redis) for rate limiting instead of the in-memory default.
- **Deleting is a GET link**: the delete link is a secret URL; anyone who has it can delete the file.
