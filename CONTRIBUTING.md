# Contributing to SecureShare

Thanks for helping out! Bug reports, fixes, docs and focused features are all welcome.

## Reporting security issues

Please **don't** open a public issue for a vulnerability. Report it privately through the repository's **Security** tab (**Report a vulnerability**). The full policy, including what is in scope, is in [SECURITY.md](SECURITY.md).

## Getting set up

You need Python 3.9 or newer.

```bash
git clone https://github.com/ydhitler1-arch/secure-share.git
cd secure-share
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. With no `SMTP_HOST` set, emails (verification and reset links) are written to `outbox.log` and printed in the console, so you can test account flows without a mail server. Everything the app writes is git-ignored.

Prefer Docker? `docker compose up -d --build` serves it on http://localhost:8000. See the README for configuration.

## Running the tests

```bash
python test_app.py
```

The suite uses Flask's test client and needs no network. It writes a temporary database and files, so to keep your dev data untouched run it with a separate data folder:

```bash
DATA_DIR=/tmp/secureshare-test python test_app.py     # PowerShell: $env:DATA_DIR="$env:TEMP\ss-test"; python test_app.py
```

CI runs the same command on Python 3.9 to 3.13 and smoke-tests the Docker image. Your pull request needs a green run.

## How the code is organised

| Path | What lives there |
|------|------------------|
| `app.py` | The whole server: accounts, email, upload/download, dashboard, quotas |
| `static/crypto.js` | Browser-side encryption and decryption (`window.SS`) |
| `static/*.js` | Page scripts (upload, download, dashboard). No inline scripts: the CSP forbids them |
| `templates/` | Jinja templates |
| `test_app.py` | Server tests |

The README explains the encryption design. Two rules keep it honest:

1. **The server must never learn plaintext, file names or keys.** The key lives in the link's `#fragment`. Don't add anything that sends it to the server (URLs, logs, headers, analytics, error reports).
2. **Cryptography changes need extra care.** Use Web Crypto and well-known constructions only; don't invent primitives. Explain the reasoning in the pull request, and keep the stored blob format documented in the README and in `crypto.js`.

## Making a change

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Branch from `main`, keep the change focused, and match the style of the code around it.
3. Add or update tests for behaviour changes. Security fixes should come with a test that fails without the fix.
4. Update the README if you change features, configuration or limits.
5. Run `python test_app.py` and, if you touched the Docker setup, `docker compose up --build`.
6. Open a pull request describing **what** changed and **why**, and how you tested it.

### Style notes

- Python: standard library first, small functions, type hints where they help, comments that explain *why*.
- Keep new dependencies to a minimum; this project deliberately has two.
- Anything user-facing that depends on an environment variable should be documented in the README configuration table and be safe when the variable is empty.
- UI changes should work on narrow (phone-width) screens and not need inline scripts or external resources.

### Commit messages

A short imperative summary line (for example `Fix reset link expiry check`), then a body explaining the reason if it isn't obvious.

## Licence

By contributing you agree that your contributions are licensed under the project's [MIT license](LICENSE).
