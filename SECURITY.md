# Security Policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue or pull request.

Use GitHub's private reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Include:

- what you found and which part of the project it affects,
- steps or a proof of concept to reproduce it,
- what an attacker could achieve (for example, reading files, taking over accounts, bypassing limits),
- the commit or version you tested.

This is a volunteer-maintained project, so responses are best-effort. You can expect an acknowledgement, an assessment of the report, and credit in the fix if you want it. Please give a reasonable amount of time to release a fix before disclosing the issue publicly.

## Supported versions

Only the latest release (currently 1.x) and the tip of `main` are supported. Fixes land on `main` first and are released as new patch versions.

## What is in scope

The project's core promise is that **the server never learns file contents, file names or encryption keys**. Reports of any of the following are especially welcome:

- anything that exposes plaintext, names or keys to the server, its logs, or a third party (including leaking the `#fragment` key in requests, referrers or error output),
- flaws in the browser-side encryption in `static/crypto.js` (key handling, nonce reuse, weak key derivation, tampering that is not detected),
- authentication and session problems: login, registration, sessions, CSRF, open redirects,
- Sign in with Google weaknesses: state or PKCE bypasses, account linking or takeover, trusting unverified Google emails,
- email verification or password reset weaknesses: token guessing or reuse, account enumeration, Host-header poisoning, session survival after a reset,
- access-control problems: one user reading or deleting another user's files or activity,
- bypasses of expiry, download limits, rate limits or the anonymous storage quotas,
- injection, XSS or CSP bypasses, and unsafe handling of uploaded data or file names,
- the Docker setup: privilege escalation or secrets baked into the image.

## Known limitations (not vulnerabilities)

These are documented design trade-offs; see the *Security notes and limitations* section of the [README](README.md):

- A server operator can serve modified JavaScript to users. This is inherent to browser-based end-to-end encryption; host the app yourself and use HTTPS.
- The server can see metadata such as file size, upload and download times, IP addresses, expiry and download counts.
- Anyone who has a share link (including its `#key`) can download the file until it expires, unless a password was also set.
- Registration reveals whether an email address already has an account.
- The development server (`python app.py`) is not meant for production use.
- There is no two-factor authentication.

## Deploying safely

If you run your own instance: serve it over HTTPS behind a reverse proxy, set `BASE_URL`, `SECURE_COOKIES=1` and `TRUST_PROXY=1`, keep the data volume (database, encrypted files and `secret.key`) private and backed up, and keep dependencies up to date. The README's Docker and configuration sections cover the details.
