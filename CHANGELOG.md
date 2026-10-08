# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-10-08

### Added
- Optional **Sign in with Google**: a "Continue with Google" button on the sign-in and register pages, enabled by setting `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. Google-verified emails create accounts that are already email-verified.
- OAuth 2.0 authorization-code flow with PKCE and a one-time `state` value, using only the standard library.
- Prebuilt multi-architecture (amd64 and arm64) Docker image published to `ghcr.io/ydhitler1-arch/secure-share` on every version tag (`1.1.0`, `1.1`, `1`, `latest`).
- Dependabot version updates (Python packages, GitHub Actions, Docker base image).
- `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS` and a pull request template.

### Security
- Linking Google to an existing local account whose email was never verified now locks that account's password and signs out its sessions, so someone who pre-registered another person's email cannot keep access.

### Changed
- The database gains a `google_sub` column automatically on first start; existing accounts and files are untouched.

## [1.0.0] - 2026-10-08

First stable release.

### Added
- **End-to-end encryption in the browser** (AES-256-GCM via Web Crypto). The server stores only ciphertext and never sees the file, its name or the key, which travels in the link's `#fragment`.
- Optional password on top of the link (PBKDF2-SHA256, 600,000 iterations).
- **Quick sharing without an account**, with expiry and download limits, per-IP rate limits and anonymous storage quotas (100 MB per IP, 1 GB in total).
- **Accounts and a dashboard** with a file list, totals, an activity log and one-click delete.
- **Email verification and password reset** with single-use hashed tokens, resend cooldowns, no account enumeration on reset, and sessions invalidated after a reset.
- Higher limits for verified accounts (up to 7 days and 100 downloads).
- A secret delete link for every upload.
- CSRF protection, rate limiting, security headers and a strict Content Security Policy.
- Docker setup (gunicorn, non-root, read-only filesystem, health check) and a GitHub Actions workflow running the tests on Python 3.9 to 3.13 plus a Docker smoke test.
- MIT license.

[Unreleased]: https://github.com/ydhitler1-arch/secure-share/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/ydhitler1-arch/secure-share/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ydhitler1-arch/secure-share/releases/tag/v1.0.0
