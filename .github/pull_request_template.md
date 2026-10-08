## What and why

<!-- What does this change, and why is it needed? Link the issue if there is one (e.g. "Closes #123"). -->

## How I tested it

<!-- Commands you ran, and anything you checked by hand (browser, Docker, etc.). -->

## Checklist

- [ ] `python test_app.py` passes
- [ ] Added or updated tests for behaviour changes (security fixes: a test that fails without the fix)
- [ ] Updated the README if features, configuration or limits changed
- [ ] No inline scripts, external resources or new dependencies (or explained below)

### Security-sensitive changes

<!-- Delete this section if the PR doesn't touch encryption, authentication, sessions, email/reset flows, quotas or the Docker setup. -->

- [ ] The server still never receives plaintext, file names or keys (nothing from the `#fragment` is sent anywhere)
- [ ] Crypto changes use Web Crypto and standard constructions only, with the reasoning explained above
- [ ] The stored blob format is unchanged, or the change is documented in the README and `static/crypto.js`

## Notes for reviewers

<!-- Trade-offs, follow-ups, screenshots for UI changes. -->
