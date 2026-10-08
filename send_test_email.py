"""Send a test email with the SMTP settings from .env (or the environment).

    python send_test_email.py you@example.com
"""
import smtplib
import sys

import app

if len(sys.argv) != 2:
    sys.exit(__doc__)
if not app.env("SMTP_HOST"):
    sys.exit("SMTP_HOST is not set, so emails are only written to outbox.log. Fill in .env first.")

try:
    app.send_message(sys.argv[1], "SecureShare test email",
                     "If you can read this, SecureShare can send email. Verification and password reset emails will work.\n")
except smtplib.SMTPAuthenticationError:
    sys.exit("The mail server rejected the username or password. For Gmail use a 16-character app password, "
             "not your normal password (it needs 2-Step Verification turned on).")
except (smtplib.SMTPException, OSError) as exc:
    sys.exit(f"Could not send: {exc!r}")
print(f"Sent a test email to {sys.argv[1]} using {app.env('SMTP_HOST')}. Check the inbox (and spam).")
