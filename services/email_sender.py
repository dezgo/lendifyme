"""Email sending utilities with support for Flask-Mail (SMTP) and Mailgun API."""
import os
import requests
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def send_magic_link_email(recipient_email: str, recipient_name: Optional[str], magic_link: str) -> tuple[bool, str]:
    """
    Send a magic link email using the configured email provider.

    Returns:
        tuple: (success: bool, message: str)
    """
    # Check if Mailgun API is configured
    mailgun_api_key = os.getenv('MAILGUN_API_KEY')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN')

    if mailgun_api_key and mailgun_domain:
        return _send_via_mailgun_api(recipient_email, recipient_name, magic_link, mailgun_api_key, mailgun_domain)

    # Fallback to Flask-Mail (SMTP) - handled by caller
    return False, "Mailgun not configured"


def _send_via_mailgun_api(recipient_email: str, recipient_name: Optional[str], magic_link: str, api_key: str, domain: str) -> tuple[bool, str]:
    """Send email via Mailgun HTTP API."""

    sender_email = os.getenv('MAIL_DEFAULT_SENDER', f'postmaster@{domain}')
    sender_name = os.getenv('MAIL_SENDER_NAME', 'LendifyMe')

    logger.info(f"📧 Sending via Mailgun API...")
    logger.info(f"   Domain: {domain}")
    logger.info(f"   From: {sender_name} <{sender_email}>")
    logger.info(f"   To: {recipient_email}")

    try:
        response = requests.post(
            f"https://api.mailgun.net/v3/{domain}/messages",
            auth=("api", api_key),
            data={
                "from": f"{sender_name} <{sender_email}>",
                "to": f"{recipient_name or recipient_email} <{recipient_email}>",
                "subject": "Your LendifyMe Login Link",
                "text": f"""Hi {recipient_name or 'there'},

Click the link below to sign in to LendifyMe:

{magic_link}

This link will expire in 15 minutes.

If you didn't request this, you can safely ignore this email.

---
LendifyMe
""",
                "html": f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; line-height: 1.6;">
    <div style="background: #f8f9fa; padding: 30px; border-radius: 8px;">
        <h1 style="color: #007bff; margin-top: 0;">LendifyMe</h1>
        <p>Hi {recipient_name or 'there'},</p>
        <p>Click the button below to sign in to LendifyMe:</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{magic_link}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                Sign In to LendifyMe
            </a>
        </div>

        <p style="color: #6c757d; font-size: 14px;">This link will expire in 15 minutes.</p>
        <p style="color: #6c757d; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>

        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">
        <p style="color: #6c757d; font-size: 12px; margin-bottom: 0;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="{magic_link}" style="color: #007bff; word-break: break-all;">{magic_link}</a>
        </p>
    </div>
</body>
</html>
"""
            },
            timeout=10
        )

        if response.status_code == 200:
            logger.info(f"✅ Mailgun: Email sent to {recipient_email}")
            return True, "Email sent successfully via Mailgun"
        else:
            error_msg = f"Mailgun API error: {response.status_code} - {response.text}"
            logger.error(f"❌ Mailgun error: {error_msg}")
            return False, error_msg

    except requests.exceptions.Timeout:
        logger.error("Email request timed out")
        return False, "Email request timed out"
    except requests.exceptions.RequestException as e:
        logger.error(f"Mailgun request exception: {str(e)}")
        return False, f"Failed to send email via Mailgun: {str(e)}"
