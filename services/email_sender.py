"""Email sending utilities with support for Resend, Mailgun API, and Flask-Mail (SMTP)."""
import os
import requests
import logging
from typing import Optional
from flask import current_app
from flask_mail import Message

logger = logging.getLogger(__name__)


def _send_via_resend(sender_email: str, sender_name: str, to_email: str, to_name: Optional[str],
                     subject: str, html_body: str, text_body: str) -> tuple[bool, str]:
    """
    Send email via Resend API.

    Resend API docs: https://resend.com/docs/api-reference/emails/send-email
    """
    resend_api_key = os.getenv('RESEND_API_KEY')

    if not resend_api_key:
        return False, "Resend not configured"

    logger.info(f"📧 Sending via Resend API...")
    logger.info(f"   From: {sender_name} <{sender_email}>")
    logger.info(f"   To: {to_email}")

    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "from": f"{sender_name} <{sender_email}>",
                "to": [to_email],
                "subject": subject,
                "html": html_body,
                "text": text_body
            },
            timeout=10
        )

        if response.status_code == 200:
            logger.info(f"✅ Resend: Email sent to {to_email}")
            return True, "Email sent successfully via Resend"
        else:
            error_msg = f"Resend API error: {response.status_code} - {response.text}"
            logger.error(f"❌ Resend error: {error_msg}")
            return False, error_msg

    except requests.exceptions.Timeout:
        logger.error("Resend request timed out")
        return False, "Email request timed out"
    except requests.exceptions.RequestException as e:
        logger.error(f"Resend request exception: {str(e)}")
        return False, f"Failed to send email via Resend: {str(e)}"


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


def send_borrower_invite_email(to_email: str, borrower_name: str, portal_link: str, lender_name: str) -> tuple[bool, str]:
    """
    Send borrower portal invitation email.

    Args:
        to_email: Borrower's email address
        borrower_name: Borrower's name
        portal_link: Full URL to borrower portal
        lender_name: Name of the lender sending the invite

    Returns:
        tuple: (success: bool, message: str)
    """
    # Check if Mailgun API is configured
    mailgun_api_key = os.getenv('MAILGUN_API_KEY')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN')

    sender_email = os.getenv('MAIL_DEFAULT_SENDER', f'postmaster@{mailgun_domain}' if mailgun_domain else 'noreply@lendifyme.app')
    sender_name = os.getenv('MAIL_SENDER_NAME', 'LendifyMe')

    subject = f"Your Loan Status Portal from {lender_name}"

    text_body = f"""Hi {borrower_name},

{lender_name} has invited you to view your loan status online.

You can now track your loan balance and payment history anytime through your personal portal:

{portal_link}

This link is private and secure. You can bookmark it for future access.

---
LendifyMe - Simple Loan Tracking
"""

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; line-height: 1.6; background: #f8f9fa;">
    <div style="background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">Your Loan Portal is Ready</h1>
        </div>

        <p>Hi {borrower_name},</p>
        <p><strong>{lender_name}</strong> has set up a personal portal where you can:</p>

        <ul style="color: #6c757d;">
            <li>View your current loan balance</li>
            <li>See your payment history</li>
            <li>Track your progress</li>
        </ul>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{portal_link}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 14px 35px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; font-size: 16px;">
                View Your Loan Portal
            </a>
        </div>

        <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #6c757d;">
                <strong>💡 Tip:</strong> Bookmark this link to easily check your loan status anytime.
            </p>
        </div>

        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">

        <p style="color: #6c757d; font-size: 12px;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="{portal_link}" style="color: #667eea; word-break: break-all;">{portal_link}</a>
        </p>

        <p style="color: #6c757d; font-size: 12px; margin-bottom: 0;">
            This link is private and secure. Keep it safe and don't share it with others.
        </p>
    </div>
</body>
</html>
"""

    # Try Mailgun first
    if mailgun_api_key and mailgun_domain:
        logger.info(f"📧 Sending borrower invite via Mailgun to {to_email}")

        try:
            response = requests.post(
                f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
                auth=("api", mailgun_api_key),
                data={
                    "from": f"{sender_name} <{sender_email}>",
                    "to": f"{borrower_name} <{to_email}>",
                    "subject": subject,
                    "text": text_body,
                    "html": html_body
                },
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"✅ Borrower invite sent to {to_email}")
                return True, "Invitation email sent successfully"
            else:
                error_msg = f"Mailgun API error: {response.status_code} - {response.text}"
                logger.error(f"❌ Mailgun error: {error_msg}")
                return False, error_msg

        except requests.exceptions.Timeout:
            logger.error("Email request timed out")
            return False, "Email request timed out"
        except requests.exceptions.RequestException as e:
            logger.error(f"Mailgun request exception: {str(e)}")
            return False, f"Failed to send email: {str(e)}"

    # If Mailgun not configured, try SMTP via Flask-Mail
    logger.info("Mailgun not configured, attempting SMTP...")

    try:
        msg = Message(
            subject=subject,
            sender=(sender_name, sender_email),
            recipients=[to_email],
            body=text_body,
            html=html_body
        )

        current_app.extensions['mail'].send(msg)
        logger.info(f"✅ Borrower invite sent via SMTP to {to_email}")
        return True, "Invitation email sent successfully via SMTP"

    except Exception as e:
        logger.error(f"Failed to send email via SMTP: {str(e)}")
        return False, f"Failed to send email: {str(e)}"


def send_payment_notification_email(
    to_email: str,
    borrower_name: str,
    portal_link: str,
    lender_name: str,
    payment_amount: float,
    payment_date: str,
    payment_description: str,
    new_balance: float,
    original_amount: float
) -> tuple[bool, str]:
    """
    Send notification email to borrower when a payment is applied to their loan.

    Args:
        to_email: Borrower's email address
        borrower_name: Borrower's name
        portal_link: Full URL to borrower portal
        lender_name: Name of the lender
        payment_amount: Amount of the payment that was applied
        payment_date: Date of the payment
        payment_description: Description of the payment transaction
        new_balance: Remaining balance after this payment
        original_amount: Original loan amount

    Returns:
        tuple: (success: bool, message: str)
    """
    # Check if Mailgun API is configured
    mailgun_api_key = os.getenv('MAILGUN_API_KEY')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN')

    sender_email = os.getenv('MAIL_DEFAULT_SENDER', f'postmaster@{mailgun_domain}' if mailgun_domain else 'noreply@lendifyme.app')
    sender_name = os.getenv('MAIL_SENDER_NAME', 'LendifyMe')

    subject = f"Payment Applied to Your Loan - ${payment_amount:.2f}"

    text_body = f"""Hi {borrower_name},

{lender_name} has recorded a payment on your loan:

Payment Details:
- Amount: ${payment_amount:.2f}
- Date: {payment_date}
- Description: {payment_description}

Loan Summary:
- Original Loan: ${original_amount:.2f}
- Remaining Balance: ${new_balance:.2f}

View your full payment history and loan details:
{portal_link}

To stop receiving these email notifications, visit your portal and update your preferences.

---
LendifyMe - Simple Loan Tracking
"""

    # Extract token from portal_link for unsubscribe functionality
    token = portal_link.split('/borrower/')[-1] if '/borrower/' in portal_link else ''

    # Calculate percentage paid
    percent_paid = ((original_amount - new_balance) / original_amount) * 100 if original_amount > 0 else 0
    is_paid_off = new_balance <= 0

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; line-height: 1.6; background: #f8f9fa;">
    <div style="background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
        <div style="background: {'linear-gradient(135deg, #48bb78 0%, #38a169 100%)' if is_paid_off else 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'}; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">{'🎉 Loan Paid Off!' if is_paid_off else '💰 Payment Received'}</h1>
        </div>

        <p>Hi {borrower_name},</p>
        <p><strong>{lender_name}</strong> has recorded a payment on your loan:</p>

        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #dee2e6;">
                    <td style="padding: 10px 0; color: #6c757d; font-size: 14px;">Payment Amount</td>
                    <td style="padding: 10px 0; text-align: right; font-weight: bold; color: #198754; font-size: 18px;">
                        ${payment_amount:.2f}
                    </td>
                </tr>
                <tr style="border-bottom: 1px solid #dee2e6;">
                    <td style="padding: 10px 0; color: #6c757d; font-size: 14px;">Payment Date</td>
                    <td style="padding: 10px 0; text-align: right;">{payment_date}</td>
                </tr>
                <tr>
                    <td style="padding: 10px 0; color: #6c757d; font-size: 14px;">Description</td>
                    <td style="padding: 10px 0; text-align: right;">{payment_description}</td>
                </tr>
            </table>
        </div>

        <h3 style="color: #212529; margin-top: 30px;">Loan Summary</h3>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #dee2e6;">
                    <td style="padding: 10px 0; color: #6c757d; font-size: 14px;">Original Loan</td>
                    <td style="padding: 10px 0; text-align: right; font-weight: bold;">${original_amount:.2f}</td>
                </tr>
                <tr style="border-bottom: 1px solid #dee2e6;">
                    <td style="padding: 10px 0; color: #6c757d; font-size: 14px;">Remaining Balance</td>
                    <td style="padding: 10px 0; text-align: right; font-weight: bold; color: {'#198754' if is_paid_off else '#d63384'}; font-size: 18px;">
                        ${new_balance:.2f}
                    </td>
                </tr>
            </table>

            <div style="margin-top: 15px; background: #e9ecef; border-radius: 4px; overflow: hidden;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 20px; width: {percent_paid:.1f}%; transition: width 0.3s ease;"></div>
            </div>
            <p style="text-align: center; color: #6c757d; font-size: 12px; margin: 5px 0 0 0;">
                {percent_paid:.1f}% paid
            </p>
        </div>

        {f'''<div style="background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 15px; border-radius: 6px; margin: 20px 0; text-align: center;">
            <strong>🎊 Congratulations!</strong> Your loan has been fully paid off!
        </div>''' if is_paid_off else ''}

        <div style="text-align: center; margin: 30px 0;">
            <a href="{portal_link}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 14px 35px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; font-size: 16px;">
                View Full Payment History
            </a>
        </div>

        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">

        <p style="color: #6c757d; font-size: 12px; margin-bottom: 10px;">
            Questions about this payment? Contact {lender_name} directly.
        </p>

        <p style="color: #999; font-size: 11px; text-align: center; margin: 10px 0 0 0;">
            Don't want these emails? <a href="{portal_link}" style="color: #667eea; text-decoration: none;">Visit your portal</a> to disable notifications.
        </p>
    </div>
</body>
</html>
"""

    # Try Mailgun first
    if mailgun_api_key and mailgun_domain:
        logger.info(f"📧 Sending payment notification via Mailgun to {to_email}")

        try:
            response = requests.post(
                f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
                auth=("api", mailgun_api_key),
                data={
                    "from": f"{sender_name} <{sender_email}>",
                    "to": f"{borrower_name} <{to_email}>",
                    "subject": subject,
                    "text": text_body,
                    "html": html_body
                },
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"✅ Payment notification sent to {to_email}")
                return True, "Payment notification sent successfully"
            else:
                error_msg = f"Mailgun API error: {response.status_code} - {response.text}"
                logger.error(f"❌ Mailgun error: {error_msg}")
                return False, error_msg

        except requests.exceptions.Timeout:
            logger.error("Email request timed out")
            return False, "Email request timed out"
        except requests.exceptions.RequestException as e:
            logger.error(f"Mailgun request exception: {str(e)}")
            return False, f"Failed to send email: {str(e)}"

    # If Mailgun not configured, try SMTP via Flask-Mail
    logger.info("Mailgun not configured, attempting SMTP...")

    try:
        from flask import current_app
        from flask_mail import Message

        msg = Message(
            subject=subject,
            sender=(sender_name, sender_email),
            recipients=[to_email],
            body=text_body,
            html=html_body
        )

        current_app.extensions['mail'].send(msg)
        logger.info(f"✅ Payment notification sent via SMTP to {to_email}")
        return True, "Payment notification sent successfully via SMTP"

    except Exception as e:
        logger.error(f"Failed to send email via SMTP: {str(e)}")
        return False, f"Failed to send email: {str(e)}"


def send_support_request_email(admin_email: str, user_email: str, user_id: int, app_url: str) -> tuple[bool, str]:
    """
    Send support request notification email to admin.

    Args:
        admin_email: Admin's email address
        user_email: User requesting support
        user_id: User's ID
        app_url: Application base URL

    Returns:
        tuple: (success: bool, message: str)
    """
    from datetime import datetime

    mailgun_api_key = os.getenv('MAILGUN_API_KEY')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN')
    sender_email = os.getenv('MAIL_DEFAULT_SENDER', f'postmaster@{mailgun_domain}' if mailgun_domain else 'noreply@lendifyme.app')
    sender_name = os.getenv('MAIL_SENDER_NAME', 'LendifyMe')

    subject = "🆘 New Support Request - LendifyMe"

    text_body = f"""A user has requested support on LendifyMe!

User: {user_email}
User ID: {user_id}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Go to the support dashboard to help them:
{app_url}/admin/support
"""

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; line-height: 1.6; background: #f8f9fa;">
    <div style="background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
        <div style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">🆘 New Support Request</h1>
        </div>

        <p style="font-size: 16px; margin-bottom: 20px;">A user needs your help on LendifyMe!</p>

        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #dee2e6;">
                    <td style="padding: 10px 0; color: #6c757d; font-size: 14px; font-weight: bold;">User</td>
                    <td style="padding: 10px 0; text-align: right;">{user_email}</td>
                </tr>
                <tr style="border-bottom: 1px solid #dee2e6;">
                    <td style="padding: 10px 0; color: #6c757d; font-size: 14px; font-weight: bold;">User ID</td>
                    <td style="padding: 10px 0; text-align: right;">#{user_id}</td>
                </tr>
                <tr>
                    <td style="padding: 10px 0; color: #6c757d; font-size: 14px; font-weight: bold;">Time</td>
                    <td style="padding: 10px 0; text-align: right;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
            </table>
        </div>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{app_url}/admin/support" style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 14px 35px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; font-size: 16px;">
                Go to Support Dashboard
            </a>
        </div>

        <p style="color: #6c757d; font-size: 12px; text-align: center; margin-top: 30px;">
            This email was sent automatically when a user requested live support.
        </p>
    </div>
</body>
</html>
"""

    # Try Resend first
    resend_result = _send_via_resend(
        sender_email=sender_email,
        sender_name=sender_name,
        to_email=admin_email,
        to_name=None,
        subject=subject,
        html_body=html_body,
        text_body=text_body
    )
    if resend_result[0]:  # Success
        return resend_result

    # Try Mailgun if Resend failed/not configured
    if mailgun_api_key and mailgun_domain:
        logger.info(f"📧 Sending support request notification via Mailgun to {admin_email}")

        try:
            response = requests.post(
                f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
                auth=("api", mailgun_api_key),
                data={
                    "from": f"{sender_name} <{sender_email}>",
                    "to": admin_email,
                    "subject": subject,
                    "text": text_body,
                    "html": html_body
                },
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"✅ Support request notification sent to {admin_email}")
                return True, "Support request notification sent successfully"
            else:
                error_msg = f"Mailgun API error: {response.status_code} - {response.text}"
                logger.error(f"❌ Mailgun error: {error_msg}")
                return False, error_msg

        except requests.exceptions.Timeout:
            logger.error("Email request timed out")
            return False, "Email request timed out"
        except requests.exceptions.RequestException as e:
            logger.error(f"Mailgun request exception: {str(e)}")
            return False, f"Failed to send email: {str(e)}"

    # If Resend and Mailgun not configured, try SMTP via Flask-Mail
    logger.info("Resend and Mailgun not configured, attempting SMTP...")

    try:
        msg = Message(
            subject=subject,
            sender=(sender_name, sender_email),
            recipients=[admin_email],
            body=text_body,
            html=html_body
        )

        current_app.extensions['mail'].send(msg)
        logger.info(f"✅ Support request notification sent via SMTP to {admin_email}")
        return True, "Support request notification sent successfully via SMTP"

    except Exception as e:
        logger.error(f"Failed to send email via SMTP: {str(e)}")
        return False, f"Failed to send email: {str(e)}"


def send_verification_email(recipient_email: str, recipient_name: Optional[str], verification_link: str) -> tuple[bool, str]:
    """
    Send an email verification link to confirm the user's email address.

    Returns:
        tuple: (success: bool, message: str)
    """
    mailgun_api_key = os.getenv('MAILGUN_API_KEY')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN')
    sender_email = os.getenv('MAIL_DEFAULT_SENDER', f'postmaster@{mailgun_domain}')
    sender_name = os.getenv('MAIL_SENDER_NAME', 'LendifyMe')

    subject = "Verify Your Email - LendifyMe"

    text_body = f"""Hi {recipient_name or 'there'},

Welcome to LendifyMe! Please verify your email address by clicking the link below:

{verification_link}

This link will expire in 24 hours.

Verifying your email helps us ensure account security and allows you to use all features of LendifyMe.

If you didn't create an account with LendifyMe, you can safely ignore this email.

---
LendifyMe
"""

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; line-height: 1.6;">
    <div style="background: #f8f9fa; padding: 30px; border-radius: 8px;">
        <h1 style="color: #667eea; margin-top: 0;">Welcome to LendifyMe!</h1>
        <p>Hi {recipient_name or 'there'},</p>
        <p>Thanks for signing up! Please verify your email address to unlock all features and keep your account secure.</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{verification_link}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 14px 32px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold;">
                Verify Email Address
            </a>
        </div>

        <p style="color: #6c757d; font-size: 14px;">This link will expire in 24 hours.</p>
        <p style="color: #6c757d; font-size: 14px;">If you didn't create an account with LendifyMe, you can safely ignore this email.</p>

        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">
        <p style="color: #6c757d; font-size: 12px; margin-bottom: 0;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="{verification_link}" style="color: #667eea; word-break: break-all;">{verification_link}</a>
        </p>
    </div>
</body>
</html>
"""

    # Try Mailgun first
    if mailgun_api_key and mailgun_domain:
        logger.info(f"📧 Sending verification email via Mailgun API to {recipient_email}")

        try:
            response = requests.post(
                f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
                auth=("api", mailgun_api_key),
                data={
                    "from": f"{sender_name} <{sender_email}>",
                    "to": f"{recipient_name or recipient_email} <{recipient_email}>",
                    "subject": subject,
                    "text": text_body,
                    "html": html_body
                },
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"✅ Verification email sent to {recipient_email}")
                return True, "Verification email sent successfully"
            else:
                error_msg = f"Mailgun API error: {response.status_code} - {response.text}"
                logger.error(f"❌ Mailgun error: {error_msg}")
                return False, error_msg

        except requests.exceptions.Timeout:
            logger.error("Email request timed out")
            return False, "Email request timed out"
        except requests.exceptions.RequestException as e:
            logger.error(f"Mailgun request exception: {str(e)}")
            return False, f"Failed to send email: {str(e)}"

    # Fallback to SMTP
    logger.info("Mailgun not configured, attempting SMTP...")

    try:
        msg = Message(
            subject=subject,
            sender=(sender_name, sender_email),
            recipients=[recipient_email],
            body=text_body,
            html=html_body
        )

        current_app.extensions['mail'].send(msg)
        logger.info(f"✅ Verification email sent via SMTP to {recipient_email}")
        return True, "Verification email sent successfully via SMTP"

    except Exception as e:
        logger.error(f"Failed to send email via SMTP: {str(e)}")
        return False, f"Failed to send email: {str(e)}"
