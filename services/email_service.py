"""
Centralized email service that wraps all email complexity.

This service handles:
- Mailgun API vs SMTP fallback
- Environment variable management
- Error handling and logging
- Template rendering

Usage:
    from services.email_service import email_service

    email_service.send_support_request(user_id, user_email)
    email_service.send_magic_link(user_email, user_name, token)
"""

import os
import logging
from typing import Optional
from flask import current_app

logger = logging.getLogger(__name__)


class EmailService:
    """Centralized email service for the application."""

    def send_support_request(self, user_id: int, user_email: str) -> None:
        """
        Send support request notification to admin.

        Args:
            user_id: ID of user requesting support
            user_email: Email of user requesting support
        """
        admin_email = os.getenv('ADMIN_EMAIL')
        if not admin_email:
            logger.warning("ADMIN_EMAIL not configured, cannot send support notification")
            return

        app_url = os.getenv('APP_URL', 'http://localhost:5000')

        from services.email_sender import send_support_request_email
        success, message = send_support_request_email(
            admin_email=admin_email,
            user_email=user_email,
            user_id=user_id,
            app_url=app_url
        )

        if success:
            logger.info(f"Support request email sent for user {user_id}")
        else:
            logger.warning(f"Failed to send support email: {message}")

    def send_magic_link(self, email: str, name: Optional[str], token: str) -> bool:
        """
        Send magic link login email.

        Args:
            email: Recipient email
            name: Recipient name (optional)
            token: Magic link token

        Returns:
            True if email sent successfully (via any method)
        """
        magic_link = f"{os.getenv('APP_URL', 'http://localhost:5000')}/auth/magic/{token}"

        from services.email_sender import send_magic_link_email
        success, message = send_magic_link_email(email, name, magic_link)

        if success:
            logger.info(f"Magic link sent to {email}")
            return True

        # Try SMTP fallback if Mailgun failed
        if os.getenv('MAIL_USERNAME') and os.getenv('MAIL_DEFAULT_SENDER'):
            try:
                from flask_mail import Message
                msg = Message(
                    subject="Your LendifyMe Login Link",
                    recipients=[email],
                    body=f"""Hi {name or 'there'},

Click the link below to sign in to LendifyMe:

{magic_link}

This link will expire in 15 minutes.

If you didn't request this, you can safely ignore this email.

---
LendifyMe
"""
                )
                current_app.extensions['mail'].send(msg)
                logger.info(f"Magic link sent via SMTP to {email}")
                return True
            except Exception as e:
                logger.error(f"SMTP failed for {email}: {str(e)}")

        # Development fallback - print to console
        logger.warning(f"No email provider configured. Magic link for {email}: {magic_link}")
        print("\n" + "=" * 70)
        print("🔗 MAGIC LINK (Development Mode - Email not configured)")
        print("=" * 70)
        print(f"User: {email}")
        print(f"Link: {magic_link}")
        print("=" * 70 + "\n")

        return False

    def send_verification_email(self, email: str, name: Optional[str], token: str) -> bool:
        """
        Send email verification link.

        Args:
            email: Recipient email
            name: Recipient name (optional)
            token: Verification token

        Returns:
            True if email sent successfully
        """
        verification_link = f"{os.getenv('APP_URL', 'http://localhost:5000')}/auth/verify/{token}"

        from services.email_sender import send_verification_email as send_verification
        success, message = send_verification(email, name, verification_link)

        if success:
            logger.info(f"Verification email sent to {email}")
        else:
            logger.warning(f"Failed to send verification email: {message}")

        return success

    def send_borrower_invite(
        self,
        borrower_email: str,
        borrower_name: str,
        portal_token: str,
        lender_name: str
    ) -> bool:
        """
        Send borrower portal invitation.

        Args:
            borrower_email: Borrower's email
            borrower_name: Borrower's name
            portal_token: Portal access token
            lender_name: Lender's name

        Returns:
            True if email sent successfully
        """
        portal_link = f"{os.getenv('APP_URL', 'http://localhost:5000')}/borrower/{portal_token}"

        from services.email_sender import send_borrower_invite_email
        success, message = send_borrower_invite_email(
            to_email=borrower_email,
            borrower_name=borrower_name,
            portal_link=portal_link,
            lender_name=lender_name
        )

        if success:
            logger.info(f"Borrower invite sent to {borrower_email}")
        else:
            logger.warning(f"Failed to send borrower invite: {message}")

        return success

    def send_payment_notification(
        self,
        borrower_email: str,
        borrower_name: str,
        portal_token: str,
        lender_name: str,
        payment_amount: float,
        payment_date: str,
        payment_description: str,
        new_balance: float,
        original_amount: float
    ) -> bool:
        """
        Send payment notification to borrower.

        Args:
            borrower_email: Borrower's email
            borrower_name: Borrower's name
            portal_token: Portal access token
            lender_name: Lender's name
            payment_amount: Amount of payment applied
            payment_date: Date of payment
            payment_description: Payment description
            new_balance: New loan balance
            original_amount: Original loan amount

        Returns:
            True if email sent successfully
        """
        portal_link = f"{os.getenv('APP_URL', 'http://localhost:5000')}/borrower/{portal_token}"

        from services.email_sender import send_payment_notification_email
        success, message = send_payment_notification_email(
            to_email=borrower_email,
            borrower_name=borrower_name,
            portal_link=portal_link,
            lender_name=lender_name,
            payment_amount=payment_amount,
            payment_date=payment_date,
            payment_description=payment_description,
            new_balance=new_balance,
            original_amount=original_amount
        )

        if success:
            logger.info(f"Payment notification sent to {borrower_email}")
        else:
            logger.warning(f"Failed to send payment notification: {message}")

        return success


# Global instance to use throughout the app
email_service = EmailService()
