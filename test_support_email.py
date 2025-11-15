#!/usr/bin/env python3
"""
Test script to verify support request email sending works.
This bypasses Socket.IO and tests the email service directly.

Usage:
    python test_support_email.py
"""

import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging to show everything
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Print environment configuration
print("=" * 70)
print("SUPPORT EMAIL TEST")
print("=" * 70)
print()
print("Environment Configuration:")
print(f"  ADMIN_EMAIL: {os.getenv('ADMIN_EMAIL', 'NOT SET')}")
print(f"  RESEND_API_KEY: {'***' + os.getenv('RESEND_API_KEY', '')[-8:] if os.getenv('RESEND_API_KEY') else 'NOT SET'}")
print(f"  MAILGUN_API_KEY: {'***' + os.getenv('MAILGUN_API_KEY', '')[-8:] if os.getenv('MAILGUN_API_KEY') else 'NOT SET'}")
print(f"  MAILGUN_DOMAIN: {os.getenv('MAILGUN_DOMAIN', 'NOT SET')}")
print(f"  APP_URL: {os.getenv('APP_URL', 'http://localhost:5000')}")
print()

# Check if ADMIN_EMAIL is set
admin_email = os.getenv('ADMIN_EMAIL')
if not admin_email:
    print("❌ ERROR: ADMIN_EMAIL not set in .env file")
    print("   Please add: ADMIN_EMAIL=your-email@example.com")
    exit(1)

# Check email provider configuration
has_resend = bool(os.getenv('RESEND_API_KEY'))
has_mailgun = bool(os.getenv('MAILGUN_API_KEY') and os.getenv('MAILGUN_DOMAIN'))

if has_resend:
    print("✅ Email provider: Resend (recommended)")
elif has_mailgun:
    print("⚠️  Email provider: Mailgun")
else:
    print("⚠️  WARNING: No email provider configured, will try SMTP fallback")
print()

# Import the email sender
from services.email_sender import send_support_request_email

# Test data
test_user_id = 999
test_user_email = "testuser@example.com"
test_app_url = os.getenv('APP_URL', 'http://localhost:5000')

print("=" * 70)
print("SENDING TEST EMAIL...")
print("=" * 70)
print(f"  To: {admin_email}")
print(f"  User: {test_user_email} (ID: {test_user_id})")
print()

# Send the email
success, message = send_support_request_email(
    admin_email=admin_email,
    user_email=test_user_email,
    user_id=test_user_id,
    app_url=test_app_url
)

print()
print("=" * 70)
print("RESULT:")
print("=" * 70)

if success:
    print(f"✅ SUCCESS: {message}")
    print()
    print(f"Check your inbox at: {admin_email}")
    print()
    print("If you don't see the email:")
    print("  1. Check your spam/junk folder")
    if has_resend:
        print("  2. Check Resend logs at: https://resend.com/emails")
    elif has_mailgun:
        print("  2. Check Mailgun logs at: https://app.mailgun.com/app/logs")
    print("  3. Verify ADMIN_EMAIL is correct in .env")
else:
    print(f"❌ FAILED: {message}")
    print()
    print("Troubleshooting:")
    print("  1. Add RESEND_API_KEY to .env (recommended)")
    print("     Get a free API key at: https://resend.com/api-keys")
    print("  2. OR use MAILGUN_API_KEY and MAILGUN_DOMAIN")
    print("  3. OR configure SMTP credentials (MAIL_USERNAME, MAIL_PASSWORD)")

print("=" * 70)
