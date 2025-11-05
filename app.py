from flask_wtf import CSRFProtect
import click
import sys
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask_mail import Mail
from functools import wraps
import os
import logging
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
from werkzeug.middleware.proxy_fix import ProxyFix

from flask import Flask, send_from_directory, request, session, render_template, redirect, url_for, flash, jsonify
from schemas.feedback import validate_feedback_input, ValidationError

import sqlite3

from services.loans import (
    decrypt_loans,
    get_loan_dek,
    encrypt_loan_data,
    get_user_subscription_tier,
    check_loan_limit,
    has_feature,
)
from services.transaction_matcher import match_transactions_to_loans
from services.connectors.registry import ConnectorRegistry
from services.connectors.csv_connector import CSVConnector
from services.feedback_service import (
    admin_feedback,
    admin_feedback_update,
    submit_feedback,
)

from helpers.utils import get_db_path
from helpers.db import get_db_connection


# Load environment variables from .env
load_dotenv()

ENV = os.environ.get("FLASK_ENV") or "production"

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    environment=ENV,          # ← This is the key bit
    integrations=[
        FlaskIntegration(),
        LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
    ],
    send_default_pii=True,
)

app = Flask(__name__)
csrf = CSRFProtect(app)

if os.getenv("FLASK_ENV") == "production":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_SECURE=(ENV == 'production'),  # only over HTTPS in production
    SESSION_COOKIE_HTTPONLY=True,     # JS can't read
    SESSION_COOKIE_SAMESITE="Lax",    # or "Strict" if OK
    PREFERRED_URL_SCHEME = "https",
)

# Config
app.config['DATABASE'] = 'lendifyme.db'
app.secret_key = os.getenv('SECRET_KEY')

if not app.secret_key:
    sys.stderr.write(
        "\nERROR: SECRET_KEY is not set in environment.\n"
        "Generate one with:\n"
        "    python -c \"import secrets; print(secrets.token_hex(32))\"\n\n"
    )
    sys.exit(1)

# Session config - make sessions last 30 days
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Email config for magic links
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['APP_URL'] = os.getenv('APP_URL', 'http://localhost:5000')

mail = Mail(app)

# Configure logging (always enabled, not just in production)
# Create logs directory if it doesn't exist
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, 'lendifyme.log')

# File handler with rotation (max 10MB, keep 10 backup files)
file_handler = RotatingFileHandler(log_file, maxBytes=10240000, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)

# Also log to console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
app.logger.addHandler(console_handler)

app.logger.setLevel(logging.INFO)
app.logger.info(f'LendifyMe startup - Debug mode: {app.debug}')
app.logger.info(f'Log file location: {log_file}')

# Log email configuration status
mailgun_configured = bool(os.getenv('MAILGUN_API_KEY') and os.getenv('MAILGUN_DOMAIN'))
smtp_configured = bool(os.getenv('MAIL_USERNAME') and os.getenv('MAIL_DEFAULT_SENDER'))
app.logger.info(f'Email config - Mailgun: {mailgun_configured}, SMTP: {smtp_configured}')
if mailgun_configured:
    app.logger.info(f'Mailgun domain: {os.getenv("MAILGUN_DOMAIN")}')

# Print to console as well so we always see it
print(f"🚀 LendifyMe starting...")
print(f"📝 Logging to: {log_file}")
print(f"🐛 Debug mode: {app.debug}")
print(f"📧 Mailgun configured: {mailgun_configured}")
print(f"📧 SMTP configured: {smtp_configured}")
if mailgun_configured:
    print(f"📧 Mailgun domain: {os.getenv('MAILGUN_DOMAIN')}")

# Register blueprints
from routes.auth import auth_bp, init_mail
app.register_blueprint(auth_bp)
init_mail(mail)  # Pass mail instance to auth blueprint
app.logger.info("Registered auth blueprint")
print("✅ Registered auth blueprint")  # Pretty output for console

from routes.loan_routes import loan_bp
app.register_blueprint(loan_bp)
app.logger.info("Registered loan blueprint")
print("✅ Registered loan blueprint")  # Pretty output for console


# Custom Jinja2 filter for human-friendly date formatting
@app.template_filter('format_date')
def format_date_filter(date_string):
    """
    Convert ISO date string (YYYY-MM-DD) to human-friendly format (e.g., '1 Oct 2024').
    Handles None and empty strings gracefully.
    Platform-independent (works on Windows, Linux, macOS).
    """
    if not date_string:
        return '—'

    try:
        # Parse ISO date string
        if isinstance(date_string, str):
            # Handle datetime strings with time component
            if 'T' in date_string:
                date_obj = datetime.fromisoformat(date_string.split('.')[0])
            else:
                date_obj = datetime.strptime(date_string, '%Y-%m-%d')
        else:
            # Already a datetime object
            date_obj = date_string

        # Format as "1 Oct 2024" (platform-independent)
        # Use lstrip to remove leading zero from day
        day = str(date_obj.day)  # No leading zero
        month = date_obj.strftime('%b')  # Short month name
        year = date_obj.strftime('%Y')  # Full year

        return f"{day} {month} {year}"
    except (ValueError, AttributeError):
        # If parsing fails, return original string
        return date_string


def filter_duplicate_transactions(matches):
    """Filter out transactions that have already been applied or rejected."""
    conn = get_db_connection()
    c = conn.cursor()

    filtered_matches = []
    for match in matches:
        transaction = match['transaction']
        loan_id = match['loan']['id']

        # Use absolute value for amount comparison since:
        # - Borrowing loans have negative transaction amounts
        # - But we store all amounts as positive in applied_transactions
        transaction_amount_abs = abs(transaction['amount'])

        # Check if this transaction has already been applied (to any loan)
        # We check with absolute value to catch both positive and negative transactions
        c.execute("""
            SELECT COUNT(*) FROM applied_transactions
            WHERE date = ? AND description = ? AND amount = ?
        """, (transaction['date'], transaction['description'], transaction_amount_abs))

        applied_count = c.fetchone()[0]

        # Check if this transaction was rejected for this specific loan
        # Now storing absolute values in rejected_matches too (as of this fix)
        # But check both for backwards compatibility with old data
        c.execute("""
            SELECT COUNT(*) FROM rejected_matches
            WHERE date = ? AND description = ?
            AND (amount = ? OR amount = ?)
            AND loan_id = ?
        """, (transaction['date'], transaction['description'],
              transaction_amount_abs, transaction['amount'], loan_id))

        rejected_count = c.fetchone()[0]

        # Include only if not applied and not rejected for this loan
        if applied_count == 0 and rejected_count == 0:
            filtered_matches.append(match)

    conn.close()
    return filtered_matches


def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('auth.login', next=request.url))

        # Check if user is admin
        if not is_user_admin():
            flash("Access denied. Admin privileges required.", "error")
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function


def get_current_user_id():
    """Get the current logged-in user's ID from session."""
    return session.get('user_id')


def is_user_admin():
    """Check if current user has admin role."""
    user_id = get_current_user_id()
    if not user_id:
        return False

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result and result[0] == 'admin'


def is_email_verified():
    """Check if current user has verified their email."""
    user_id = get_current_user_id()
    if not user_id:
        return False

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email_verified FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result and result[0] == 1


def get_unverified_loan_count():
    """Get the number of loans an unverified user has created."""
    user_id = get_current_user_id()
    if not user_id:
        return 0

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM loans WHERE user_id = ?", (user_id,))
    count = c.fetchone()[0]
    conn.close()

    return count


# ============================================================================
# ENCRYPTION HELPER FUNCTIONS
# ============================================================================

def get_user_encryption_salt():
    """Get the current user's encryption salt from database."""
    user_id = get_current_user_id()
    if not user_id:
        return None

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result[0] if result else None


def get_user_password_from_session():
    """Get the user's password from session (needed for decryption)."""
    return session.get('user_password')


# ============================================================================
# SUBSCRIPTION HELPER FUNCTIONS
# ============================================================================


def log_event(event_name, user_id=None, event_data=None):
    """
    Log an analytics event to the database.

    Args:
        event_name: Name of the event (e.g., 'user_signed_up', 'loan_created')
        user_id: Optional user ID (defaults to current user if logged in)
        event_data: Optional dict with additional context (stored as JSON)
    """
    try:
        # Use current user if not specified
        if user_id is None:
            user_id = get_current_user_id()

        # Get session ID if available
        session_id = session.get('_id', None)

        # Convert event_data to JSON if provided
        event_data_json = json.dumps(event_data) if event_data else None

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO events (event_name, user_id, session_id, event_data)
            VALUES (?, ?, ?, ?)
        """, (event_name, user_id, session_id, event_data_json))
        conn.commit()
        conn.close()
    except Exception as e:
        # Don't let analytics failures break the app
        app.logger.error(f"Failed to log event {event_name}: {e}")


@app.before_request
def redirect_www():
    if request.host.startswith("www."):
        new_url = request.url.replace("://www.", "://", 1)
        return redirect(new_url, code=301)


# Error handlers
@app.errorhandler(400)
def bad_request(e):
    """Handle 400 Bad Request errors (primarily CSRF failures)."""
    # Check if it's a CSRF error
    error_description = str(e.description) if hasattr(e, 'description') else ""
    is_csrf_error = "CSRF" in error_description or "csrf" in error_description.lower()

    return render_template("400.html", is_csrf_error=is_csrf_error), 400


@app.errorhandler(404)
def not_found(e):
    """Handle 404 Not Found errors."""
    return render_template("404.html"), 404


def init_db():
    from services import migrations

    db_path = get_db_path()  # uses current_app when context is active
    conn = get_db_connection()
    try:
        migrations.run_migrations(conn)
    finally:
        conn.close()


@app.cli.command("init-db")
def init_db_command():
    """Initialize DB / run migrations (use in deploy)."""
    # Flask provides an app context for CLI commands, but we’ll be explicit
    with app.app_context():
        init_db()
    click.echo("✅ Database initialized (migrations applied).")


@app.route("/health")
def health():
    if ENV != 'development':
        return "status: ok", 200, {'Content-Type': 'text/plain; charset=utf-8'}

    """Health check endpoint with diagnostics."""
    # Write a test log entry
    app.logger.info("Health check endpoint accessed")

    diagnostics = {
        "status": "ok",
        "app_root": os.path.dirname(os.path.abspath(__file__)),
        "log_file": log_file,
        "log_file_exists": os.path.exists(log_file),
        "log_dir_exists": os.path.exists(log_dir),
        "debug_mode": app.debug,
        "python_version": sys.version,
        "working_directory": os.getcwd(),
        "email_config": {
            "mailgun_configured": bool(os.getenv('MAILGUN_API_KEY') and os.getenv('MAILGUN_DOMAIN')),
            "mailgun_domain": os.getenv('MAILGUN_DOMAIN', 'Not set'),
            "smtp_configured": bool(os.getenv('MAIL_USERNAME')),
        },
        "log_dir_writable": os.access(log_dir, os.W_OK) if os.path.exists(log_dir) else "Dir doesn't exist"
    }

    # Try to read last 10 lines of log file
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                log_preview = f.readlines()[-10:]
        except Exception as e:
            log_preview = [f"Error reading log: {str(e)}"]
    else:
        log_preview = ["Log file doesn't exist yet"]

    diagnostics["log_preview"] = log_preview

    # Return as formatted text for easy reading
    output = "=== LendifyMe Health Check ===\n\n"
    for key, value in diagnostics.items():
        if key == "log_preview":
            output += f"\n{key}:\n"
            for line in value:
                output += f"  {line}"
        else:
            output += f"{key}: {value}\n"

    return output, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@app.route("/borrower/<token>")
def borrower_portal(token):
    """Borrower self-service portal - view loan details and transaction history."""
    if not token:
        flash("Invalid access link", "error")
        return redirect("/")

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Find loan by access token
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.date_borrowed, l.date_due,
               l.borrower_encrypted, l.amount_encrypted,
               l.note, l.note_encrypted,
               l.repayment_amount, l.repayment_amount_encrypted,
               l.repayment_frequency, l.repayment_frequency_encrypted,
               l.bank_name, l.bank_name_encrypted,
               l.borrower_email, l.borrower_email_encrypted,
               l.borrower_notifications_enabled
        FROM loans l
        WHERE l.borrower_access_token = ?
    """, (token,))
    loan_row = c.fetchone()

    if not loan_row:
        conn.close()
        flash("Invalid or expired access link", "error")
        return render_template("borrower_portal_error.html"), 404

    loan_id = loan_row['id']

    # Get DEK from token (borrower access - no password needed)
    dek = get_loan_dek(loan_id, borrower_token=token)

    if not dek:
        conn.close()
        flash("Unable to decrypt loan data. Please contact the lender.", "error")
        return render_template("borrower_portal_error.html"), 500

    # Decrypt loan fields
    from services.encryption import decrypt_field

    borrower = decrypt_field(loan_row['borrower_encrypted'], dek) if loan_row['borrower_encrypted'] else loan_row['borrower']
    amount = float(decrypt_field(loan_row['amount_encrypted'], dek)) if loan_row['amount_encrypted'] else loan_row['amount']
    note = decrypt_field(loan_row['note_encrypted'], dek) if loan_row['note_encrypted'] else loan_row['note']
    bank_name = decrypt_field(loan_row['bank_name_encrypted'], dek) if loan_row['bank_name_encrypted'] else loan_row['bank_name']
    borrower_email = decrypt_field(loan_row['borrower_email_encrypted'], dek) if loan_row['borrower_email_encrypted'] else loan_row['borrower_email']

    repayment_amount = None
    if loan_row['repayment_amount_encrypted']:
        repayment_amount = float(decrypt_field(loan_row['repayment_amount_encrypted'], dek))
    elif loan_row['repayment_amount'] is not None:
        repayment_amount = loan_row['repayment_amount']

    repayment_frequency = decrypt_field(loan_row['repayment_frequency_encrypted'], dek) if loan_row['repayment_frequency_encrypted'] else loan_row['repayment_frequency']

    # Calculate amount_repaid from applied_transactions
    c.execute("""
        SELECT COALESCE(SUM(amount), 0) as amount_repaid
        FROM applied_transactions
        WHERE loan_id = ?
    """, (loan_id,))
    amount_repaid = c.fetchone()[0]

    # Calculate outstanding balance
    outstanding = amount - amount_repaid

    # Get all applied transactions for this loan
    c.execute("""
        SELECT id, date, description, amount, applied_at
        FROM applied_transactions
        WHERE loan_id = ?
        ORDER BY date DESC
    """, (loan_id,))
    transactions = c.fetchall()

    conn.close()

    # Prepare loan dict for template
    loan = {
        'id': loan_id,
        'borrower': borrower,
        'amount': amount,
        'date_borrowed': loan_row['date_borrowed'],
        'date_due': loan_row['date_due'],
        'note': note,
        'repayment_amount': repayment_amount,
        'repayment_frequency': repayment_frequency,
        'bank_name': bank_name,
        'borrower_email': borrower_email,
        'amount_repaid': amount_repaid,
        'outstanding': outstanding,
        'notifications_enabled': loan_row['borrower_notifications_enabled']
    }

    return render_template("borrower_portal.html", loan=loan, transactions=transactions, token=token)


@app.route("/borrower/<token>/notifications", methods=["POST"])
def borrower_toggle_notifications(token):
    """Toggle email notifications for borrower."""
    if not token:
        flash("Invalid access link", "error")
        return redirect("/")

    action = request.form.get("action")  # 'enable' or 'disable'

    conn = get_db_connection()
    c = conn.cursor()

    # Find loan by access token
    c.execute("SELECT id, borrower FROM loans WHERE borrower_access_token = ?", (token,))
    loan_data = c.fetchone()

    if not loan_data:
        conn.close()
        flash("Invalid or expired access link", "error")
        return redirect("/")

    loan_id, borrower = loan_data

    # Update notification preference
    if action == "disable":
        c.execute("UPDATE loans SET borrower_notifications_enabled = 0 WHERE id = ?", (loan_id,))
        flash("Email notifications disabled. You can still view your loan anytime via this portal.", "success")
    elif action == "enable":
        c.execute("UPDATE loans SET borrower_notifications_enabled = 1 WHERE id = ?", (loan_id,))
        flash("Email notifications enabled. You'll receive updates when payments are recorded.", "success")

    conn.commit()
    conn.close()

    return redirect(f"/borrower/{token}")


@app.route("/loan/<int:loan_id>/send-invite", methods=["GET", "POST"])
@login_required
def send_borrower_invite(loan_id):
    """Send invitation email to borrower with portal access link."""
    conn = get_db_connection()
    c = conn.cursor()

    # Verify loan ownership and get loan details
    c.execute("""
        SELECT l.id, borrower, borrower_access_token, borrower_email, l.amount,
               COALESCE(SUM(at.amount), 0) as amount_repaid
        FROM loans l
        LEFT JOIN applied_transactions at ON l.id = at.loan_id
        WHERE l.id = ? AND l.user_id = ?
        GROUP BY l.id
    """, (loan_id, get_current_user_id()))
    loan = c.fetchone()

    if not loan:
        conn.close()
        flash("Loan not found", "error")
        return redirect("/")

    loan_id, borrower, access_token, borrower_email, amount, amount_repaid = loan

    if not access_token:
        conn.close()
        flash("This loan doesn't have an access token. Please edit the loan to generate one.", "error")
        return redirect("/")

    if request.method == "POST":
        email = request.form.get("borrower_email")

        if not email:
            conn.close()
            flash("Email address is required", "error")
            return render_template("send_invite.html", loan=loan)

        # Save email address to loan
        c.execute("UPDATE loans SET borrower_email = ? WHERE id = ?", (email, loan_id))
        conn.commit()
        conn.close()

        # Send invitation email
        portal_link = f"{app.config['APP_URL']}/borrower/{access_token}"

        try:
            from services.email_sender import send_borrower_invite_email
            send_borrower_invite_email(
                to_email=email,
                borrower_name=borrower,
                portal_link=portal_link,
                lender_name=session.get('user_name') or session.get('user_email')
            )
            flash(f"Invitation sent to {email}!", "success")
        except Exception as e:
            app.logger.error(f"Failed to send invitation email: {e}")
            flash(f"Failed to send email. You can share this link manually: {portal_link}", "error")

        return redirect("/")

    conn.close()
    return render_template("send_invite.html", loan=loan)


@app.route("/onboarding")
@login_required
def onboarding():
    """Onboarding flow for new users."""
    # Check if already completed
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT onboarding_completed FROM users WHERE id = ?", (get_current_user_id(),))
    user = c.fetchone()
    conn.close()

    if user and user[0]:
        # Already completed onboarding
        return redirect("/")

    # Get current step from query param
    # Skip step 1 (email confirmation) as it's confusing after registration
    step = request.args.get('step', '2')

    if step == '1':
        # Step 1: Welcome + verify email (kept for backwards compatibility, but skip by default)
        return render_template("onboarding_step1.html",
                             email=session.get('user_email'))
    elif step == '2':
        # Check if user has password before showing loan creation
        user_password = get_user_password_from_session()
        encryption_salt = get_user_encryption_salt()

        if not user_password or not encryption_salt:
            # Redirect to password setup first
            flash("First, let's secure your account with a password to encrypt your loan data.", "info")
            return redirect("/settings/password?redirect=onboarding")

        # Step 2: Create first loan
        return render_template("onboarding_step2.html")
    elif step == 'complete':
        # Mark onboarding as complete
        user_id = get_current_user_id()
        if not user_id:
            app.logger.error("Session lost during onboarding completion")
            flash("Session expired. Please log in again.", "error")
            return redirect("/login")

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET onboarding_completed = 1 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        app.logger.info(f"Onboarding completed for user {user_id}")
        flash("Welcome to LendifyMe! 🎉", "success")
        return redirect("/")

    return redirect("/onboarding?step=2")


@app.route("/onboarding/update-email", methods=["POST"])
@login_required
def onboarding_update_email():
    """Update email during onboarding."""
    new_email = request.form.get("email", "").strip()

    if not new_email:
        flash("Email is required", "error")
        return redirect("/onboarding?step=1")

    conn = get_db_connection()
    c = conn.cursor()

    # Check if new email is already taken
    c.execute("SELECT id FROM users WHERE email = ? AND id != ?",
             (new_email, get_current_user_id()))
    if c.fetchone():
        flash("That email is already in use", "error")
        conn.close()
        return redirect("/onboarding?step=1")

    # Update email
    c.execute("UPDATE users SET email = ? WHERE id = ?",
             (new_email, get_current_user_id()))
    conn.commit()
    conn.close()

    # Update session
    session['user_email'] = new_email

    flash("Email updated!", "success")
    return redirect("/onboarding?step=1")


@app.route("/pricing")
def pricing():
    """Display pricing tiers and subscription options."""
    conn = get_db_connection()
    c = conn.cursor()

    # Get all subscription plans
    c.execute("""
        SELECT tier, name, price_monthly, price_yearly, max_loans, features_json
        FROM subscription_plans
        WHERE active = 1
        ORDER BY price_monthly ASC
    """)
    plan_rows = c.fetchall()
    conn.close()

    # Convert to dicts
    plans = []
    for row in plan_rows:
        tier, name, price_monthly, price_yearly, max_loans, features_json = row
        features = json.loads(features_json)
        plans.append({
            'tier': tier,
            'name': name,
            'price_monthly': price_monthly / 100 if price_monthly else 0,  # Convert cents to dollars
            'price_yearly': price_yearly / 100 if price_yearly else 0,
            'max_loans': max_loans,
            'features': features
        })

    # Get current user's tier if logged in
    current_tier = None
    current_loans = 0
    manual_override = False
    if 'user_id' in session:
        current_tier = get_user_subscription_tier()
        current_loans, _, _ = check_loan_limit()

        # Check if user has manual override (admin-granted)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT manual_override FROM users WHERE id = ?", (get_current_user_id(),))
        result = c.fetchone()
        manual_override = result[0] if result else False
        conn.close()

    return render_template("pricing.html",
                         plans=plans,
                         current_tier=current_tier,
                         current_loans=current_loans,
                         manual_override=manual_override)


@app.route("/subscribe/<tier>")
@login_required
def subscribe(tier):
    """Create Stripe checkout session for subscription."""
    import stripe
    from datetime import datetime, timedelta

    # Validate tier
    if tier not in ['basic', 'pro']:
        flash("Invalid subscription tier", "error")
        return redirect("/pricing")

    # Get billing cycle (monthly or yearly)
    billing_cycle = request.args.get('billing', 'monthly')
    if billing_cycle not in ['monthly', 'yearly']:
        billing_cycle = 'monthly'

    # Check if user already has this tier or higher
    current_tier = get_user_subscription_tier()
    tier_hierarchy = {'free': 0, 'basic': 1, 'pro': 2}
    if tier_hierarchy.get(current_tier, 0) >= tier_hierarchy.get(tier, 0):
        flash(f"You already have {current_tier.title()} plan access", "error")
        return redirect("/pricing")

    # Get or create Stripe customer
    user_id = get_current_user_id()
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT stripe_customer_id, email FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    stripe_customer_id, user_email = result

    # Initialize Stripe
    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

    if not stripe.api_key:
        flash("Stripe is not configured. Please contact support.", "error")
        conn.close()
        return redirect("/pricing")

    try:
        # Create or retrieve Stripe customer
        if not stripe_customer_id:
            customer = stripe.Customer.create(
                email=user_email,
                metadata={'user_id': user_id}
            )
            stripe_customer_id = customer.id

            # Save customer ID
            c.execute("UPDATE users SET stripe_customer_id = ? WHERE id = ?",
                     (stripe_customer_id, user_id))
            conn.commit()

        # Get price ID from environment based on billing cycle
        price_id_key = f'STRIPE_PRICE_ID_{tier.upper()}_{billing_cycle.upper()}'
        price_id = os.getenv(price_id_key)

        if not price_id:
            flash(f"Pricing not configured for {tier.title()} plan ({billing_cycle}). Please contact support.", "error")
            conn.close()
            return redirect("/pricing")

        # Set trial end date (14 days from now)
        trial_end = int((datetime.now() + timedelta(days=14)).timestamp())

        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=stripe_customer_id,
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{app.config['APP_URL']}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{app.config['APP_URL']}/pricing",
            subscription_data={
                'trial_period_days': 14,
                'metadata': {
                    'user_id': user_id,
                    'tier': tier,
                    'billing_cycle': billing_cycle
                }
            },
            metadata={
                'user_id': user_id,
                'tier': tier,
                'billing_cycle': billing_cycle
            }
        )

        # Store trial start in database
        trial_ends_at = (datetime.now() + timedelta(days=14)).isoformat()
        c.execute("UPDATE users SET trial_ends_at = ? WHERE id = ?",
                 (trial_ends_at, user_id))
        conn.commit()
        conn.close()

        # Log analytics event
        log_event('subscription_checkout_started', event_data={'tier': tier, 'billing_cycle': billing_cycle})

        # Redirect to Stripe Checkout
        return redirect(checkout_session.url, code=303)

    except stripe.StripeError as e:
        flash(f"Payment error: {str(e)}", "error")
        conn.close()
        return redirect("/pricing")
    except Exception as e:
        app.logger.error(f"Subscription error: {e}")
        flash("An error occurred. Please try again.", "error")
        conn.close()
        return redirect("/pricing")


@app.route("/checkout/success")
@login_required
def checkout_success():
    """Handle successful checkout."""
    session_id = request.args.get('session_id')

    if not session_id:
        flash("Invalid checkout session", "error")
        return redirect("/")

    flash("Subscription activated! Welcome to your new plan.", "success")
    log_event('subscription_activated')

    return redirect("/")


@app.route("/checkout/cancel")
@login_required
def checkout_cancel():
    """Handle cancelled checkout."""
    flash("Checkout cancelled. You can subscribe anytime from the pricing page.", "error")
    return redirect("/pricing")


@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events."""
    import stripe
    from datetime import datetime

    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

    if not webhook_secret:
        app.logger.error("Stripe webhook secret not configured")
        return ('Webhook secret not configured', 400)

    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        app.logger.error("Invalid webhook payload")
        return ('Invalid payload', 400)
    except stripe.SignatureVerificationError:
        app.logger.error("Invalid webhook signature")
        return ('Invalid signature', 400)

    # Handle the event
    event_type = event['type']
    data_object = event['data']['object']

    app.logger.info(f"Received Stripe webhook: {event_type}")

    conn = get_db_connection()
    c = conn.cursor()

    try:
        if event_type == 'checkout.session.completed':
            # Payment successful, subscription created
            session = data_object
            customer_id = session.get('customer')
            subscription_id = session.get('subscription')
            metadata = session.get('metadata', {})
            user_id = metadata.get('user_id')
            tier = metadata.get('tier')

            if user_id and tier:
                # Update user's subscription tier
                c.execute("""
                    UPDATE users
                    SET subscription_tier = ?, stripe_customer_id = ?
                    WHERE id = ?
                """, (tier, customer_id, user_id))

                # Create subscription record
                c.execute("""
                    INSERT INTO user_subscriptions
                    (user_id, stripe_subscription_id, stripe_customer_id, tier, status, created_at)
                    VALUES (?, ?, ?, ?, 'trialing', CURRENT_TIMESTAMP)
                """, (user_id, subscription_id, customer_id, tier))

                conn.commit()
                app.logger.info(f"Subscription created for user {user_id}: {tier}")

        elif event_type == 'customer.subscription.updated':
            # Subscription status changed
            subscription = data_object
            subscription_id = subscription['id']
            status = subscription['status']
            current_period_start = datetime.fromtimestamp(subscription['current_period_start']).isoformat()
            current_period_end = datetime.fromtimestamp(subscription['current_period_end']).isoformat()
            cancel_at_period_end = subscription.get('cancel_at_period_end', False)

            # Update subscription record
            c.execute("""
                UPDATE user_subscriptions
                SET status = ?,
                    current_period_start = ?,
                    current_period_end = ?,
                    cancel_at_period_end = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE stripe_subscription_id = ?
            """, (status, current_period_start, current_period_end, cancel_at_period_end, subscription_id))

            # If subscription becomes active, update user tier
            if status == 'active':
                c.execute("""
                    UPDATE users
                    SET subscription_tier = (
                        SELECT tier FROM user_subscriptions
                        WHERE stripe_subscription_id = ?
                    )
                    WHERE id = (
                        SELECT user_id FROM user_subscriptions
                        WHERE stripe_subscription_id = ?
                    )
                """, (subscription_id, subscription_id))

            conn.commit()
            app.logger.info(f"Subscription {subscription_id} updated: {status}")

        elif event_type == 'customer.subscription.deleted':
            # Subscription cancelled or ended
            subscription = data_object
            subscription_id = subscription['id']

            # Get user_id before deleting
            c.execute("SELECT user_id FROM user_subscriptions WHERE stripe_subscription_id = ?", (subscription_id,))
            result = c.fetchone()

            if result:
                user_id = result[0]

                # Downgrade user to free tier
                c.execute("UPDATE users SET subscription_tier = 'free' WHERE id = ?", (user_id,))

                # Update subscription status
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = 'canceled',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))

                conn.commit()
                app.logger.info(f"Subscription {subscription_id} cancelled, user {user_id} downgraded to free")

        elif event_type == 'invoice.payment_succeeded':
            # Successful payment
            invoice = data_object
            subscription_id = invoice.get('subscription')

            if subscription_id:
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = 'active',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))
                conn.commit()
                app.logger.info(f"Payment succeeded for subscription {subscription_id}")

        elif event_type == 'invoice.payment_failed':
            # Failed payment
            invoice = data_object
            subscription_id = invoice.get('subscription')

            if subscription_id:
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = 'past_due',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))
                conn.commit()
                app.logger.warning(f"Payment failed for subscription {subscription_id}")

        conn.close()
        return ('Success', 200)

    except Exception as e:
        app.logger.error(f"Error processing webhook: {e}")
        conn.rollback()
        conn.close()
        return ('Error processing webhook', 500)


@app.route("/billing")
@login_required
def billing():
    """Manage subscription and billing."""
    import stripe

    user_id = get_current_user_id()
    conn = get_db_connection()
    c = conn.cursor()

    # Get user's subscription info
    c.execute("""
        SELECT u.subscription_tier, u.stripe_customer_id, u.manual_override,
               us.stripe_subscription_id, us.status, us.current_period_end,
               us.cancel_at_period_end, sp.price_monthly, sp.price_yearly, sp.features_json
        FROM users u
        LEFT JOIN user_subscriptions us ON u.id = us.user_id AND us.status IN ('active', 'trialing', 'past_due')
        LEFT JOIN subscription_plans sp ON u.subscription_tier = sp.tier
        WHERE u.id = ?
    """, (user_id,))
    result = c.fetchone()

    if not result:
        conn.close()
        flash("User not found", "error")
        return redirect("/")

    tier, stripe_customer_id, manual_override, subscription_id, status, period_end, cancel_at_period_end, price_monthly, price_yearly, features_json = result

    # Get usage stats
    current_loans, max_loans, can_create = check_loan_limit()

    subscription_data = {
        'tier': tier,
        'tier_name': tier.title(),
        'status': status,
        'price_monthly': price_monthly / 100 if price_monthly else 0,
        'price_yearly': price_yearly / 100 if price_yearly else 0,
        'manual_override': manual_override,
        'subscription_id': subscription_id,
        'cancel_at_period_end': cancel_at_period_end,
        'period_end': period_end,
        'current_loans': current_loans,
        'max_loans': max_loans,
        'features': json.loads(features_json) if features_json else {}
    }

    # Create Stripe portal session for managing subscription
    portal_url = None
    if stripe_customer_id and not manual_override:
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
        try:
            portal_session = stripe.billing_portal.Session.create(
                customer=stripe_customer_id,
                return_url=f"{app.config['APP_URL']}/billing"
            )
            portal_url = portal_session.url
        except Exception as e:
            app.logger.error(f"Error creating portal session: {e}")

    conn.close()

    return render_template("billing.html",
                         subscription=subscription_data,
                         portal_url=portal_url)


@app.route("/admin/users")
@admin_required
def admin_users():
    """Admin page to manage all users and their subscriptions."""
    conn = get_db_connection()
    c = conn.cursor()

    # Get all users with their subscription info and usage stats
    c.execute("""
        SELECT u.id, u.email, u.name, u.subscription_tier, u.manual_override,
               u.created_at, u.email_verified,
               us.status, us.current_period_end,
               COUNT(DISTINCT l.id) as loan_count
        FROM users u
        LEFT JOIN user_subscriptions us ON u.id = us.user_id AND us.status IN ('active', 'trialing', 'past_due')
        LEFT JOIN loans l ON u.id = l.user_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """)
    user_rows = c.fetchall()

    users = []
    for row in user_rows:
        users.append({
            'id': row[0],
            'email': row[1],
            'name': row[2],
            'tier': row[3],
            'manual_override': row[4],
            'created_at': row[5],
            'email_verified': row[6],
            'subscription_status': row[7],
            'period_end': row[8],
            'loan_count': row[9]
        })

    conn.close()

    return render_template("admin_users.html", users=users)


@app.route("/admin/user/<int:user_id>/upgrade", methods=["POST"])
@admin_required
def admin_upgrade_user(user_id):
    """Manually upgrade a user's subscription tier."""
    new_tier = request.form.get("tier")

    if new_tier not in ['free', 'basic', 'pro']:
        flash("Invalid tier", "error")
        return redirect("/admin/users")

    conn = get_db_connection()
    c = conn.cursor()

    # Update user's tier and set manual override
    c.execute("""
        UPDATE users
        SET subscription_tier = ?,
            manual_override = 1,
            trial_ends_at = NULL
        WHERE id = ?
    """, (new_tier, user_id))

    # Get user email for flash message
    c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    user_email = result[0] if result else f"User {user_id}"

    conn.commit()
    conn.close()

    log_event('admin_user_upgrade', event_data={'target_user_id': user_id, 'new_tier': new_tier})
    flash(f"Successfully updated {user_email} to {new_tier.title()} (manual override)", "success")

    return redirect("/admin/users")


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """Delete a user account and all associated data."""
    current_user_id = get_current_user_id()

    # Safety check: Can't delete yourself
    if user_id == current_user_id:
        flash("You cannot delete your own account.", "error")
        return redirect("/admin/users")

    conn = get_db_connection()
    c = conn.cursor()

    # Check if user exists and get their info
    c.execute("SELECT email, role FROM users WHERE id = ?", (user_id,))
    user_result = c.fetchone()

    if not user_result:
        flash("User not found.", "error")
        conn.close()
        return redirect("/admin/users")

    user_email, user_role = user_result

    # Safety check: Don't delete the last admin
    if user_role == 'admin':
        c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = c.fetchone()[0]

        if admin_count <= 1:
            flash("Cannot delete the last admin user.", "error")
            conn.close()
            return redirect("/admin/users")

    # Manually delete related records (in case CASCADE isn't set up everywhere)
    # Delete loans and their related data
    c.execute("""
        DELETE FROM applied_transactions
        WHERE loan_id IN (SELECT id FROM loans WHERE user_id = ?)
    """, (user_id,))

    c.execute("""
        DELETE FROM rejected_matches
        WHERE loan_id IN (SELECT id FROM loans WHERE user_id = ?)
    """, (user_id,))

    c.execute("DELETE FROM loans WHERE user_id = ?", (user_id,))

    # Delete other user-related data
    c.execute("DELETE FROM bank_connections WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM pending_matches_data WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM passkeys WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM magic_links WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM user_subscriptions WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM events WHERE user_id = ?", (user_id,))

    # Finally delete the user
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()

    log_event('admin_user_delete', event_data={'target_user_id': user_id, 'target_email': user_email})
    flash(f"Successfully deleted user {user_email} and all associated data.", "success")

    return redirect("/admin/users")


@app.route("/admin/cleanup-inactive", methods=["POST"])
@admin_required
def admin_cleanup_inactive():
    """
    Clean up inactive user accounts to prevent spam buildup.

    Deletion criteria:
    - Unverified accounts: inactive for 7+ days
    - Verified accounts with no loans: inactive for 90+ days
    - Accounts with loans are never auto-deleted (manual deletion only)
    """
    days_unverified = int(request.form.get("days_unverified", 7))
    days_verified = int(request.form.get("days_verified", 90))
    dry_run = request.form.get("dry_run") == "1"

    conn = get_db_connection()
    c = conn.cursor()

    deleted_users = []

    # Find unverified accounts that haven't logged in for X days and have no loans
    c.execute("""
        SELECT u.id, u.email, u.created_at, u.last_login_at, u.email_verified
        FROM users u
        LEFT JOIN loans l ON l.user_id = u.id
        WHERE u.email_verified = 0
        AND (u.last_login_at IS NULL OR u.last_login_at < datetime('now', '-' || ? || ' days'))
        AND u.role != 'admin'
        GROUP BY u.id
        HAVING COUNT(l.id) = 0
    """, (days_unverified,))

    unverified_users = c.fetchall()

    # Find verified accounts that haven't logged in for X days and have no loans
    c.execute("""
        SELECT u.id, u.email, u.created_at, u.last_login_at, u.email_verified
        FROM users u
        LEFT JOIN loans l ON l.user_id = u.id
        WHERE u.email_verified = 1
        AND (u.last_login_at IS NULL OR u.last_login_at < datetime('now', '-' || ? || ' days'))
        AND u.role != 'admin'
        GROUP BY u.id
        HAVING COUNT(l.id) = 0
    """, (days_verified,))

    verified_users = c.fetchall()

    candidates = unverified_users + verified_users

    if not dry_run:
        for user_id, email, created_at, last_login_at, email_verified in candidates:
            # Delete all user-related data
            c.execute("DELETE FROM bank_connections WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM pending_matches_data WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM passkeys WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM magic_links WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM user_subscriptions WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM events WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))

            deleted_users.append({
                'email': email,
                'verified': email_verified,
                'created_at': created_at,
                'last_login_at': last_login_at
            })

        conn.commit()

        log_event('admin_cleanup_inactive', event_data={
            'deleted_count': len(deleted_users),
            'days_unverified': days_unverified,
            'days_verified': days_verified
        })

        flash(f"Successfully deleted {len(deleted_users)} inactive accounts.", "success")
    else:
        # Dry run - just show what would be deleted
        for user_id, email, created_at, last_login_at, email_verified in candidates:
            deleted_users.append({
                'email': email,
                'verified': email_verified,
                'created_at': created_at,
                'last_login_at': last_login_at
            })

        flash(f"Dry run: Found {len(deleted_users)} accounts that would be deleted.", "success")

    conn.close()

    # Store results in session to display on admin page
    session['cleanup_results'] = {
        'deleted_users': deleted_users,
        'dry_run': dry_run,
        'days_unverified': days_unverified,
        'days_verified': days_verified
    }

    return redirect("/admin/users")


# ---------------------------
# Admin: list + pagination
# ---------------------------
@app.route("/admin/feedback")
@admin_required
def _admin_feedback():
    status_filter = (request.args.get("status") or "all").lower().strip()

    # simple, safe int parsing
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except ValueError:
        page_size = 50

    try:
        feedback_list, status_counts, total = admin_feedback(
            status_filter=status_filter,
            page=page,
            page_size=page_size,
        )
    except ValidationError as e:
        flash(str(e), "error")
        # fall back to "all"
        feedback_list, status_counts, total = admin_feedback(
            status_filter="all", page=1, page_size=page_size
        )
        status_filter = "all"
        page = 1

    # For template pager
    total_pages = max(1, (total + page_size - 1) // page_size)

    return render_template(
        "admin_feedback.html",
        feedback=feedback_list,
        status_filter=status_filter,
        status_counts=status_counts,
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


# ---------------------------
# Admin: update one row
# ---------------------------
@app.route("/admin/feedback/<int:feedback_id>/update", methods=["POST"])
@admin_required
def _admin_feedback_update(feedback_id: int):
    new_status = request.form.get("status", "")
    admin_notes = request.form.get("admin_notes", "")

    try:
        updated = admin_feedback_update(
            feedback_id=feedback_id,
            new_status=new_status,
            admin_notes=admin_notes,
        )
    except ValidationError as e:
        flash(str(e), "error")
        # preserve current filter/page in the redirect if present
        return redirect(url_for("_admin_feedback", **request.args))

    if updated:
        flash("Feedback updated successfully", "success")
    else:
        flash("No changes made (record not found?)", "warning")

    return redirect(url_for("_admin_feedback", **request.args))


# ---------------------------
# Public: submit feedback
# ---------------------------
@app.route("/feedback/submit", methods=["POST"])
def feedback_submit_route():
    # Thin route: gather raw inputs only
    ip_addr = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
    user_agent = request.headers.get("User-Agent")

    try:
        data = validate_feedback_input(
            feedback_type=request.form.get("feedback_type"),
            message=request.form.get("message"),
            page_url=request.form.get("page_url"),
            page_title=request.form.get("page_title"),
            user_id=session.get("user_id"),
            user_email=session.get("user_email"),
            ip_addr=ip_addr,
            user_agent=user_agent,
        )
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), getattr(e, "status_code", 400)

    # Service owns connection + transactions
    try:
        fb_id, _ = submit_feedback(data)
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), getattr(e, "status_code", 400)

    return jsonify({"success": True, "id": fb_id})


@app.route("/settings")
@login_required
def settings():
    """Settings hub page."""
    return render_template("settings.html")


# Common passwords blocklist
COMMON_PASSWORDS = {
    'password', '12345678', '123456789', '12345', '1234567', '123456',
    'password1', 'password123', 'qwerty', 'abc123', 'monkey', '1234567890',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master',
    'sunshine', 'ashley', 'bailey', 'shadow', 'superman', 'qazwsx',
    '123123', 'welcome', 'admin', 'login', 'passw0rd', 'starwars',
    'whatever', 'freedom', 'mustang', 'batman', 'football', 'princess',
    'michael', 'jennifer', 'jordan', '111111', '000000',
    '696969', '666666', 'zxcvbnm', 'hunter', 'buster', 'soccer',
    'harley', 'ranger', 'charlie', 'abcd1234', 'password!',
    'qwertyuiop', 'asdfghjkl', 'zxcvbn', '1q2w3e4r', 'abcdef'
}


@app.route("/settings/password", methods=["GET", "POST"])
@login_required
def settings_password():
    """Manage account password - add, change, or remove."""
    redirect_from = request.args.get('redirect')

    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        action = request.form.get("action")  # 'add', 'change', or 'remove'

        conn = get_db_connection()
        c = conn.cursor()

        c.execute("SELECT password_hash FROM users WHERE id = ?", (get_current_user_id(),))
        user = c.fetchone()

        if not user:
            flash("User not found", "error")
            conn.close()
            return redirect("/")

        has_password = user[0] is not None

        if action == "add":
            # Adding password for the first time
            if has_password:
                flash("You already have a password. Use 'Change Password' instead.", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            if not new_password:
                flash("Password is required", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            if len(new_password) < 8:
                flash("Password must be at least 8 characters", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            # Block common passwords
            if new_password.lower() in COMMON_PASSWORDS:
                flash("This password is too common and frequently compromised. Please choose a different password.", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            if new_password != confirm_password:
                flash("Passwords do not match", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            from werkzeug.security import generate_password_hash
            from services.encryption import generate_encryption_salt, generate_master_recovery_phrase, normalize_recovery_phrase

            password_hash = generate_password_hash(new_password)

            # Generate encryption salt for zero-knowledge encryption of bank credentials
            encryption_salt = generate_encryption_salt()

            # Generate master recovery phrase (6 BIP39 words) for password recovery without data loss
            master_recovery_key = generate_master_recovery_phrase(num_words=6)
            # Normalize and hash the phrase for verification (same as password hashing)
            master_recovery_key_hash = generate_password_hash(normalize_recovery_phrase(master_recovery_key))

            c.execute("""
                UPDATE users
                SET password_hash = ?, auth_provider = 'password', encryption_salt = ?, master_recovery_key_hash = ?
                WHERE id = ?
            """, (password_hash, encryption_salt, master_recovery_key_hash, get_current_user_id()))
            conn.commit()
            conn.close()

            # Store password in session for immediate bank connection setup and loan encryption
            session['user_password'] = new_password

            # Store master recovery key in session for dual-encrypting loans
            # (Similar to how we store password in session)
            session['master_recovery_key'] = master_recovery_key

            # Store master recovery phrase for display (one-time view)
            session['show_master_recovery_phrase'] = master_recovery_key

            # Redirect to recovery phrase display page
            return redirect("/auth/recovery-phrase")

        elif action == "upgrade":
            # Upgrade existing password to enable bank encryption
            if not has_password:
                flash("You don't have a password yet. Use 'Add Password' instead.", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, needs_upgrade=False, redirect_from=redirect_from)

            if not new_password:
                flash("Password is required", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, needs_upgrade=True, redirect_from=redirect_from)

            # Verify current password
            from werkzeug.security import check_password_hash
            if not check_password_hash(user[0], new_password):
                flash("Password is incorrect", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, needs_upgrade=True, redirect_from=redirect_from)

            # Generate encryption salt
            from services.encryption import generate_encryption_salt
            encryption_salt = generate_encryption_salt()

            c.execute("""
                UPDATE users
                SET encryption_salt = ?
                WHERE id = ?
            """, (encryption_salt, get_current_user_id()))
            conn.commit()
            conn.close()

            # Store password in session
            session['user_password'] = new_password

            flash("Account upgraded! You can now connect your bank accounts.", "success")
            redirect_to = request.args.get('redirect')
            if redirect_to == 'banks':
                return redirect("/settings/banks/add")
            return redirect("/settings/password")

        elif action == "change":
            # Changing existing password
            if not has_password:
                flash("You don't have a password yet. Use 'Add Password' instead.", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            # Check if user logged in via recovery code (password reset scenario)
            logged_in_via_recovery = session.get('logged_in_via_recovery', False)

            # Check if user provided recovery phrase instead of password
            recovery_phrase_provided = request.form.get("recovery_phrase_change", "").strip()
            auth_credential = None  # Will store either password or recovery phrase for re-encryption

            if not logged_in_via_recovery:
                # Normal password change - require current password OR recovery phrase
                if not current_password and not recovery_phrase_provided:
                    flash("Current password or recovery phrase is required", "error")
                    conn.close()
                    return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from, logged_in_via_recovery=False)

                from werkzeug.security import check_password_hash

                if recovery_phrase_provided:
                    # Verify recovery phrase
                    c.execute("SELECT master_recovery_key_hash FROM users WHERE id = ?", (get_current_user_id(),))
                    recovery_hash_row = c.fetchone()

                    if not recovery_hash_row or not recovery_hash_row[0]:
                        flash("No recovery phrase set for this account", "error")
                        conn.close()
                        return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from, logged_in_via_recovery=False)

                    from services.encryption import normalize_recovery_phrase
                    normalized_phrase = normalize_recovery_phrase(recovery_phrase_provided)

                    if not check_password_hash(recovery_hash_row[0], normalized_phrase):
                        flash("Incorrect recovery phrase", "error")
                        conn.close()
                        return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from, logged_in_via_recovery=False)

                    # Recovery phrase verified - use it for re-encryption
                    auth_credential = normalized_phrase
                else:
                    # Verify current password
                    if not check_password_hash(user[0], current_password):
                        flash("Current password is incorrect", "error")
                        conn.close()
                        return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from, logged_in_via_recovery=False)

                    # Password verified - use it for re-encryption
                    auth_credential = current_password

            if not new_password:
                flash("New password is required", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            if len(new_password) < 8:
                flash("New password must be at least 8 characters", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            # Block common passwords
            if new_password.lower() in COMMON_PASSWORDS:
                flash("This password is too common and frequently compromised. Please choose a different password.", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            if new_password != confirm_password:
                flash("New passwords do not match", "error")
                conn.close()
                return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from)

            # Re-encrypt all loan DEKs with new password
            # Get user's encryption salt
            c.execute("SELECT encryption_salt FROM users WHERE id = ?", (get_current_user_id(),))
            salt_result = c.fetchone()

            if salt_result and salt_result[0]:
                encryption_salt = salt_result[0]

                # Get all loans with encrypted DEKs
                c.execute("""
                    SELECT id, encrypted_dek
                    FROM loans
                    WHERE user_id = ? AND encrypted_dek IS NOT NULL
                """, (get_current_user_id(),))
                loans_to_reencrypt = c.fetchall()

                if loans_to_reencrypt:
                    from services.encryption import decrypt_dek_with_password, encrypt_dek_with_password

                    # Use auth credential (password, recovery phrase, or session password)
                    old_credential = auth_credential if auth_credential else session.get('user_password')

                    reencrypted_count = 0
                    for loan_id, encrypted_dek in loans_to_reencrypt:
                        try:
                            # Decrypt with old credential (password or recovery phrase)
                            dek = decrypt_dek_with_password(encrypted_dek, old_credential, encryption_salt)

                            # Re-encrypt with new password
                            new_encrypted_dek = encrypt_dek_with_password(dek, new_password, encryption_salt)

                            # Update loan
                            c.execute("""
                                UPDATE loans
                                SET encrypted_dek = ?
                                WHERE id = ?
                            """, (new_encrypted_dek, loan_id))

                            reencrypted_count += 1
                        except Exception as e:
                            app.logger.error(f"Failed to re-encrypt loan {loan_id}: {e}")

                    if reencrypted_count > 0:
                        app.logger.info(f"Re-encrypted {reencrypted_count} loans with new password for user {get_current_user_id()}")

            from werkzeug.security import generate_password_hash
            password_hash = generate_password_hash(new_password)

            c.execute("""
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
            """, (password_hash, get_current_user_id()))
            conn.commit()
            conn.close()

            # Clear recovery login flag and store new password in session
            session.pop('logged_in_via_recovery', None)
            session['user_password'] = new_password

            # Redirect to success page
            return redirect("/settings/password/success")

        elif action == "remove":
            # Password removal is no longer allowed due to zero-knowledge encryption
            # Without a password, users cannot decrypt their loan data
            flash("Password cannot be removed. It's required to encrypt and decrypt your loan data.", "error")
            conn.close()
            return redirect("/settings/password")

        conn.close()

    # GET request - show form
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash, encryption_salt FROM users WHERE id = ?", (get_current_user_id(),))
    user = c.fetchone()
    conn.close()

    has_password = user and user[0] is not None
    has_encryption_salt = user and user[1] is not None
    needs_upgrade = has_password and not has_encryption_salt
    redirect_from = request.args.get('redirect')
    logged_in_via_recovery = session.get('logged_in_via_recovery', False)

    return render_template("settings_password.html",
                         has_password=has_password,
                         needs_upgrade=needs_upgrade,
                         redirect_from=redirect_from,
                         logged_in_via_recovery=logged_in_via_recovery)


@app.route("/settings/password/success")
@login_required
def password_change_success():
    """Show success page after password change."""
    return render_template("password_success.html")


@app.route("/settings/recovery", methods=["GET", "POST"])
@login_required
def settings_recovery():
    """Manage recovery phrase - regenerate or view status."""
    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()

        conn = get_db_connection()
        c = conn.cursor()

        c.execute("SELECT password_hash, master_recovery_key_hash FROM users WHERE id = ?", (get_current_user_id(),))
        user = c.fetchone()

        if not user:
            flash("User not found", "error")
            conn.close()
            return redirect("/")

        password_hash, recovery_key_hash = user

        if not password_hash:
            flash("You need to set up a password first before generating a recovery phrase.", "error")
            conn.close()
            return redirect("/settings/password")

        # Require current password to regenerate recovery phrase
        if not current_password:
            flash("Current password is required to regenerate recovery phrase", "error")
            conn.close()
            return render_template("settings_recovery.html", has_recovery_phrase=(recovery_key_hash is not None))

        # Verify current password
        from werkzeug.security import check_password_hash
        if not check_password_hash(password_hash, current_password):
            flash("Current password is incorrect", "error")
            conn.close()
            return render_template("settings_recovery.html", has_recovery_phrase=(recovery_key_hash is not None))

        # Get user's encryption salt
        c.execute("SELECT encryption_salt FROM users WHERE id = ?", (get_current_user_id(),))
        salt_result = c.fetchone()

        if not salt_result or not salt_result[0]:
            flash("Encryption not set up. Please contact support.", "error")
            conn.close()
            return redirect("/settings/recovery")

        encryption_salt = salt_result[0]

        # Re-encrypt all loan DEKs with new recovery phrase
        # Get all loans with encrypted DEKs
        c.execute("""
            SELECT id, encrypted_dek
            FROM loans
            WHERE user_id = ? AND encrypted_dek IS NOT NULL
        """, (get_current_user_id(),))
        loans_to_reencrypt = c.fetchall()

        from services.encryption import (
            decrypt_dek_with_password,
            encrypt_dek_with_recovery_phrase,
            generate_master_recovery_phrase,
            normalize_recovery_phrase
        )
        from werkzeug.security import generate_password_hash

        # Generate new recovery phrase
        new_recovery_phrase = generate_master_recovery_phrase(num_words=6)
        new_recovery_phrase_hash = generate_password_hash(normalize_recovery_phrase(new_recovery_phrase))

        # Re-encrypt all loans with new recovery phrase
        reencrypted_count = 0
        if loans_to_reencrypt:
            for loan_id, encrypted_dek in loans_to_reencrypt:
                try:
                    # Decrypt with current password
                    dek = decrypt_dek_with_password(encrypted_dek, current_password, encryption_salt)

                    # Re-encrypt with new recovery phrase
                    new_encrypted_dek_recovery = encrypt_dek_with_recovery_phrase(dek, new_recovery_phrase, encryption_salt)

                    # Update loan
                    c.execute("""
                        UPDATE loans
                        SET encrypted_dek_recovery = ?
                        WHERE id = ?
                    """, (new_encrypted_dek_recovery, loan_id))

                    reencrypted_count += 1
                except Exception as e:
                    app.logger.error(f"Failed to re-encrypt loan {loan_id} with new recovery phrase: {e}")

            if reencrypted_count > 0:
                app.logger.info(f"Re-encrypted {reencrypted_count} loans with new recovery phrase for user {get_current_user_id()}")

        # Update user's recovery phrase hash
        c.execute("""
            UPDATE users
            SET master_recovery_key_hash = ?
            WHERE id = ?
        """, (new_recovery_phrase_hash, get_current_user_id()))
        conn.commit()
        conn.close()

        # Store new recovery phrase in session for dual-encrypting future loans
        session['master_recovery_key'] = new_recovery_phrase

        # Store recovery phrase for display (one-time view)
        session['show_master_recovery_phrase'] = new_recovery_phrase

        # Redirect to recovery phrase display page
        return redirect("/auth/recovery-phrase?regenerated=1")

    # GET request - show form
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash, master_recovery_key_hash FROM users WHERE id = ?", (get_current_user_id(),))
    user = c.fetchone()
    conn.close()

    has_password = user and user[0] is not None
    has_recovery_phrase = user and user[1] is not None

    if not has_password:
        flash("Please set up a password first before managing recovery phrases.", "error")
        return redirect("/settings/password")

    return render_template("settings_recovery.html", has_recovery_phrase=has_recovery_phrase)


@app.route("/settings/banks")
@login_required
def settings_banks():
    """List user's bank connections."""
    from services.connectors.registry import ConnectorRegistry

    connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())

    return render_template("settings_banks.html", connections=connections)


@app.route("/settings/banks/add")
@login_required
def settings_banks_add():
    """Show available bank connectors to add."""
    # Require email verification for bank connections
    if not is_email_verified():
        flash("Please verify your email to connect bank accounts. Check your inbox for the verification link.", "error")
        return redirect("/settings/banks")

    # Require password for zero-knowledge encryption
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash, encryption_salt FROM users WHERE id = ?", (get_current_user_id(),))
    user = c.fetchone()
    conn.close()

    if not user or not user[0]:
        flash("For security, bank credentials require password-based encryption. Please set up a password first.", "error")
        return redirect("/settings/password?redirect=banks")

    if not user[1]:  # Has password but no encryption salt
        flash("Please upgrade your account to enable bank connections.", "error")
        return redirect("/settings/password?redirect=banks")

    from services.connectors.registry import ConnectorRegistry

    connectors = ConnectorRegistry.get_all_connector_info()

    return render_template("settings_banks_add.html", connectors=connectors)


@app.route("/settings/banks/add/<connector_type>", methods=["GET", "POST"])
@login_required
def settings_banks_configure(connector_type):
    """Configure credentials for a specific connector."""
    from services.connectors.registry import ConnectorRegistry
    from services.encryption import encrypt_credentials

    # Get connector info
    connector_class = ConnectorRegistry.get_connector_class(connector_type)
    if not connector_class:
        flash("Invalid bank connector", "error")
        return redirect("/settings/banks/add")

    # Get connector info for form
    try:
        instance = connector_class(api_key="dummy")
        schema = connector_class.get_credential_schema()
        connector_info = {
            'name': instance.connector_name,
            'auth_type': schema['auth_type'],
            'fields': schema['fields']
        }
    except Exception as e:
        flash(f"Error loading connector: {str(e)}", "error")
        return redirect("/settings/banks/add")

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()

        # Collect credentials from form
        credentials = {}
        for field in connector_info['fields']:
            field_name = field['name']
            field_value = request.form.get(field_name, "").strip()

            if field.get('required') and not field_value:
                flash(f"{field['label']} is required", "error")
                return render_template("settings_banks_configure.html",
                                     connector_type=connector_type,
                                     connector_info=connector_info)

            credentials[field_name] = field_value

        # Test the connection
        try:
            connector = ConnectorRegistry.create_connector(connector_type, **credentials)
            if not connector or not connector.test_connection():
                log_event('bank_link_started', event_data={'connector_type': connector_type, 'success': False})
                flash("Connection test failed. Please check your credentials.", "error")
                return render_template("settings_banks_configure.html",
                                     connector_type=connector_type,
                                     connector_info=connector_info)
        except Exception as e:
            log_event('bank_link_started', event_data={'connector_type': connector_type, 'success': False})
            flash(f"Connection test failed: {str(e)}", "error")
            return render_template("settings_banks_configure.html",
                                 connector_type=connector_type,
                                 connector_info=connector_info)

        # Encrypt credentials using password-based zero-knowledge encryption
        try:
            from services.encryption import encrypt_credentials_with_password

            # Get user's password from session and salt from database
            user_password = session.get('user_password')
            if not user_password:
                flash("Please log in with your password to connect bank accounts.", "error")
                return redirect("/login")

            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT encryption_salt FROM users WHERE id = ?", (get_current_user_id(),))
            user = c.fetchone()

            if not user or not user[0]:
                flash("Encryption not set up. Please contact support.", "error")
                conn.close()
                return redirect("/settings/banks")

            encryption_salt = user[0]
            encrypted_creds = encrypt_credentials_with_password(credentials, user_password, encryption_salt)

        except Exception as e:
            flash(f"Failed to encrypt credentials: {str(e)}", "error")
            if 'conn' in locals():
                conn.close()
            return redirect("/settings/banks/add")

        # Save to database
        c.execute("""
            INSERT INTO bank_connections (user_id, connector_type, display_name, credentials_encrypted)
            VALUES (?, ?, ?, ?)
        """, (get_current_user_id(), connector_type, display_name, encrypted_creds))

        conn.commit()
        conn.close()

        # Log analytics event
        log_event('bank_link_success', event_data={'connector_type': connector_type})

        flash(f"Successfully connected to {connector_info['name']}!", "success")
        return redirect("/settings/banks")

    return render_template("settings_banks_configure.html",
                         connector_type=connector_type,
                         connector_info=connector_info)


@app.route("/settings/banks/<int:connection_id>/test", methods=["POST"])
@login_required
def settings_banks_test(connection_id):
    """Test a bank connection."""
    from services.connectors.registry import ConnectorRegistry

    # Get user password from session (required for decryption)
    user_password = session.get('user_password')
    if not user_password:
        flash("Please log in with your password to test bank connections.", "error")
        return redirect("/login")

    connector = ConnectorRegistry.create_from_connection(
        get_db_path(),
        connection_id,
        get_current_user_id(),
        user_password
    )

    if not connector:
        flash("Connection not found or credentials could not be decrypted", "error")
        return redirect("/settings/banks")

    try:
        if connector.test_connection():
            flash(f"Connection to {connector.connector_name} successful!", "success")
        else:
            flash(f"Connection to {connector.connector_name} failed", "error")
    except Exception as e:
        flash(f"Connection test failed: {str(e)}", "error")

    return redirect("/settings/banks")


@app.route("/settings/banks/<int:connection_id>/reset-sync", methods=["POST"])
@login_required
def settings_banks_reset_sync(connection_id):
    """Reset last_synced_at to force full re-sync on next login."""
    conn = get_db_connection()
    c = conn.cursor()

    # Verify ownership before resetting
    c.execute("""
        SELECT user_id FROM bank_connections
        WHERE id = ?
    """, (connection_id,))

    result = c.fetchone()

    if not result or result[0] != get_current_user_id():
        flash("Connection not found", "error")
        conn.close()
        return redirect("/settings/banks")

    # Reset last_synced_at
    c.execute("""
        UPDATE bank_connections
        SET last_synced_at = NULL
        WHERE id = ?
    """, (connection_id,))

    conn.commit()
    conn.close()

    flash("Sync history reset. Next login will perform a full re-sync from your oldest loan.", "success")
    return redirect("/settings/banks")


@app.route("/settings/banks/<int:connection_id>/delete", methods=["POST"])
@login_required
def settings_banks_delete(connection_id):
    """Delete a bank connection."""
    conn = get_db_connection()
    c = conn.cursor()

    # Verify ownership before deleting
    c.execute("""
        UPDATE bank_connections
        SET is_active = 0
        WHERE id = ? AND user_id = ?
    """, (connection_id, get_current_user_id()))

    if c.rowcount > 0:
        flash("Bank connection removed", "success")
    else:
        flash("Connection not found", "error")

    conn.commit()
    conn.close()

    return redirect("/settings/banks")


@app.route("/match", methods=["GET", "POST"])
@login_required
def match_transactions():
    # Require email verification for transaction matching
    if not is_email_verified():
        flash("Please verify your email to use transaction matching. Check your inbox for the verification link.", "error")
        return redirect("/")

    if request.method == "POST":
        from datetime import datetime, timedelta

        import_source = request.form.get("import_source", "csv")
        connector = None
        transactions = []

        # Check if trying to use bank API without access
        if import_source != "csv" and not has_feature(get_current_user_id(), 'bank_api'):
            flash("Bank API connections are only available on the Pro plan. Upgrade to access this feature!", "error")
            return redirect("/pricing")

        try:
            if import_source == "csv":
                # CSV Upload
                csv_content = request.form.get("transactions_csv")
                if not csv_content:
                    flash("Please provide CSV data", "error")
                    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
                    return render_template("match_upload.html", user_connections=user_connections)

                connector = CSVConnector(csv_content=csv_content)
                transactions = connector.get_transactions()
                all_transactions = transactions  # For CSV, all and filtered transactions are the same

            else:
                # Bank Connection - import_source is the connection_id
                try:
                    connection_id = int(import_source)
                except ValueError:
                    flash("Invalid bank connection", "error")
                    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
                    return render_template("match_upload.html", user_connections=user_connections)

                # Get user password from session (required for decryption)
                user_password = session.get('user_password')
                if not user_password:
                    flash("Please log in with your password to sync bank transactions.", "error")
                    return redirect("/login")

                connector = ConnectorRegistry.create_from_connection(
                    get_db_path(),
                    connection_id,
                    get_current_user_id(),
                    user_password
                )

                if not connector:
                    flash(f"Unable to connect to your bank. Please check your connection settings or log in with your password.", "error")
                    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
                    return render_template("match_upload.html", user_connections=user_connections)

                # Test connection first
                if not connector.test_connection():
                    flash(f"Unable to connect to {connector.connector_name}. Please try again or check your connection settings.", "error")
                    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
                    return render_template("match_upload.html", user_connections=user_connections)

                # Calculate since_date from date_range parameter
                since_date = None
                date_range = request.form.get("date_range", "30")

                if date_range == "custom":
                    # Use custom date from form
                    since_date = request.form.get("since_date")
                else:
                    # Calculate date based on number of days
                    try:
                        days = int(date_range)
                        since = datetime.now() - timedelta(days=days)
                        since_date = since.strftime("%Y-%m-%d")
                    except ValueError:
                        # Default to 30 days if invalid
                        since = datetime.now() - timedelta(days=30)
                        since_date = since.strftime("%Y-%m-%d")

                # Fetch transactions
                all_transactions = connector.get_transactions(since_date=since_date)
                # Keep ALL transactions (both incoming and outgoing) for now
                # We'll filter based on loan type during matching
                transactions = all_transactions

                flash(f"Successfully fetched {len(transactions)} transactions from {connector.connector_name} since {since_date}", "success")

            # Convert Transaction objects to dicts
            transaction_dicts = [t.to_dict() for t in transactions]
            all_transactions_dicts = [t.to_dict() for t in all_transactions]

            # Get all loans for current user with calculated repaid amounts AND loan_type
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""
                SELECT l.id, l.borrower, l.amount, l.note, l.date_borrowed,
                       COALESCE(SUM(at.amount), 0) as amount_repaid,
                       l.repayment_amount, l.repayment_frequency, l.bank_name, l.loan_type
                FROM loans l
                LEFT JOIN applied_transactions at ON l.id = at.loan_id
                WHERE l.user_id = ?
                GROUP BY l.id
            """, (get_current_user_id(),))
            loan_rows = c.fetchall()
            conn.close()

            # Convert to list of dicts
            loans = []
            for row in loan_rows:
                loans.append({
                    'id': row[0],
                    'borrower': row[1],
                    'amount': row[2],
                    'note': row[3] or '',
                    'date_borrowed': row[4],
                    'amount_repaid': row[5],
                    'repayment_amount': row[6],
                    'repayment_frequency': row[7],
                    'bank_name': row[8],
                    'loan_type': row[9]  # 'lending' or 'borrowing'
                })

            # Find matches
            matches = match_transactions_to_loans(transaction_dicts, loans)

            # Filter out already-applied transactions
            matches = filter_duplicate_transactions(matches)

            # Add unique IDs to each match to avoid index sync issues
            import hashlib
            for match in matches:
                # Create unique ID from transaction details + loan ID
                match_str = f"{match['transaction']['date']}-{match['transaction']['description']}-{match['transaction']['amount']}-{match['loan']['id']}"
                match['match_id'] = hashlib.md5(match_str.encode()).hexdigest()[:16]

            # Only store context transactions (within ±7 days of any match) to avoid session size limits
            context_transactions = []
            if matches:
                from datetime import datetime, timedelta

                # Get all match dates
                match_dates = set()
                for match in matches:
                    match_date_str = match['transaction']['date']
                    try:
                        match_date = datetime.strptime(match_date_str, '%Y-%m-%d')
                        match_dates.add(match_date)
                    except ValueError:
                        pass

                # Filter transactions within ±7 days of any match
                for t in all_transactions_dicts:
                    try:
                        t_date = datetime.strptime(t['date'], '%Y-%m-%d')
                        # Check if within ±7 days of any match date
                        for match_date in match_dates:
                            if abs((t_date - match_date).days) <= 7:
                                context_transactions.append(t)
                                break
                    except (ValueError, KeyError):
                        pass

            # Store matches and context transactions in DATABASE instead of session to avoid cookie size limits
            import secrets
            from datetime import datetime, timedelta

            session_key = secrets.token_urlsafe(16)
            expires_at = (datetime.now() + timedelta(hours=24)).isoformat()

            conn = get_db_connection()
            c = conn.cursor()

            # Clean up any old expired data for this user
            c.execute("DELETE FROM pending_matches_data WHERE user_id = ? AND expires_at < ?",
                     (get_current_user_id(), datetime.now().isoformat()))

            # Store the new data
            c.execute("""
                INSERT INTO pending_matches_data (user_id, session_key, matches_json, context_transactions_json, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (get_current_user_id(), session_key, json.dumps(matches), json.dumps(context_transactions), expires_at))
            conn.commit()
            conn.close()

            # Store only the session key in the actual session cookie (no caching to avoid size limits)
            session['pending_matches_key'] = session_key

            app.logger.info(f"Stored {len(matches)} matches and {len(context_transactions)} context transactions in database")

            return redirect("/match/review")

        except ConnectionError as e:
            flash(f"Connection error: {str(e)}", "error")
            user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
            return render_template("match_upload.html", user_connections=user_connections)
        except ValueError as e:
            flash(f"Authentication error: {str(e)}", "error")
            user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
            return render_template("match_upload.html", user_connections=user_connections)
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
            user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
            return render_template("match_upload.html", user_connections=user_connections)

    # GET request - show upload form
    user_id = get_current_user_id()
    has_bank_api_access = has_feature(user_id, 'bank_api')
    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), user_id) if has_bank_api_access else []
    tier = get_user_subscription_tier(user_id)

    return render_template("match_upload.html",
                         user_connections=user_connections,
                         has_bank_api=has_bank_api_access,
                         current_tier=tier)


@app.route("/match/review")
@login_required
def review_matches():
    """Show pending matches for review."""
    session_key = session.get('pending_matches_key')

    if not session_key:
        flash("No pending matches. Import transactions first.", "error")
        return redirect("/match")

    # Load directly from database (no session caching to avoid cookie size limits)
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        SELECT matches_json, context_transactions_json
        FROM pending_matches_data
        WHERE user_id = ? AND session_key = ? AND expires_at > ?
    """, (get_current_user_id(), session_key, datetime.now().isoformat()))

    result = c.fetchone()
    conn.close()

    if not result:
        flash("No pending matches found or session expired. Import transactions again.", "error")
        session.pop('pending_matches_key', None)
        return redirect("/match")

    matches = json.loads(result[0]) if result[0] else []
    all_transactions = json.loads(result[1]) if result[1] else []

    if not matches:
        flash("No pending matches. Import transactions first.", "error")
        return redirect("/match")

    return render_template("match_review.html", matches=matches, all_transactions=all_transactions)


@app.route("/apply-match", methods=["POST"])
@login_required
def apply_match():
    match_id = request.form.get("match_id")
    session_key = session.get('pending_matches_key')

    if match_id and session_key:
        conn = get_db_connection()
        c = conn.cursor()

        # Load matches from database
        c.execute("""
            SELECT id, matches_json
            FROM pending_matches_data
            WHERE user_id = ? AND session_key = ?
        """, (get_current_user_id(), session_key))

        result = c.fetchone()

        if result:
            db_id, matches_json = result
            matches = json.loads(matches_json)

            # Find the match by match_id instead of index
            match = None
            match_idx = None
            for idx, m in enumerate(matches):
                if m.get('match_id') == match_id:
                    match = m
                    match_idx = idx
                    break

            if match:
                loan_id = match['loan']['id']
                amount = match['transaction']['amount']
                transaction = match['transaction']

                # Verify loan ownership and get loan details
                c.execute("""
                    SELECT l.id, l.borrower, l.borrower_email, l.borrower_access_token, l.amount,
                           COALESCE(SUM(at.amount), 0) as current_repaid, l.loan_type, l.borrower_notifications_enabled
                    FROM loans l
                    LEFT JOIN applied_transactions at ON l.id = at.loan_id
                    WHERE l.id = ? AND l.user_id = ?
                    GROUP BY l.id
                """, (loan_id, get_current_user_id()))
                loan_details = c.fetchone()

                if loan_details:
                    loan_id_db, borrower_name, borrower_email, access_token, loan_amount, current_repaid, loan_type, notifications_enabled = loan_details

                    # For borrowing loans, transactions are negative (outgoing), but we store as positive repayments
                    # For lending loans, transactions are already positive (incoming)
                    amount_to_store = abs(transaction['amount'])

                    # Record the applied transaction (always store as positive)
                    c.execute("""
                        INSERT INTO applied_transactions (date, description, amount, loan_id)
                        VALUES (?, ?, ?, ?)
                    """, (transaction['date'], transaction['description'],
                          amount_to_store, loan_id))

                    # Remove the match and update database
                    matches.pop(match_idx)
                    c.execute("""
                        UPDATE pending_matches_data
                        SET matches_json = ?
                        WHERE id = ?
                    """, (json.dumps(matches), db_id))

                    conn.commit()

                    # Calculate new balance after this payment (using absolute value)
                    new_balance = loan_amount - (current_repaid + amount_to_store)

                    # Log analytics event
                    log_event('transaction_matched', event_data={'loan_id': loan_id, 'amount': amount_to_store})

                    # Send email notification if borrower has email, access token, notifications enabled, AND lender has email feature
                    if borrower_email and access_token and notifications_enabled and has_feature(get_current_user_id(), 'email_notifications'):
                        portal_link = f"{app.config['APP_URL']}/borrower/{access_token}"
                        lender_name = session.get('user_name') or session.get('user_email', 'Your lender')

                        try:
                            from services.email_sender import send_payment_notification_email
                            success, message = send_payment_notification_email(
                                to_email=borrower_email,
                                borrower_name=borrower_name,
                                portal_link=portal_link,
                                lender_name=lender_name,
                                payment_amount=amount_to_store,
                                payment_date=transaction['date'],
                                payment_description=transaction['description'],
                                new_balance=new_balance,
                                original_amount=loan_amount
                            )

                            if success:
                                app.logger.info(f"Payment notification sent to {borrower_email}")
                            else:
                                app.logger.warning(f"Failed to send payment notification: {message}")
                        except Exception as e:
                            app.logger.error(f"Error sending payment notification: {e}")

                    conn.close()
                    return ('', 204)  # Success, no content

        conn.close()

    return ('', 400)  # Bad request


@app.route("/reject-match", methods=["POST"])
@login_required
def reject_match():
    match_id = request.form.get("match_id")
    session_key = session.get('pending_matches_key')

    if match_id and session_key:
        conn = get_db_connection()
        c = conn.cursor()

        # Load matches from database
        c.execute("""
            SELECT id, matches_json
            FROM pending_matches_data
            WHERE user_id = ? AND session_key = ?
        """, (get_current_user_id(), session_key))

        result = c.fetchone()

        if result:
            db_id, matches_json = result
            matches = json.loads(matches_json)

            # Find the match by match_id instead of index
            match = None
            match_idx = None
            for idx, m in enumerate(matches):
                if m.get('match_id') == match_id:
                    match = m
                    match_idx = idx
                    break

            if match:
                loan_id = match['loan']['id']
                transaction = match['transaction']

                # Record the rejected match to prevent future suggestions
                # Store absolute value for consistency with applied_transactions
                c.execute("""
                    INSERT INTO rejected_matches (date, description, amount, loan_id)
                    VALUES (?, ?, ?, ?)
                """, (transaction['date'], transaction['description'],
                      abs(transaction['amount']), loan_id))

                # Remove the match and update database
                matches.pop(match_idx)
                c.execute("""
                    UPDATE pending_matches_data
                    SET matches_json = ?
                    WHERE id = ?
                """, (json.dumps(matches), db_id))

                conn.commit()
                conn.close()
                return ('', 204)  # Success, no content

        conn.close()

    return ('', 400)  # Bad request


@app.route("/analytics")
@admin_required
def analytics():
    """Analytics dashboard showing usage metrics. Admin only."""
    from datetime import datetime, timedelta

    conn = get_db_connection()
    c = conn.cursor()

    # Date calculations
    today = datetime.now().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)

    metrics = {}

    # Total users
    c.execute("SELECT COUNT(*) FROM users")
    metrics['total_users'] = c.fetchone()[0]

    # New signups (last 7 days, last 30 days) (excluding admin)
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'user_signed_up' AND created_at >= date('now', '-7 days') AND user_id != 1")
    metrics['new_users_7d'] = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'user_signed_up' AND created_at >= date('now', '-30 days') AND user_id != 1")
    metrics['new_users_30d'] = c.fetchone()[0]

    # DAU (Daily Active Users) - users with any event today (excluding admin)
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE date(created_at) = date('now')
          AND user_id != 1
    """)
    metrics['dau'] = c.fetchone()[0]

    # WAU (Weekly Active Users) (excluding admin)
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-7 days')
          AND user_id != 1
    """)
    metrics['wau'] = c.fetchone()[0]

    # MAU (Monthly Active Users) (excluding admin)
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-30 days')
          AND user_id != 1
    """)
    metrics['mau'] = c.fetchone()[0]

    # Total loans created
    c.execute("SELECT COUNT(*) FROM loans")
    metrics['total_loans'] = c.fetchone()[0]

    # Loans created (last 7 days, last 30 days) (excluding admin)
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'loan_created' AND created_at >= date('now', '-7 days') AND user_id != 1")
    metrics['loans_7d'] = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'loan_created' AND created_at >= date('now', '-30 days') AND user_id != 1")
    metrics['loans_30d'] = c.fetchone()[0]

    # Bank link funnel (excluding admin)
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'bank_link_started' AND created_at >= date('now', '-30 days') AND user_id != 1")
    bank_started = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'bank_link_success' AND created_at >= date('now', '-30 days') AND user_id != 1")
    bank_success = c.fetchone()[0]

    metrics['bank_link_started'] = bank_started
    metrics['bank_link_success'] = bank_success
    metrics['bank_link_conversion'] = (bank_success / bank_started * 100) if bank_started > 0 else 0

    # Retention: users active this week who were also active last week (excluding admin)
    c.execute("""
        SELECT COUNT(DISTINCT e1.user_id)
        FROM events e1
        WHERE e1.created_at >= date('now', '-7 days')
          AND e1.user_id != 1
          AND e1.user_id IN (
              SELECT DISTINCT user_id
              FROM events
              WHERE created_at >= date('now', '-14 days')
                AND created_at < date('now', '-7 days')
                AND user_id != 1
          )
    """)
    retained_users = c.fetchone()[0]

    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-14 days')
          AND created_at < date('now', '-7 days')
          AND user_id != 1
    """)
    previous_week_users = c.fetchone()[0]

    metrics['retention_rate'] = (retained_users / previous_week_users * 100) if previous_week_users > 0 else 0

    # Recent events (last 20) (excluding admin)
    c.execute("""
        SELECT e.event_name, e.created_at, u.email, e.event_data
        FROM events e
        LEFT JOIN users u ON e.user_id = u.id
        WHERE e.user_id != 1
        ORDER BY e.created_at DESC
        LIMIT 20
    """)
    recent_events = []
    for row in c.fetchall():
        event_name, created_at, email, event_data = row
        recent_events.append({
            'event_name': event_name,
            'created_at': created_at,
            'user_email': email if email else 'Anonymous',
            'event_data': json.loads(event_data) if event_data else {}
        })

    # Event counts by type (last 30 days) (excluding admin)
    c.execute("""
        SELECT event_name, COUNT(*) as count
        FROM events
        WHERE created_at >= date('now', '-30 days')
          AND user_id != 1
        GROUP BY event_name
        ORDER BY count DESC
    """)
    event_counts = c.fetchall()

    conn.close()

    return render_template("analytics.html",
                         metrics=metrics,
                         recent_events=recent_events,
                         event_counts=event_counts)


@app.route("/sync-banks", methods=["POST"])
@login_required
def sync_banks_now():
    """Manually trigger bank sync."""
    user_password = session.get('user_password')
    if not user_password:
        flash("Please log in with your password to sync bank transactions.", "error")
        return redirect("/login")

    try:
        from services.auto_sync import sync_all_bank_connections
        sync_results = sync_all_bank_connections(get_db_path(), get_current_user_id(), user_password)

        # Store results in session for dashboard display
        session['sync_results'] = {
            'auto_applied_count': len(sync_results['auto_applied']),
            'pending_review_count': len(sync_results['pending_review']),
            'connections_synced': sync_results['connections_synced'],
            'total_transactions_fetched': sync_results['total_transactions_fetched'],
            'new_transactions_found': sync_results['new_transactions_found'],
            'already_applied_count': sync_results['already_applied_count'],
            'connection_details': sync_results['connection_details'],
            'errors': sync_results['errors'],
            'timestamp': datetime.now().isoformat()
        }

        # Store pending matches for review page
        if sync_results['pending_review']:
            session['pending_matches'] = [
                {
                    'transaction': t,  # Already a dict
                    'loan': l,
                    'confidence': c
                }
                for t, l, c in sync_results['pending_review']
            ]

        if sync_results['new_transactions_found'] > 0:
            flash(f"Sync complete! Found {sync_results['new_transactions_found']} new transaction(s).", "success")
        else:
            flash("Sync complete. No new transactions found.", "info")

        if sync_results['errors']:
            for error in sync_results['errors']:
                flash(error, "error")

    except Exception as e:
        app.logger.error(f"Manual sync failed: {str(e)}")
        flash(f"Sync failed: {str(e)}", "error")

    return redirect("/")


@app.route("/match/review-pending")
@login_required
def review_pending_auto_matches():
    """Review pending matches from auto-sync."""
    pending_matches = session.get('pending_matches', [])

    if not pending_matches:
        flash("No pending matches to review.", "info")
        return redirect("/")

    return render_template("match_review_pending.html", matches=pending_matches)


@app.route("/match/apply-pending", methods=["POST"])
@login_required
def apply_pending_match():
    """Apply a pending match from auto-sync."""
    match_index = int(request.form.get("match_index", -1))
    pending_matches = session.get('pending_matches', [])

    if match_index < 0 or match_index >= len(pending_matches):
        flash("Invalid match.", "error")
        return redirect("/match/review-pending")

    match = pending_matches[match_index]
    transaction = match['transaction']
    loan = match['loan']
    confidence = match['confidence']

    # Apply the match
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        INSERT INTO applied_transactions
        (date, description, amount, loan_id, auto_applied, confidence_score)
        VALUES (?, ?, ?, ?, 0, ?)
    """, (transaction['date'], transaction['description'], transaction['amount'],
          loan['id'], confidence))

    conn.commit()
    conn.close()

    # Remove from pending list
    pending_matches.pop(match_index)
    session['pending_matches'] = pending_matches

    flash(f"Applied ${transaction['amount']:.2f} payment to {loan['borrower']}'s loan.", "success")

    if pending_matches:
        return redirect("/match/review-pending")
    else:
        return redirect("/")


@app.route("/match/reject-pending", methods=["POST"])
@login_required
def reject_pending_match():
    """Reject a pending match from auto-sync."""
    match_index = int(request.form.get("match_index", -1))
    pending_matches = session.get('pending_matches', [])

    if match_index < 0 or match_index >= len(pending_matches):
        flash("Invalid match.", "error")
        return redirect("/match/review-pending")

    match = pending_matches[match_index]
    transaction = match['transaction']
    loan = match['loan']

    # Record rejection
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        INSERT INTO rejected_matches (date, description, amount, loan_id)
        VALUES (?, ?, ?, ?)
    """, (transaction['date'], transaction['description'], transaction['amount'], loan['id']))

    conn.commit()
    conn.close()

    # Remove from pending list
    pending_matches.pop(match_index)
    session['pending_matches'] = pending_matches

    flash("Match rejected.", "info")

    if pending_matches:
        return redirect("/match/review-pending")
    else:
        return redirect("/")


@app.route("/match/undo/<int:transaction_id>", methods=["POST"])
@login_required
def undo_auto_match(transaction_id):
    """Undo an auto-applied match."""
    conn = get_db_connection()
    c = conn.cursor()

    # Verify ownership and that it was auto-applied
    c.execute("""
        SELECT at.id, at.loan_id, at.amount, l.user_id
        FROM applied_transactions at
        JOIN loans l ON l.id = at.loan_id
        WHERE at.id = ? AND at.auto_applied = 1
    """, (transaction_id,))

    result = c.fetchone()

    if not result:
        flash("Transaction not found or not eligible for undo.", "error")
        conn.close()
        return redirect("/")

    trans_id, loan_id, amount, owner_id = result

    if owner_id != get_current_user_id():
        flash("Unauthorized", "error")
        conn.close()
        return redirect("/")

    # Delete the applied transaction
    c.execute("DELETE FROM applied_transactions WHERE id = ?", (transaction_id,))
    conn.commit()
    conn.close()

    log_event('auto_match_undone', event_data={'transaction_id': transaction_id, 'loan_id': loan_id})

    flash(f"Undid auto-applied payment of ${amount:.2f}. The transaction can be re-matched if needed.", "success")
    return redirect("/")


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )


@app.route("/", methods=["GET", "POST"])
def index():
    # Public landing
    app.logger.info(f"Index route hit. Session user_id: {session.get('user_id')}")
    if not session.get("user_id"):
        app.logger.info("No user_id in session, showing landing page")
        return render_template("landing.html")

    # Create loan (POST)
    if request.method == "POST":
        redirect_to = _handle_index_post(request.form)
        return redirect(redirect_to)

    # Dashboard (GET)
    context_or_redirect = _build_dashboard_context()
    if isinstance(context_or_redirect, dict):
        return render_template(
            "index.html",
            loans=context_or_redirect["loans"],
            app_url=app.config["APP_URL"],
            email_verified=context_or_redirect["email_verified"],
            has_password=context_or_redirect["has_password"],
            needs_password_unlock=context_or_redirect.get("needs_password_unlock", False),
        )
    # it's a redirect target
    return redirect(context_or_redirect)


@app.route("/unlock", methods=["POST"])
@login_required
def unlock_with_password():
    """Unlock encrypted loan data by verifying password or recovery phrase."""
    password = request.form.get("password")
    recovery_phrase = request.form.get("recovery_phrase")

    if not password and not recovery_phrase:
        flash("Please enter your password or recovery phrase", "error")
        return redirect("/")

    conn = get_db_connection()
    c = conn.cursor()

    # Get user's password hash and recovery key hash
    c.execute("SELECT password_hash, master_recovery_key_hash, encryption_salt FROM users WHERE id = ?",
              (get_current_user_id(),))
    user_row = c.fetchone()
    conn.close()

    if not user_row:
        flash("User not found", "error")
        return redirect("/")

    password_hash, recovery_key_hash, encryption_salt = user_row

    # Try password first
    if password:
        if not password_hash:
            flash("No password set for this account", "error")
            return redirect("/")

        from werkzeug.security import check_password_hash
        if check_password_hash(password_hash, password):
            # Password correct - store in session for decryption
            session['user_password'] = password
            flash("Loans unlocked successfully!", "success")
            return redirect("/")
        else:
            flash("Incorrect password", "error")
            return redirect("/")

    # Try recovery phrase
    if recovery_phrase:
        if not recovery_key_hash:
            flash("No recovery phrase set for this account", "error")
            return redirect("/")

        from werkzeug.security import check_password_hash
        from services.encryption import normalize_recovery_phrase

        normalized_phrase = normalize_recovery_phrase(recovery_phrase)

        if check_password_hash(recovery_key_hash, normalized_phrase):
            # Recovery phrase correct - store in session for decryption
            session['user_password'] = normalized_phrase
            # Also store the recovery key itself for future loan creation
            session['master_recovery_key'] = normalized_phrase
            flash("Loans unlocked successfully with recovery phrase!", "success")
            return redirect("/")
        else:
            flash("Incorrect recovery phrase", "error")
            return redirect("/")

    return redirect("/")


# -----------------------------
# Internal helpers (app.py only)
# -----------------------------

def _handle_index_post(form):
    """Handle creating a loan from the dashboard form."""
    borrower = form.get("borrower")
    bank_name = form.get("bank_name")
    date_borrowed = form.get("date_borrowed")
    amount = form.get("amount")
    note = form.get("note")
    repayment_amount = form.get("repayment_amount")
    repayment_frequency = form.get("repayment_frequency")
    loan_type = form.get("loan_type", "lending")
    onboarding = form.get("onboarding")

    # Gate: email verification limits
    if not is_email_verified():
        if get_unverified_loan_count() >= 2:
            flash(
                "Please verify your email to create more loans. "
                "Check your inbox for the verification link.",
                "error",
            )
            return "/"

    # Gate: subscription limits
    current_loans, max_loans, can_create = check_loan_limit()
    if not can_create:
        tier_name = get_user_subscription_tier().title()
        if max_loans is not None:
            flash(
                f"You've reached the limit of {max_loans} loans on the {tier_name} plan. "
                "Upgrade to create more!",
                "error",
            )
        return "/pricing"

    # Create loan if required fields present
    if borrower and amount:
        if not _create_encrypted_loan(
            borrower=borrower,
            bank_name=bank_name,
            date_borrowed=date_borrowed,
            amount_str=amount,
            note=note,
            repayment_amount_str=repayment_amount,
            repayment_frequency=repayment_frequency,
            loan_type=loan_type,
        ):
            # creation failed with a user-facing flash already
            return "/"

        # analytics (for the user's own dashboard metrics)
        try:
            log_event("loan_created", event_data={"loan_type": loan_type, "amount": float(amount)})
        except Exception:
            app.logger.exception("Failed to log loan_created event")

    # Complete onboarding flow if flagged
    if onboarding == "1":
        return "/onboarding?step=complete"

    return "/"


def _create_encrypted_loan(
    *,
    borrower: str,
    bank_name: str | None,
    date_borrowed: str | None,
    amount_str: str,
    note: str | None,
    repayment_amount_str: str | None,
    repayment_frequency: str | None,
    loan_type: str,
) -> bool:
    """Do the encryption + insert. Returns True on success and flashes on failure."""
    from services.encryption import (
        generate_dek,
        create_token_from_dek,
        encrypt_dek_with_password,
        encrypt_dek_with_recovery_phrase,
    )

    conn = get_db_connection()
    c = conn.cursor()
    try:
        user_password = get_user_password_from_session()
        encryption_salt = get_user_encryption_salt()
        if not user_password or not encryption_salt:
            flash("Please set up a password to create encrypted loans.", "error")
            return False

        dek = generate_dek()
        access_token = create_token_from_dek(dek)
        encrypted_dek = encrypt_dek_with_password(dek, user_password, encryption_salt)

        encrypted_dek_recovery = None
        master_recovery_key = session.get("master_recovery_key")
        if master_recovery_key:
            encrypted_dek_recovery = encrypt_dek_with_recovery_phrase(dek, master_recovery_key, encryption_salt)

        loan_data = {
            "borrower": borrower,
            "bank_name": bank_name or None,
            "amount": float(amount_str),
            "note": note,
            "borrower_email": None,
            "repayment_amount": float(repayment_amount_str) if repayment_amount_str else None,
            "repayment_frequency": repayment_frequency or None,
        }

        encrypted_fields = encrypt_loan_data(loan_data, dek)

        c.execute(
            """
            INSERT INTO loans (
                borrower_encrypted, bank_name_encrypted, amount_encrypted, note_encrypted,
                date_borrowed, repayment_amount_encrypted, repayment_frequency_encrypted,
                user_id, borrower_access_token, loan_type, encrypted_dek, encrypted_dek_recovery
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                encrypted_fields["borrower_encrypted"],
                encrypted_fields["bank_name_encrypted"],
                encrypted_fields["amount_encrypted"],
                encrypted_fields["note_encrypted"],
                date_borrowed,
                encrypted_fields["repayment_amount_encrypted"],
                encrypted_fields["repayment_frequency_encrypted"],
                get_current_user_id(),
                access_token,
                loan_type,
                encrypted_dek,
                encrypted_dek_recovery,
            ),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError as e:
        app.logger.error(
            "Failed to create loan (likely needs migrations for nullable plaintext columns): %s",
            e,
        )
        flash("Database error. Please restart the application to run migrations.", "error")
        return False
    except Exception:
        app.logger.exception("Unhandled error creating encrypted loan")
        flash("Unexpected error creating loan.", "error")
        return False
    finally:
        conn.close()


def _build_dashboard_context():
    """
    Returns either:
      - dict for template context (loans, email_verified, has_password)
      - or a string URL to redirect to (e.g., '/login')
    """
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    try:
        user_password = get_user_password_from_session()

        # Count loans first
        c.execute("SELECT COUNT(*) FROM loans WHERE user_id = ?", (get_current_user_id(),))
        loan_count = c.fetchone()[0]

        if not user_password and loan_count > 0:
            # Distinguish between "has password in DB" vs "recovery login only" vs "no password"
            c.execute("SELECT password_hash FROM users WHERE id = ?", (get_current_user_id(),))
            user_row = c.fetchone()
            has_password_in_db = user_row and user_row[0] is not None

            if has_password_in_db:
                # User logged in via magic link but has encrypted loans
                # Show dashboard with password unlock prompt
                return {
                    "loans": [],
                    "email_verified": is_email_verified(),
                    "has_password": True,
                    "needs_password_unlock": True,  # Show password unlock form
                }
            if session.get("logged_in_via_recovery"):
                flash("Please reset your password to access your encrypted loan data.", "error")
                return "/settings/password?redirect=dashboard"

            flash("Please set up a password to secure your loan data with encryption.", "error")
            return "/settings/password?redirect=dashboard"

        # No password and no loans: show empty dashboard
        if not user_password:
            return {
                "loans": [],
                "email_verified": is_email_verified(),
                "has_password": False,
            }

        # Otherwise load + decrypt loans
        c.execute(
            """
            SELECT l.id, l.borrower, l.amount, l.note, l.date_borrowed,
                   l.borrower_encrypted, l.amount_encrypted, l.note_encrypted,
                   l.bank_name, l.bank_name_encrypted,
                   l.repayment_amount, l.repayment_amount_encrypted,
                   l.repayment_frequency, l.repayment_frequency_encrypted,
                   l.borrower_email, l.borrower_email_encrypted,
                   l.created_at, l.borrower_access_token, l.loan_type, l.encrypted_dek
            FROM loans l
            WHERE l.user_id = ?
            ORDER BY l.created_at DESC
            """,
            (get_current_user_id(),),
        )
        encrypted_rows = c.fetchall()
        loans = decrypt_loans(c, encrypted_rows, user_password)

        return {
            "loans": loans,
            "email_verified": is_email_verified(),
            "has_password": True,
        }
    finally:
        conn.close()


if __name__ == "__main__":
    # Avoid double-run in Flask’s reloader child
    if os.getenv("WERKZEUG_RUN_MAIN") != "true":
        with app.app_context():
            init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
