from flask_wtf import CSRFProtect
from flask_socketio import SocketIO
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

# Socket.IO needs to be initialized before CSRF to avoid conflicts
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False, engineio_logger=False, async_mode='threading')

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

from routes.borrower import borrower_bp
app.register_blueprint(borrower_bp)
app.logger.info("Registered borrower blueprint")
print("✅ Registered borrower blueprint")

from routes.admin import admin_bp, analytics_view
from helpers.decorators import admin_required as admin_required_decorator, login_required
app.register_blueprint(admin_bp)
app.logger.info("Registered admin blueprint")
print("✅ Registered admin blueprint")

from routes.matching import (
    matching_bp,
    apply_match_handler,
    reject_match_handler,
    sync_banks_handler
)
app.register_blueprint(matching_bp)
app.logger.info("Registered matching blueprint")
print("✅ Registered matching blueprint")

from routes.settings import settings_bp
app.register_blueprint(settings_bp)
app.logger.info("Registered settings blueprint")
print("✅ Registered settings blueprint")

from routes.subscription import subscription_bp
app.register_blueprint(subscription_bp)
app.logger.info("Registered subscription blueprint")
print("✅ Registered subscription blueprint")

from routes.support import support_bp, register_socketio_handlers
app.register_blueprint(support_bp)
register_socketio_handlers(socketio)
app.logger.info("Registered support blueprint with Socket.IO handlers")
print("✅ Registered support blueprint")

# Register analytics route separately (at /analytics, not /admin/analytics)
@app.route("/analytics")
@admin_required_decorator
def analytics():
    return analytics_view()

# Register matching routes separately for backward compatibility (not under /match prefix)
@app.route("/apply-match", methods=["POST"])
@login_required
def apply_match():
    return apply_match_handler()

@app.route("/reject-match", methods=["POST"])
@login_required
def reject_match():
    return reject_match_handler()

@app.route("/sync-banks", methods=["POST"])
@login_required
def sync_banks_now():
    return sync_banks_handler()


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


# Borrower routes moved to routes/borrower.py blueprint


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


# Subscription routes moved to routes/subscription.py blueprint
# /pricing, /subscribe/<tier>, /checkout/success, /checkout/cancel, /webhooks/stripe, /billing


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


# Settings routes moved to routes/settings.py blueprint
# /settings, /settings/password, /settings/password/success, /settings/recovery
# /settings/banks, /settings/banks/add, /settings/banks/add/<connector_type>
# /settings/banks/<id>/test, /settings/banks/<id>/reset-sync, /settings/banks/<id>/delete


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
    # Avoid double-run in Flask's reloader child
    if os.getenv("WERKZEUG_RUN_MAIN") != "true":
        with app.app_context():
            init_db()
    socketio.run(app, debug=True, host="127.0.0.1", port=5000)
