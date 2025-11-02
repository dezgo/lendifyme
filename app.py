import sqlite3
import json
import secrets
import time
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from services import migrations
from services.transaction_matcher import match_transactions_to_loans
from services.connectors.registry import ConnectorRegistry
from services.connectors.csv_connector import CSVConnector
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory
from flask_mail import Mail, Message
from functools import wraps
from services.auth_helpers import (
    generate_recovery_codes,
    verify_recovery_code,
    generate_magic_link_token,
    get_magic_link_expiry,
    is_magic_link_expired
)
from services.email_sender import send_magic_link_email
import os
import logging
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import LoggingIntegration


# Load environment variables from .env
load_dotenv()

ENV = os.environ.get("FLASK_ENV") or "production"

sentry_sdk.init(
    dsn="https://930407a171aa9648e71bb8c75cf738b1@o4510260806352896.ingest.us.sentry.io/4510260812054528",
    environment=ENV,          # ← This is the key bit
    integrations=[
        FlaskIntegration(),
        LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
    ],
    send_default_pii=True,
)

app = Flask(__name__)

# Config
app.config['DATABASE'] = 'lendifyme.db'
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

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


def get_db_path():
    """Get database path from config (allows tests to override)."""
    return app.config.get('DATABASE', 'lendifyme.db')


def filter_duplicate_transactions(matches):
    """Filter out transactions that have already been applied or rejected."""
    conn = sqlite3.connect(get_db_path())
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
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login', next=request.url))

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

    conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result[0] if result else None


def get_user_password_from_session():
    """Get the user's password from session (needed for decryption)."""
    return session.get('user_password')


def encrypt_loan_data(loan_data, dek):
    """
    Encrypt sensitive loan fields using envelope encryption.

    Args:
        loan_data: Dict with loan fields
        dek: Data encryption key (bytes)

    Returns:
        Dict with encrypted fields
    """
    from services.encryption import encrypt_field

    return {
        'borrower_encrypted': encrypt_field(loan_data.get('borrower'), dek) if loan_data.get('borrower') else None,
        'amount_encrypted': encrypt_field(str(loan_data.get('amount')), dek) if loan_data.get('amount') is not None else None,
        'note_encrypted': encrypt_field(loan_data.get('note'), dek) if loan_data.get('note') else None,
        'bank_name_encrypted': encrypt_field(loan_data.get('bank_name'), dek) if loan_data.get('bank_name') else None,
        'borrower_email_encrypted': encrypt_field(loan_data.get('borrower_email'), dek) if loan_data.get('borrower_email') else None,
        'repayment_amount_encrypted': encrypt_field(str(loan_data.get('repayment_amount')), dek) if loan_data.get('repayment_amount') is not None else None,
        'repayment_frequency_encrypted': encrypt_field(loan_data.get('repayment_frequency'), dek) if loan_data.get('repayment_frequency') else None,
    }


def decrypt_loan_data(loan_row, dek):
    """
    Decrypt loan data from database row.

    Args:
        loan_row: Database row (dict or tuple)
        dek: Data encryption key (bytes)

    Returns:
        Dict with decrypted loan data
    """
    from services.encryption import decrypt_field

    # Handle both dict and tuple row formats
    if isinstance(loan_row, dict):
        get_field = lambda key: loan_row.get(key)
    else:
        # Assume it's a row from c.fetchone() - need column names
        # This will be handled by the calling code
        return None

    try:
        return {
            'borrower': decrypt_field(get_field('borrower_encrypted'), dek) if get_field('borrower_encrypted') else get_field('borrower'),
            'amount': float(decrypt_field(get_field('amount_encrypted'), dek)) if get_field('amount_encrypted') else get_field('amount'),
            'note': decrypt_field(get_field('note_encrypted'), dek) if get_field('note_encrypted') else get_field('note'),
            'bank_name': decrypt_field(get_field('bank_name_encrypted'), dek) if get_field('bank_name_encrypted') else get_field('bank_name'),
            'borrower_email': decrypt_field(get_field('borrower_email_encrypted'), dek) if get_field('borrower_email_encrypted') else get_field('borrower_email'),
            'repayment_amount': float(decrypt_field(get_field('repayment_amount_encrypted'), dek)) if get_field('repayment_amount_encrypted') else get_field('repayment_amount'),
            'repayment_frequency': decrypt_field(get_field('repayment_frequency_encrypted'), dek) if get_field('repayment_frequency_encrypted') else get_field('repayment_frequency'),
        }
    except Exception as e:
        app.logger.error(f"Failed to decrypt loan data: {e}")
        return None


def get_loan_dek(loan_id, user_password=None, borrower_token=None):
    """
    Get the DEK for a specific loan.

    Can decrypt using either:
    - User's password (for lender access)
    - Borrower access token (for borrower portal)

    Args:
        loan_id: The loan ID
        user_password: User's password (optional if using token)
        borrower_token: Borrower access token (optional if using password)

    Returns:
        bytes: The decrypted DEK, or None if unable to decrypt
    """
    from services.encryption import (
        decrypt_dek_with_password,
        extract_dek_from_token,
        encrypt_dek_with_password
    )

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    if borrower_token:
        # Borrower access: extract DEK directly from token
        try:
            dek = extract_dek_from_token(borrower_token)
            conn.close()
            return dek
        except Exception as e:
            app.logger.error(f"Failed to extract DEK from token: {e}")
            conn.close()
            return None

    elif user_password:
        # Lender access: decrypt DEK with password
        c.execute("""
            SELECT encrypted_dek, user_id
            FROM loans
            WHERE id = ?
        """, (loan_id,))

        result = c.fetchone()
        if not result:
            conn.close()
            return None

        encrypted_dek, user_id = result

        # Check for migration placeholder
        if encrypted_dek and encrypted_dek.startswith("MIGRATION_PENDING:"):
            # Extract DEK from placeholder and re-encrypt it properly
            dek_str = encrypted_dek.replace("MIGRATION_PENDING:", "")
            dek = dek_str.encode('utf-8')

            # Get user's encryption salt
            c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
            salt_result = c.fetchone()

            if salt_result and salt_result[0]:
                # Re-encrypt DEK with user's password
                new_encrypted_dek = encrypt_dek_with_password(dek, user_password, salt_result[0])

                # Update database
                c.execute("UPDATE loans SET encrypted_dek = ? WHERE id = ?",
                         (new_encrypted_dek, loan_id))
                conn.commit()

                app.logger.info(f"Finalized DEK encryption for loan {loan_id}")

            conn.close()
            return dek

        # Normal case: decrypt DEK
        c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
        salt_result = c.fetchone()
        conn.close()

        if not salt_result or not salt_result[0]:
            return None

        try:
            return decrypt_dek_with_password(encrypted_dek, user_password, salt_result[0])
        except Exception as e:
            app.logger.error(f"Failed to decrypt DEK for loan {loan_id}: {e}")
            return None

    conn.close()
    return None


# ============================================================================
# SUBSCRIPTION HELPER FUNCTIONS
# ============================================================================

def get_user_subscription_tier(user_id=None):
    """
    Get user's current subscription tier (free/basic/pro).

    Args:
        user_id: User ID (defaults to current user)

    Returns:
        str: 'free', 'basic', or 'pro'
    """
    if user_id is None:
        user_id = get_current_user_id()

    if not user_id:
        return 'free'

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT subscription_tier FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result[0] if result else 'free'


def get_subscription_limits(tier):
    """
    Get subscription limits and features for a tier.

    Args:
        tier: 'free', 'basic', or 'pro'

    Returns:
        dict: Features and limits for the tier
    """
    import json

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("""
        SELECT max_loans, features_json
        FROM subscription_plans
        WHERE tier = ? AND active = 1
    """, (tier,))
    result = c.fetchone()
    conn.close()

    if not result:
        # Fallback defaults
        return {
            'max_loans': 3,
            'manual_repayment': True,
            'csv_import': True,
            'borrower_portal': True,
            'email_notifications': False,
            'transaction_export': False,
            'bank_api': False,
            'analytics': False
        }

    max_loans, features_json = result
    features = json.loads(features_json)
    features['max_loans'] = max_loans  # Ensure max_loans is in the dict

    return features


def check_loan_limit(user_id=None):
    """
    Check if user can create more loans.

    Args:
        user_id: User ID (defaults to current user)

    Returns:
        tuple: (current_count, max_allowed, can_create)
    """
    if user_id is None:
        user_id = get_current_user_id()

    if not user_id:
        return (0, 3, False)

    # Get user's tier
    tier = get_user_subscription_tier(user_id)
    limits = get_subscription_limits(tier)
    max_loans = limits.get('max_loans')

    # Count current active loans
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM loans WHERE user_id = ?", (user_id,))
    current_count = c.fetchone()[0]
    conn.close()

    # None means unlimited
    if max_loans is None:
        return (current_count, None, True)

    can_create = current_count < max_loans
    return (current_count, max_loans, can_create)


def has_feature(user_id, feature_name):
    """
    Check if user has access to a specific feature.

    Args:
        user_id: User ID
        feature_name: Feature key (e.g., 'bank_api', 'email_notifications', 'transaction_export')

    Returns:
        bool: True if user has access to the feature
    """
    if not user_id:
        return False

    tier = get_user_subscription_tier(user_id)
    limits = get_subscription_limits(tier)

    return limits.get(feature_name, False)


def is_trial_active(user_id=None):
    """
    Check if user is currently in a trial period.

    Args:
        user_id: User ID (defaults to current user)

    Returns:
        bool: True if trial is active
    """
    from datetime import datetime

    if user_id is None:
        user_id = get_current_user_id()

    if not user_id:
        return False

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT trial_ends_at FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    if not result or not result[0]:
        return False

    trial_ends_at = datetime.fromisoformat(result[0])
    return datetime.now() < trial_ends_at


def generate_borrower_access_token():
    """Generate a secure random token for borrower access."""
    return secrets.token_urlsafe(32)


def log_event(event_name, user_id=None, event_data=None):
    """
    Log an analytics event to the database.

    Args:
        event_name: Name of the event (e.g., 'user_signed_up', 'loan_created')
        user_id: Optional user ID (defaults to current user if logged in)
        event_data: Optional dict with additional context (stored as JSON)
    """
    try:
        import json

        # Use current user if not specified
        if user_id is None:
            user_id = get_current_user_id()

        # Get session ID if available
        session_id = session.get('_id', None)

        # Convert event_data to JSON if provided
        event_data_json = json.dumps(event_data) if event_data else None

        conn = sqlite3.connect(get_db_path())
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


def init_db():
    conn = sqlite3.connect(get_db_path())
    migrations.run_migrations(conn)
    conn.close()


init_db()


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration - super simple, just email."""
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        # Anti-spam measure 1: Honeypot field check
        # Bots often fill in all fields, including hidden ones
        honeypot = request.form.get("website", "")
        if honeypot:
            app.logger.warning(f"Registration blocked: honeypot filled for {email}")
            # Don't tell the bot they failed - just pretend it worked
            flash("Thanks for signing up! Check your email to verify your account.", "success")
            return render_template("register.html")

        # Anti-spam measure 2: Time-based validation
        # Reject submissions that are unrealistically fast (< 2 seconds)
        form_timestamp = request.form.get("form_timestamp", "")
        if form_timestamp:
            try:
                form_load_time = int(form_timestamp)
                current_time = int(time.time() * 1000)  # Convert to milliseconds
                time_taken = (current_time - form_load_time) / 1000  # Convert to seconds

                if time_taken < 1:
                    app.logger.warning(f"Registration blocked: too fast ({time_taken}s) for {email}")
                    flash("Please take a moment to review the form.", "error")
                    return render_template("register.html")
            except (ValueError, TypeError):
                app.logger.warning(f"Registration blocked: invalid timestamp for {email}")
                flash("Invalid form submission. Please try again.", "error")
                return render_template("register.html")

        # Anti-spam measure 3: Rate limiting by IP
        # Allow max 3 registration attempts per IP per hour
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        rate_limit_key = f"register_attempts:{client_ip}"

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        # Check rate limit (stored in a simple table)
        c.execute("""
            SELECT COUNT(*) FROM rate_limits
            WHERE key = ? AND timestamp > datetime('now', '-1 hour')
        """, (rate_limit_key,))
        attempt_count = c.fetchone()[0]

        if attempt_count >= 3 and ENV != 'development':
            app.logger.warning(f"Registration blocked: rate limit exceeded for IP {client_ip}")
            flash("Too many registration attempts. Please try again later.", "error")
            conn.close()
            return render_template("register.html")

        # Record this attempt
        c.execute("""
            INSERT INTO rate_limits (key, timestamp) VALUES (?, datetime('now'))
        """, (rate_limit_key,))
        conn.commit()
        conn.close()

        if not email:
            flash("Email is required", "error")
            return render_template("register.html")

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        # Check if email already exists
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = c.fetchone()
        if existing:
            flash("Email already registered. Use 'Login' to sign in.", "error")
            conn.close()
            return redirect(url_for('login'))

        # Generate recovery codes (for account recovery)
        plain_codes, hashed_codes_json = generate_recovery_codes()

        # Generate verification token
        from services.auth_helpers import generate_verification_token, get_verification_expiry
        verification_token = generate_verification_token()
        verification_sent_at = get_verification_expiry(hours=0)  # Current time

        # Create user - no name, no password required initially
        c.execute("""
            INSERT INTO users (email, recovery_codes, auth_provider, onboarding_completed, email_verified, verification_token, verification_sent_at)
            VALUES (?, ?, 'magic_link', 0, 0, ?, ?)
        """, (email, hashed_codes_json, verification_token, verification_sent_at))
        conn.commit()

        user_id = c.lastrowid
        conn.close()

        # Log analytics event
        log_event('user_signed_up', user_id=user_id, event_data={'email': email})

        # Send verification email
        verification_link = f"{app.config['APP_URL']}/auth/verify/{verification_token}"
        from services.email_sender import send_verification_email
        try:
            success, message = send_verification_email(email, None, verification_link)
            if success:
                app.logger.info(f"Verification email sent to {email}")
            else:
                app.logger.warning(f"Failed to send verification email: {message}")
        except Exception as e:
            app.logger.error(f"Error sending verification email: {e}")

        # Log them in immediately (even though unverified - they can still use basic features)
        session.permanent = True  # Ensure session persists across redirects
        session['user_id'] = user_id
        session['user_email'] = email
        session['user_name'] = None

        # Store recovery codes for later (they'll see them during onboarding)
        session['recovery_codes'] = plain_codes

        # Redirect to onboarding
        return redirect("/onboarding")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login - supports both password and magic link."""
    if request.method == "POST":
        app.logger.info("Login POST request received")
        email = request.form.get("email")
        password = request.form.get("password")
        app.logger.info(f"Login attempt for email: {email}")

        if not email:
            flash("Email is required", "error")
            return render_template("login.html")

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        c.execute("SELECT id, email, name, password_hash, auth_provider FROM users WHERE email = ?", (email,))
        user = c.fetchone()

        if not user:
            # Don't reveal if email exists or not for security
            app.logger.info(f"User not found for email: {email}")
            if password:
                flash("Invalid email or password", "error")
            else:
                flash("If that email is registered, you'll receive a magic link shortly.", "success")
            conn.close()
            return render_template("login.html")

        user_id, user_email, user_name, password_hash, auth_provider = user
        app.logger.info(f"User found: {user_id} - {user_email}")

        # If password provided, try password auth
        if password:
            if not password_hash:
                flash("This account uses magic link authentication. Leave password blank to receive a magic link.", "error")
                conn.close()
                return render_template("login.html")

            from werkzeug.security import check_password_hash
            if check_password_hash(password_hash, password):
                # Password correct - log in
                # Get user role
                c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
                role_row = c.fetchone()
                user_role = role_row[0] if role_row else 'user'

                session.permanent = True  # Ensure session persists
                session['user_id'] = user_id
                session['user_email'] = user_email
                session['user_name'] = user_name
                session['is_admin'] = (user_role == 'admin')
                # Store password in session for zero-knowledge encryption of bank credentials
                session['user_password'] = password
                # Clear recovery login flag (they logged in normally)
                session.pop('logged_in_via_recovery', None)

                # Update last login timestamp
                c.execute("UPDATE users SET last_login_at = datetime('now') WHERE id = ?", (user_id,))
                conn.commit()

                # Check if user has a master recovery key and migrate existing loans if needed
                c.execute("SELECT master_recovery_key_hash, encryption_salt FROM users WHERE id = ?", (user_id,))
                recovery_info = c.fetchone()
                master_recovery_key_hash, encryption_salt = recovery_info if recovery_info else (None, None)

                if master_recovery_key_hash and encryption_salt:
                    # Check if there are loans that need migration
                    c.execute("""
                        SELECT id, encrypted_dek FROM loans
                        WHERE user_id = ? AND encrypted_dek_recovery IS NULL AND encrypted_dek IS NOT NULL
                    """, (user_id,))
                    loans_to_migrate = c.fetchall()

                    if loans_to_migrate:
                        # Check if we have master recovery key in session (from recent password setup)
                        master_recovery_key = session.get('master_recovery_key')

                        if not master_recovery_key:
                            # User doesn't have recovery key in session - try to verify it from password
                            # This won't work for security reasons, so just log it
                            app.logger.info(f"User {user_id} has {len(loans_to_migrate)} loans that need recovery key encryption, but key not in session")
                            session['needs_recovery_key_migration'] = len(loans_to_migrate)
                        else:
                            # We have the recovery key! Migrate the loans now
                            from services.encryption import (
                                decrypt_dek_with_password, encrypt_dek_with_recovery_key
                            )

                            migrated_count = 0
                            for loan_id, encrypted_dek in loans_to_migrate:
                                try:
                                    # Decrypt DEK with password
                                    dek = decrypt_dek_with_password(encrypted_dek, password, encryption_salt)

                                    # Re-encrypt with recovery key
                                    encrypted_dek_recovery = encrypt_dek_with_recovery_key(dek, master_recovery_key, encryption_salt)

                                    # Update loan
                                    c.execute("""
                                        UPDATE loans
                                        SET encrypted_dek_recovery = ?
                                        WHERE id = ?
                                    """, (encrypted_dek_recovery, loan_id))

                                    migrated_count += 1
                                except Exception as e:
                                    app.logger.error(f"Failed to migrate loan {loan_id}: {e}")

                            if migrated_count > 0:
                                conn.commit()
                                app.logger.info(f"Successfully migrated {migrated_count} loans for user {user_id}")
                                session.pop('needs_recovery_key_migration', None)

                conn.close()
                app.logger.info(f"Password login successful for {user_email}")
                log_event('login_success', user_id=user_id, event_data={'method': 'password'})

                # Clear any old sync results
                session.pop('sync_results', None)

                flash("Welcome back!", "success")
                return redirect("/")
            else:
                # Password incorrect
                conn.close()
                app.logger.warning(f"Invalid password for {user_email}")
                flash("Invalid email or password", "error")
                return render_template("login.html")

        # No password provided - send magic link
        user_id, user_email, user_name = user_id, user_email, user_name
        app.logger.info(f"User requested magic link for {user_id}")

        # Send magic link
        app.logger.info(f"Generating magic link for user {user_id}")
        token = generate_magic_link_token()
        expires_at = get_magic_link_expiry(minutes=15)

        c.execute("""
            INSERT INTO magic_links (user_id, token, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, token, expires_at))
        conn.commit()
        conn.close()
        app.logger.info(f"Magic link token saved to database")

        # Send email with magic link
        magic_link = f"{app.config['APP_URL']}/auth/magic/{token}"
        email_sent = False
        app.logger.info(f"About to send magic link email to {user_email}")

        # Try Mailgun API first (recommended)
        success, message = send_magic_link_email(user_email, user_name, magic_link)
        app.logger.info(f"send_magic_link_email returned: success={success}, message={message}")
        if success:
            app.logger.info(f"Magic link sent successfully to {user_email}")
            flash("Check your email! We've sent you a magic link to sign in.", "success")
            email_sent = True
        else:
            app.logger.warning(f"Mailgun failed for {user_email}: {message}")
            # Try Flask-Mail (SMTP) as fallback
            if app.config.get('MAIL_USERNAME') and app.config.get('MAIL_DEFAULT_SENDER'):
                try:
                    msg = Message(
                        subject="Your LendifyMe Login Link",
                        recipients=[user_email],
                        body=f"""Hi {user_name or 'there'},

Click the link below to sign in to LendifyMe:

{magic_link}

This link will expire in 15 minutes.

If you didn't request this, you can safely ignore this email.

---
LendifyMe
"""
                    )
                    mail.send(msg)
                    app.logger.info(f"Magic link sent via SMTP to {user_email}")
                    flash("Check your email! We've sent you a magic link to sign in.", "success")
                    email_sent = True
                except Exception as e:
                    app.logger.error(f"SMTP failed for {user_email}: {str(e)}")
                    flash(f"Error sending email: {str(e)}", "error")

        # Development mode - print link to console if email failed
        if not email_sent:
            app.logger.warning(f"No email provider configured. Magic link for {user_email}: {magic_link}")
            print("\n" + "="*70)
            print("🔗 MAGIC LINK (Development Mode - Email not configured)")
            print("="*70)
            print(f"User: {user_email}")
            print(f"Link: {magic_link}")
            print("="*70 + "\n")
            flash("Email not configured. Check the console for your magic link!", "success")

        return render_template("login.html")

    return render_template("login.html")


@app.route("/auth/recover", methods=["GET", "POST"])
def recover():
    """Recovery code login for users who lost email access."""
    if request.method == "POST":
        email = request.form.get("email")
        recovery_code = request.form.get("recovery_code")

        if not email or not recovery_code:
            flash("Both email and recovery code are required", "error")
            return render_template("recover.html")

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        c.execute("SELECT id, email, name, recovery_codes FROM users WHERE email = ?", (email,))
        user = c.fetchone()

        if not user:
            # Don't reveal if email exists or not for security
            flash("Invalid email or recovery code", "error")
            conn.close()
            return render_template("recover.html")

        user_id, user_email, user_name, recovery_codes_json = user

        # Verify recovery code
        is_valid, updated_codes = verify_recovery_code(recovery_code, recovery_codes_json)
        if is_valid:
            # Update recovery codes (remove used one) and last login timestamp
            c.execute("UPDATE users SET recovery_codes = ?, last_login_at = datetime('now') WHERE id = ?", (updated_codes, user_id))
            conn.commit()
            conn.close()

            # Log them in
            session.permanent = True  # Ensure session persists
            session['user_id'] = user_id
            session['user_email'] = user_email
            session['user_name'] = user_name
            session['logged_in_via_recovery'] = True  # Flag to allow password reset without old password

            flash(f"Welcome back, {user_name or user_email}! Recovery code accepted.", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid email or recovery code", "error")
            conn.close()
            return render_template("recover.html")

    return render_template("recover.html")


@app.route("/auth/magic/<token>")
def magic_link_auth(token):
    """Verify magic link and log user in."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    c.execute("""
        SELECT ml.id, ml.user_id, ml.expires_at, ml.used, u.email, u.name, u.role
        FROM magic_links ml
        JOIN users u ON ml.user_id = u.id
        WHERE ml.token = ?
    """, (token,))

    result = c.fetchone()

    if not result:
        flash("Invalid or expired login link", "error")
        conn.close()
        return redirect(url_for('login'))

    link_id, user_id, expires_at, used, user_email, user_name, user_role = result

    # Check if already used
    if used:
        flash("This login link has already been used", "error")
        conn.close()
        return redirect(url_for('login'))

    # Check if expired
    if is_magic_link_expired(expires_at):
        flash("This login link has expired. Request a new one.", "error")
        conn.close()
        return redirect(url_for('login'))

    # Mark as used
    c.execute("UPDATE magic_links SET used = 1 WHERE id = ?", (link_id,))
    # Update last login timestamp
    c.execute("UPDATE users SET last_login_at = datetime('now') WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    # Log user in
    session.permanent = True  # Ensure session persists
    session['user_id'] = user_id
    session['user_email'] = user_email
    session['user_name'] = user_name
    session['is_admin'] = (user_role == 'admin')
    # Clear recovery login flag (they logged in normally)
    session.pop('logged_in_via_recovery', None)

    log_event('login_success', user_id=user_id, event_data={'method': 'magic_link'})

    flash(f"Welcome back, {user_name or user_email}!", "success")
    return redirect(url_for('index'))


@app.route("/auth/verify/<token>")
def verify_email(token):
    """Verify user's email address via verification token."""
    from services.auth_helpers import is_verification_expired

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Find user by verification token
    c.execute("""
        SELECT id, email, name, verification_sent_at, email_verified
        FROM users
        WHERE verification_token = ?
    """, (token,))

    result = c.fetchone()

    if not result:
        flash("Invalid or expired verification link", "error")
        conn.close()
        return redirect(url_for('login'))

    user_id, user_email, user_name, verification_sent_at, email_verified = result

    # Check if already verified
    if email_verified:
        flash("Your email is already verified!", "success")
        conn.close()
        return redirect(url_for('login'))

    # Check if expired (24 hours)
    if verification_sent_at and is_verification_expired(verification_sent_at, hours=24):
        flash("This verification link has expired. Request a new one from your account settings.", "error")
        conn.close()
        return redirect(url_for('login'))

    # Mark as verified and clear token
    c.execute("""
        UPDATE users
        SET email_verified = 1, verification_token = NULL, verification_sent_at = NULL
        WHERE id = ?
    """, (user_id,))
    conn.commit()
    conn.close()

    # Log them in if not already logged in
    if session.get('user_id') != user_id:
        session['user_id'] = user_id
        session['user_email'] = user_email
        session['user_name'] = user_name

    flash("Email verified successfully! 🎉", "success")
    return redirect(url_for('index'))


@app.route("/resend-verification", methods=["POST"])
@login_required
def resend_verification():
    """Resend verification email to current user."""
    from services.auth_helpers import generate_verification_token, get_verification_expiry

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Get user details
    c.execute("SELECT email, name, email_verified FROM users WHERE id = ?", (get_current_user_id(),))
    user = c.fetchone()

    if not user:
        flash("User not found", "error")
        conn.close()
        return redirect("/")

    email, name, email_verified = user

    # Check if already verified
    if email_verified:
        flash("Your email is already verified!", "success")
        conn.close()
        return redirect("/")

    # Generate new verification token
    verification_token = generate_verification_token()
    verification_sent_at = get_verification_expiry(hours=0)  # Current time

    # Update user with new token
    c.execute("""
        UPDATE users
        SET verification_token = ?, verification_sent_at = ?
        WHERE id = ?
    """, (verification_token, verification_sent_at, get_current_user_id()))
    conn.commit()
    conn.close()

    # Send verification email
    verification_link = f"{app.config['APP_URL']}/auth/verify/{verification_token}"
    from services.email_sender import send_verification_email
    try:
        success, message = send_verification_email(email, name, verification_link)
        if success:
            app.logger.info(f"Verification email resent to {email}")
            flash("Verification email sent! Check your inbox.", "success")
        else:
            app.logger.warning(f"Failed to resend verification email: {message}")
            flash("Failed to send email. Please try again later.", "error")
    except Exception as e:
        app.logger.error(f"Error sending verification email: {e}")
        flash("Failed to send email. Please try again later.", "error")

    return redirect("/")


@app.route("/auth/recovery-codes")
@login_required
def show_recovery_codes():
    """Show recovery codes and master recovery key after password setup (one-time view)."""
    if 'show_recovery_codes' not in session:
        flash("No recovery codes to show", "error")
        return redirect(url_for('index'))

    codes = session.get('show_recovery_codes')
    master_recovery_key = session.get('show_master_recovery_key')
    user_id = session.get('recovery_codes_for_user')

    # Auto-login the user who just registered
    if user_id:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute("SELECT id, email, name FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['user_email'] = user[1]
            session['user_name'] = user[2]

    # Clear from session after showing once
    session.pop('show_recovery_codes', None)
    session.pop('show_master_recovery_key', None)
    session.pop('recovery_codes_for_user', None)

    return render_template("recovery_codes.html", codes=codes, master_recovery_key=master_recovery_key)


@app.route("/logout")
def logout():
    """User logout."""
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for('index'))


@app.route("/health")
def health():
    """Health check endpoint with diagnostics."""
    import sys

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
    log_preview = []
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

    conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
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
    conn = sqlite3.connect(get_db_path())
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


@app.route("/", methods=["GET", "POST"])
def index():
    # Show landing page if not logged in
    if not session.get('user_id'):
        return render_template("landing.html")

    if request.method == "POST":
        borrower = request.form.get("borrower")
        bank_name = request.form.get("bank_name")
        date_borrowed = request.form.get("date_borrowed")
        amount = request.form.get("amount")
        note = request.form.get("note")
        repayment_amount = request.form.get("repayment_amount")
        repayment_frequency = request.form.get("repayment_frequency")
        loan_type = request.form.get("loan_type", "lending")  # Default to lending
        onboarding = request.form.get("onboarding")  # Check if this is during onboarding

        # Check if user needs to verify email before creating more loans
        if not is_email_verified():
            loan_count = get_unverified_loan_count()
            if loan_count >= 2:
                flash("Please verify your email to create more loans. Check your inbox for the verification link.", "error")
                return redirect("/")

        # Check subscription loan limit
        current_loans, max_loans, can_create = check_loan_limit()
        if not can_create:
            tier = get_user_subscription_tier()
            tier_name = tier.title()
            if max_loans is not None:
                flash(f"You've reached the limit of {max_loans} loans on the {tier_name} plan. Upgrade to create more!", "error")
            return redirect("/pricing")

        if borrower and amount:
            from services.encryption import (
                generate_dek, create_token_from_dek, encrypt_dek_with_password,
                encrypt_dek_with_recovery_key
            )

            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()

            # Get user's password and encryption salt for encrypting DEK
            user_password = get_user_password_from_session()
            encryption_salt = get_user_encryption_salt()

            if not user_password or not encryption_salt:
                flash("Please set up a password to create encrypted loans.", "error")
                conn.close()
                return redirect("/settings/password?redirect=dashboard")

            # Generate DEK for this loan
            dek = generate_dek()

            # Create borrower access token from DEK (enables passwordless borrower access)
            access_token = create_token_from_dek(dek)

            # Encrypt the DEK with user's password (enables lender access)
            encrypted_dek = encrypt_dek_with_password(dek, user_password, encryption_salt)

            # Encrypt the DEK with master recovery key (enables password reset without data loss)
            master_recovery_key = session.get('master_recovery_key')
            encrypted_dek_recovery = None
            if master_recovery_key:
                encrypted_dek_recovery = encrypt_dek_with_recovery_key(dek, master_recovery_key, encryption_salt)

            # Prepare loan data for encryption
            loan_data = {
                'borrower': borrower,
                'bank_name': bank_name if bank_name else None,
                'amount': float(amount),
                'note': note,
                'borrower_email': None,  # Not collected during creation
                'repayment_amount': float(repayment_amount) if repayment_amount else None,
                'repayment_frequency': repayment_frequency if repayment_frequency else None,
            }

            # Encrypt sensitive fields
            encrypted_fields = encrypt_loan_data(loan_data, dek)

            # Insert loan with encrypted data
            # Note: plaintext columns (borrower, amount, etc.) are intentionally NULL
            # Migration v25 makes them nullable to support zero-knowledge encryption
            try:
                c.execute("""
                    INSERT INTO loans (
                        borrower_encrypted, bank_name_encrypted, amount_encrypted, note_encrypted,
                        date_borrowed, repayment_amount_encrypted, repayment_frequency_encrypted,
                        user_id, borrower_access_token, loan_type, encrypted_dek, encrypted_dek_recovery
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    encrypted_fields['borrower_encrypted'],
                    encrypted_fields['bank_name_encrypted'],
                    encrypted_fields['amount_encrypted'],
                    encrypted_fields['note_encrypted'],
                    date_borrowed,
                    encrypted_fields['repayment_amount_encrypted'],
                    encrypted_fields['repayment_frequency_encrypted'],
                    get_current_user_id(),
                    access_token,
                    loan_type,
                    encrypted_dek,
                    encrypted_dek_recovery
                ))
            except sqlite3.IntegrityError as e:
                # If this fails, it means the migration didn't run to make columns nullable
                conn.close()
                app.logger.error(f"Failed to create loan: {e}. Database may need migration.")
                flash("Database error. Please restart the application to run migrations.", "error")
                return redirect("/")
            loan_id = c.lastrowid
            conn.commit()
            conn.close()

            # Log analytics event (amount is logged, but this is for user's own analytics)
            log_event('loan_created', event_data={'loan_type': loan_type, 'amount': float(amount)})

        # If this was during onboarding, redirect to complete onboarding
        if onboarding == "1":
            return redirect("/onboarding?step=complete")

        return redirect("/")

    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row  # Enable column name access
    c = conn.cursor()

    # Get user's password for decryption
    user_password = get_user_password_from_session()

    # Check if user has any loans first
    c.execute("SELECT COUNT(*) FROM loans WHERE user_id = ?", (get_current_user_id(),))
    loan_count = c.fetchone()[0]

    if not user_password and loan_count > 0:
        # User has loans but no password in session
        # Check if they have a password_hash (already set up password) or not
        c.execute("SELECT password_hash FROM users WHERE id = ?", (get_current_user_id(),))
        user_row = c.fetchone()
        has_password_in_db = user_row and user_row[0] is not None

        if has_password_in_db:
            # They have a password but it's not in session (e.g., logged in via email verification)
            flash("Please log in with your password to access your encrypted loan data.", "error")
            conn.close()
            session.clear()  # Clear session to force proper login
            return redirect("/login")
        elif session.get('logged_in_via_recovery'):
            # Logged in via recovery code but no password
            flash("Please reset your password to access your encrypted loan data.", "error")
            conn.close()
            return redirect("/settings/password?redirect=dashboard")
        else:
            # No password at all
            flash("Please set up a password to secure your loan data with encryption.", "error")
            conn.close()
            return redirect("/settings/password?redirect=dashboard")

    if not user_password:
        # No password and no loans - show empty state
        conn.close()
        email_verified = is_email_verified()
        return render_template("index.html", loans=[], app_url=app.config['APP_URL'], email_verified=email_verified, has_password=False)

    c.execute("""
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
    """, (get_current_user_id(),))

    encrypted_loans = c.fetchall()

    # Decrypt loans and calculate amount_repaid
    loans = []
    for loan_row in encrypted_loans:
        loan_id = loan_row['id']

        # Get DEK for this loan
        dek = get_loan_dek(loan_id, user_password=user_password)

        if not dek:
            app.logger.error(f"Failed to decrypt DEK for loan {loan_id}")
            continue

        # Decrypt loan fields
        from services.encryption import decrypt_field

        # Use encrypted fields if available, fall back to plaintext (for migration)
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

        # Create decrypted loan tuple (matching original query structure)
        loans.append((
            loan_id,
            borrower,
            amount,
            note,
            loan_row['date_borrowed'],
            amount_repaid,
            repayment_amount,
            repayment_frequency,
            bank_name,
            loan_row['created_at'],
            loan_row['borrower_access_token'],
            borrower_email,
            loan_row['loan_type']
        ))

    # Get email verification status and password status
    email_verified = is_email_verified()
    has_password = user_password is not None
    conn.close()

    return render_template("index.html", loans=loans, app_url=app.config['APP_URL'], email_verified=email_verified, has_password=has_password)


@app.route("/repay/<int:loan_id>", methods=["POST"])
@login_required
def repay(loan_id):
    repayment_amount = request.form.get("repayment_amount")
    if not repayment_amount:
        return redirect("/")

    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Load the loan row (including encrypted columns) and current repaid total
    c.execute(
        """
        SELECT l.*,
               COALESCE((
                   SELECT SUM(amount) FROM applied_transactions at
                   WHERE at.loan_id = l.id
               ), 0) AS current_repaid
        FROM loans l
        WHERE l.id = ? AND l.user_id = ?
        """,
        (loan_id, get_current_user_id()),
    )
    loan_row = c.fetchone()

    if not loan_row:
        conn.close()
        return redirect("/")

    # Decrypt fields as needed
    user_password = get_user_password_from_session()
    dek = get_loan_dek(loan_id, user_password=user_password)
    from services.encryption import decrypt_field  # local import to avoid circulars

    borrower_name = (
        decrypt_field(loan_row["borrower_encrypted"], dek)
        if loan_row["borrower_encrypted"]
        else loan_row["borrower"]
    )
    borrower_email = (
        decrypt_field(loan_row["borrower_email_encrypted"], dek)
        if loan_row["borrower_email_encrypted"]
        else loan_row["borrower_email"]
    )

    access_token = loan_row["borrower_access_token"]
    notifications_enabled = bool(loan_row["borrower_notifications_enabled"])

    current_repaid = float(loan_row["current_repaid"] or 0.0)
    if loan_row["amount_encrypted"]:
        loan_amount = float(decrypt_field(loan_row["amount_encrypted"], dek))
    else:
        loan_amount = float(loan_row["amount"])

    payment_amount = float(repayment_amount)

    # Record manual repayment
    c.execute(
        """
        INSERT INTO applied_transactions (date, description, amount, loan_id)
        VALUES (date('now'), 'Manual repayment', ?, ?)
        """,
        (payment_amount, loan_id),
    )
    conn.commit()

    # New balance (kept in case downstream logic uses it)
    new_balance = loan_amount - (current_repaid + payment_amount)  # noqa: F841

    conn.close()
    return redirect("/")


@app.route("/edit/<int:loan_id>", methods=["GET", "POST"])
@login_required
def edit_loan(loan_id):
    if request.method == "POST":
        borrower = request.form.get("borrower")
        bank_name = request.form.get("bank_name")
        amount = request.form.get("amount")
        date_borrowed = request.form.get("date_borrowed")
        note = request.form.get("note")
        repayment_amount = request.form.get("repayment_amount")
        repayment_frequency = request.form.get("repayment_frequency")

        if borrower and amount:
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute("""
                UPDATE loans
                SET borrower = ?, bank_name = ?, amount = ?, date_borrowed = ?, note = ?,
                    repayment_amount = ?, repayment_frequency = ?
                WHERE id = ? AND user_id = ?
            """, (borrower,
                  bank_name if bank_name else None,
                  float(amount), date_borrowed, note,
                  float(repayment_amount) if repayment_amount else None,
                  repayment_frequency if repayment_frequency else None,
                  loan_id, get_current_user_id()))
            conn.commit()
            conn.close()

            # Log analytics event
            log_event('loan_updated', event_data={'loan_id': loan_id})

            flash("Loan updated successfully", "success")

        return redirect("/")

    # GET request - show edit form
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.note, l.date_borrowed,
               COALESCE(SUM(at.amount), 0) as amount_repaid,
               l.repayment_amount, l.repayment_frequency, l.bank_name
        FROM loans l
        LEFT JOIN applied_transactions at ON l.id = at.loan_id
        WHERE l.id = ? AND l.user_id = ?
        GROUP BY l.id
    """, (loan_id, get_current_user_id()))
    loan = c.fetchone()
    conn.close()

    if not loan:
        flash("Loan not found", "error")
        return redirect("/")

    return render_template("edit_loan.html", loan=loan)


@app.route("/delete/<int:loan_id>", methods=["POST"])
@login_required
def delete_loan(loan_id):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("DELETE FROM loans WHERE id = ? AND user_id = ?", (loan_id, get_current_user_id()))
    conn.commit()
    conn.close()

    # Log analytics event
    log_event('loan_deleted', event_data={'loan_id': loan_id})

    flash("Loan deleted successfully", "success")
    return redirect("/")


@app.route("/loan/<int:loan_id>/transactions")
@login_required
def loan_transactions(loan_id):
    """View all applied transactions for a specific loan."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Get loan details with calculated repaid amount
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.date_borrowed,
               COALESCE(SUM(at.amount), 0) as amount_repaid,
               l.bank_name, l.note
        FROM loans l
        LEFT JOIN applied_transactions at ON l.id = at.loan_id
        WHERE l.id = ? AND l.user_id = ?
        GROUP BY l.id
    """, (loan_id, get_current_user_id()))
    loan = c.fetchone()

    if not loan:
        flash("Loan not found", "error")
        return redirect("/")

    # Get all applied transactions for this loan
    c.execute("""
        SELECT id, date, description, amount, applied_at, auto_applied, confidence_score
        FROM applied_transactions
        WHERE loan_id = ?
        ORDER BY date DESC
    """, (loan_id,))
    transactions = c.fetchall()

    conn.close()

    has_export = has_feature(get_current_user_id(), 'transaction_export')
    return render_template("loan_transactions.html", loan=loan, transactions=transactions, has_export=has_export)


@app.route("/loan/<int:loan_id>/transactions/export")
@login_required
def export_loan_transactions(loan_id):
    """Export loan transactions as CSV."""
    # Check if user has transaction export feature
    if not has_feature(get_current_user_id(), 'transaction_export'):
        flash("Transaction export is available on Basic and Pro plans. Upgrade to export your transactions!", "error")
        return redirect("/pricing")

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Get loan details with calculated repaid amount
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.date_borrowed,
               COALESCE(SUM(at.amount), 0) as amount_repaid,
               l.bank_name, l.note
        FROM loans l
        LEFT JOIN applied_transactions at ON l.id = at.loan_id
        WHERE l.id = ? AND l.user_id = ?
        GROUP BY l.id
    """, (loan_id, get_current_user_id()))
    loan = c.fetchone()

    if not loan:
        flash("Loan not found", "error")
        return redirect("/")

    # Get all applied transactions for this loan
    c.execute("""
        SELECT id, date, description, amount, applied_at
        FROM applied_transactions
        WHERE loan_id = ?
        ORDER BY date DESC
    """, (loan_id,))
    transactions = c.fetchall()

    conn.close()

    # Build CSV content
    from io import StringIO
    import csv

    output = StringIO()
    writer = csv.writer(output)

    # Header section
    writer.writerow(['Loan Transaction History'])
    writer.writerow([])
    writer.writerow(['Borrower:', loan[1]])
    if loan[5]:
        writer.writerow(['Bank Name:', loan[5]])
    writer.writerow(['Original Amount:', f'${loan[2]:.2f}'])
    writer.writerow(['Total Repaid:', f'${loan[4]:.2f}'])
    writer.writerow(['Remaining:', f'${loan[2] - loan[4]:.2f}'])
    writer.writerow([])

    # Transaction table
    writer.writerow(['Transaction Date', 'Description', 'Amount', 'Applied On'])
    for transaction in transactions:
        writer.writerow([
            transaction[1],  # date
            transaction[2],  # description
            f'${transaction[3]:.2f}',  # amount
            transaction[4].split('T')[0] if 'T' in transaction[4] else transaction[4]  # applied_at
        ])

    # Total
    writer.writerow([])
    writer.writerow(['Total:', '', f'${loan[4]:.2f}', ''])

    # Create response
    from flask import Response
    csv_content = output.getvalue()
    output.close()

    response = Response(csv_content, mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename=loan_{loan_id}_{loan[1].replace(" ", "_")}_transactions.csv'

    return response


@app.route("/onboarding")
@login_required
def onboarding():
    """Onboarding flow for new users."""
    # Check if already completed
    conn = sqlite3.connect(get_db_path())
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

        conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
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
    import json

    conn = sqlite3.connect(get_db_path())
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
        conn = sqlite3.connect(get_db_path())
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
    import os
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
    conn = sqlite3.connect(get_db_path())
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
    import os
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

    conn = sqlite3.connect(get_db_path())
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
    import os
    from datetime import datetime
    import json

    user_id = get_current_user_id()
    conn = sqlite3.connect(get_db_path())
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
    conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
    conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints for CASCADE
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

    conn = sqlite3.connect(get_db_path())
    conn.execute("PRAGMA foreign_keys = ON")
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


@app.route("/settings")
@login_required
def settings():
    """Settings hub page."""
    return render_template("settings.html")


@app.route("/settings/recovery-codes", methods=["GET", "POST"])
@login_required
def settings_recovery_codes():
    """View and manage recovery codes."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    c.execute("SELECT recovery_codes, password_hash FROM users WHERE id = ?", (get_current_user_id(),))
    user = c.fetchone()
    conn.close()

    if not user:
        flash("User not found", "error")
        return redirect("/")

    recovery_codes_json, password_hash = user
    has_codes = recovery_codes_json and recovery_codes_json != '[]'
    has_password = password_hash is not None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "generate":
            # Generate new recovery codes
            password = request.form.get("password", "").strip() if has_password else None

            # Verify password if user has one
            if has_password:
                if not password:
                    flash("Password is required to generate new recovery codes", "error")
                    return render_template("settings_recovery_codes.html",
                                         has_codes=has_codes, has_password=has_password)

                from werkzeug.security import check_password_hash
                if not check_password_hash(password_hash, password):
                    flash("Incorrect password", "error")
                    return render_template("settings_recovery_codes.html",
                                         has_codes=has_codes, has_password=has_password)

            # Generate new codes
            from services.auth_helpers import generate_recovery_codes
            plain_codes, hashed_codes_json = generate_recovery_codes()

            # Save to database
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute("UPDATE users SET recovery_codes = ? WHERE id = ?",
                     (hashed_codes_json, get_current_user_id()))
            conn.commit()
            conn.close()

            flash("New recovery codes generated! Save them in a secure place.", "success")
            return render_template("settings_recovery_codes.html",
                                 has_codes=True,
                                 has_password=has_password,
                                 new_codes=plain_codes)

    # GET request
    return render_template("settings_recovery_codes.html",
                         has_codes=has_codes,
                         has_password=has_password)


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

        conn = sqlite3.connect(get_db_path())
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
            from services.encryption import generate_encryption_salt, generate_master_recovery_key

            password_hash = generate_password_hash(new_password)

            # Generate encryption salt for zero-knowledge encryption of bank credentials
            encryption_salt = generate_encryption_salt()

            # Generate master recovery key for password recovery without data loss
            master_recovery_key = generate_master_recovery_key()
            master_recovery_key_hash = generate_password_hash(master_recovery_key)

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

            # Store recovery codes and master recovery key in session to show to user
            # Get recovery codes that were generated during registration
            recovery_codes = session.get('recovery_codes', [])
            if not recovery_codes:
                # If no codes in session, generate new ones
                from services.auth_helpers import generate_recovery_codes
                plain_codes, hashed_codes_json = generate_recovery_codes()

                # Update user with recovery codes
                conn = sqlite3.connect(get_db_path())
                c = conn.cursor()
                c.execute("UPDATE users SET recovery_codes = ? WHERE id = ?",
                         (hashed_codes_json, get_current_user_id()))
                conn.commit()
                conn.close()

                recovery_codes = plain_codes

            # Store in session for recovery codes display page
            session['show_recovery_codes'] = recovery_codes
            session['show_master_recovery_key'] = master_recovery_key
            session['recovery_codes_for_user'] = get_current_user_id()

            # Redirect to recovery codes display page
            return redirect("/auth/recovery-codes")

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

            if not logged_in_via_recovery:
                # Normal password change - require current password
                if not current_password:
                    flash("Current password is required", "error")
                    conn.close()
                    return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from, logged_in_via_recovery=False)

                # Verify current password
                from werkzeug.security import check_password_hash
                if not check_password_hash(user[0], current_password):
                    flash("Current password is incorrect", "error")
                    conn.close()
                    return render_template("settings_password.html", has_password=has_password, redirect_from=redirect_from, logged_in_via_recovery=False)

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

            flash("Password changed successfully! Your data is now accessible.", "success")
            return redirect("/settings/password")

        elif action == "remove":
            # Password removal is no longer allowed due to zero-knowledge encryption
            # Without a password, users cannot decrypt their loan data
            flash("Password cannot be removed. It's required to encrypt and decrypt your loan data.", "error")
            conn.close()
            return redirect("/settings/password")

        conn.close()

    # GET request - show form
    conn = sqlite3.connect(get_db_path())
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
    conn = sqlite3.connect(get_db_path())
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

            conn = sqlite3.connect(get_db_path())
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
    conn = sqlite3.connect(get_db_path())
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
    conn = sqlite3.connect(get_db_path())
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
            conn = sqlite3.connect(get_db_path())
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

            conn = sqlite3.connect(get_db_path())
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
    conn = sqlite3.connect(get_db_path())
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
        conn = sqlite3.connect(get_db_path())
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
        conn = sqlite3.connect(get_db_path())
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


@app.route("/remove-transaction/<int:transaction_id>", methods=["POST"])
@login_required
def remove_transaction(transaction_id):
    """Remove an applied transaction and reverse its effect on the loan."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Get the transaction details and verify ownership
    c.execute("""
        SELECT at.loan_id, at.amount, at.description, at.date
        FROM applied_transactions at
        JOIN loans l ON at.loan_id = l.id
        WHERE at.id = ? AND l.user_id = ?
    """, (transaction_id, get_current_user_id()))

    transaction = c.fetchone()

    if transaction:
        loan_id, amount, description, date = transaction

        # Delete the applied transaction (amount_repaid will recalculate automatically)
        c.execute("""
            DELETE FROM applied_transactions
            WHERE id = ?
        """, (transaction_id,))

        conn.commit()
        flash(f"Removed ${amount:.2f} transaction from {date}", "success")
    else:
        flash("Transaction not found", "error")

    conn.close()

    # Redirect back to the loan's transaction history
    if transaction:
        return redirect(f"/loan/{loan_id}/transactions")
    else:
        return redirect("/")


@app.route("/analytics")
@admin_required
def analytics():
    """Analytics dashboard showing usage metrics. Admin only."""
    from datetime import datetime, timedelta
    import json

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Date calculations
    today = datetime.now().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)

    metrics = {}

    # Total users
    c.execute("SELECT COUNT(*) FROM users")
    metrics['total_users'] = c.fetchone()[0]

    # New signups (last 7 days, last 30 days)
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'user_signed_up' AND created_at >= date('now', '-7 days')")
    metrics['new_users_7d'] = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'user_signed_up' AND created_at >= date('now', '-30 days')")
    metrics['new_users_30d'] = c.fetchone()[0]

    # DAU (Daily Active Users) - users with any event today
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE date(created_at) = date('now')
    """)
    metrics['dau'] = c.fetchone()[0]

    # WAU (Weekly Active Users)
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-7 days')
    """)
    metrics['wau'] = c.fetchone()[0]

    # MAU (Monthly Active Users)
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-30 days')
    """)
    metrics['mau'] = c.fetchone()[0]

    # Total loans created
    c.execute("SELECT COUNT(*) FROM loans")
    metrics['total_loans'] = c.fetchone()[0]

    # Loans created (last 7 days, last 30 days)
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'loan_created' AND created_at >= date('now', '-7 days')")
    metrics['loans_7d'] = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'loan_created' AND created_at >= date('now', '-30 days')")
    metrics['loans_30d'] = c.fetchone()[0]

    # Bank link funnel
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'bank_link_started' AND created_at >= date('now', '-30 days')")
    bank_started = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'bank_link_success' AND created_at >= date('now', '-30 days')")
    bank_success = c.fetchone()[0]

    metrics['bank_link_started'] = bank_started
    metrics['bank_link_success'] = bank_success
    metrics['bank_link_conversion'] = (bank_success / bank_started * 100) if bank_started > 0 else 0

    # Retention: users active this week who were also active last week
    c.execute("""
        SELECT COUNT(DISTINCT e1.user_id)
        FROM events e1
        WHERE e1.created_at >= date('now', '-7 days')
          AND e1.user_id IN (
              SELECT DISTINCT user_id
              FROM events
              WHERE created_at >= date('now', '-14 days')
                AND created_at < date('now', '-7 days')
          )
    """)
    retained_users = c.fetchone()[0]

    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-14 days')
          AND created_at < date('now', '-7 days')
    """)
    previous_week_users = c.fetchone()[0]

    metrics['retention_rate'] = (retained_users / previous_week_users * 100) if previous_week_users > 0 else 0

    # Recent events (last 20)
    c.execute("""
        SELECT e.event_name, e.created_at, u.email, e.event_data
        FROM events e
        LEFT JOIN users u ON e.user_id = u.id
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

    # Event counts by type (last 30 days)
    c.execute("""
        SELECT event_name, COUNT(*) as count
        FROM events
        WHERE created_at >= date('now', '-30 days')
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
    conn = sqlite3.connect(get_db_path())
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
    conn = sqlite3.connect(get_db_path())
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
    conn = sqlite3.connect(get_db_path())
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


if __name__ == "__main__":
    app.run(debug=True)
