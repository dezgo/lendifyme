import sqlite3
import os
import json
import logging
import secrets
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from services import migrations
from services.transaction_matcher import match_transactions_to_loans
from services.connectors.registry import ConnectorRegistry
from services.connectors.csv_connector import CSVConnector
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_mail import Mail, Message
from functools import wraps
from services.auth_helpers import (
    generate_recovery_codes,
    verify_recovery_code,
    generate_magic_link_token,
    hash_token,
    get_magic_link_expiry,
    is_magic_link_expired
)
from services.email_sender import send_magic_link_email


# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Config
app.config['DATABASE'] = 'lendifyme.db'
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

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


def get_current_user_id():
    """Get the current logged-in user's ID from session."""
    return session.get('user_id')


def generate_borrower_access_token():
    """Generate a secure random token for borrower access."""
    return secrets.token_urlsafe(32)


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
    """User registration - passwordless."""
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")

        if not email:
            flash("Email is required", "error")
            return render_template("register.html")

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        # Check if email already exists
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        if c.fetchone():
            flash("Email already registered. Use 'Login' to sign in.", "error")
            conn.close()
            return redirect(url_for('login'))

        # Generate recovery codes
        plain_codes, hashed_codes_json = generate_recovery_codes()

        # Create user
        c.execute("""
            INSERT INTO users (email, name, recovery_codes, auth_provider)
            VALUES (?, ?, ?, 'magic_link')
        """, (email, name, hashed_codes_json))
        conn.commit()

        user_id = c.lastrowid
        conn.close()

        # Store recovery codes in session to show user once
        session['show_recovery_codes'] = plain_codes
        session['recovery_codes_for_user'] = user_id

        flash("Account created! Save your recovery codes below.", "success")
        return redirect(url_for('show_recovery_codes'))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login - send magic link or use recovery code."""
    if request.method == "POST":
        app.logger.info("Login POST request received")
        email = request.form.get("email")
        recovery_code = request.form.get("recovery_code")
        app.logger.info(f"Login attempt for email: {email}, has_recovery_code: {bool(recovery_code)}")

        if not email:
            flash("Email is required", "error")
            return render_template("login.html")

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        c.execute("SELECT id, email, name, recovery_codes FROM users WHERE email = ?", (email,))
        user = c.fetchone()

        if not user:
            # Don't reveal if email exists or not for security
            app.logger.info(f"User not found for email: {email}")
            flash("If that email is registered, you'll receive a magic link shortly.", "success")
            conn.close()
            return render_template("login.html")

        user_id, user_email, user_name, recovery_codes_json = user
        app.logger.info(f"User found: {user_id} - {user_email}")

        # If recovery code provided, try that first
        if recovery_code:
            is_valid, updated_codes = verify_recovery_code(recovery_code, recovery_codes_json)
            if is_valid:
                # Update recovery codes (remove used one)
                c.execute("UPDATE users SET recovery_codes = ? WHERE id = ?", (updated_codes, user_id))
                conn.commit()
                conn.close()

                # Log them in
                session['user_id'] = user_id
                session['user_email'] = user_email
                session['user_name'] = user_name

                flash(f"Welcome back, {user_name or user_email}! Recovery code used.", "success")
                return redirect(url_for('index'))
            else:
                flash("Invalid recovery code", "error")
                conn.close()
                return render_template("login.html")

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


@app.route("/auth/magic/<token>")
def magic_link_auth(token):
    """Verify magic link and log user in."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    c.execute("""
        SELECT ml.id, ml.user_id, ml.expires_at, ml.used, u.email, u.name
        FROM magic_links ml
        JOIN users u ON ml.user_id = u.id
        WHERE ml.token = ?
    """, (token,))

    result = c.fetchone()

    if not result:
        flash("Invalid or expired login link", "error")
        conn.close()
        return redirect(url_for('login'))

    link_id, user_id, expires_at, used, user_email, user_name = result

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
    conn.commit()
    conn.close()

    # Log user in
    session['user_id'] = user_id
    session['user_email'] = user_email
    session['user_name'] = user_name

    flash(f"Welcome back, {user_name or user_email}!", "success")
    return redirect(url_for('index'))


@app.route("/auth/recovery-codes")
def show_recovery_codes():
    """Show recovery codes after registration (one-time view)."""
    if 'show_recovery_codes' not in session:
        flash("No recovery codes to show", "error")
        return redirect(url_for('index'))

    codes = session.get('show_recovery_codes')
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
    session.pop('recovery_codes_for_user', None)

    return render_template("recovery_codes.html", codes=codes)


@app.route("/logout")
def logout():
    """User logout."""
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for('login'))


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
    c = conn.cursor()

    # Find loan by access token
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.date_borrowed, l.date_due,
               l.note, l.repayment_amount, l.repayment_frequency,
               l.bank_name, l.borrower_email,
               COALESCE(SUM(at.amount), 0) as amount_repaid
        FROM loans l
        LEFT JOIN applied_transactions at ON l.id = at.loan_id
        WHERE l.borrower_access_token = ?
        GROUP BY l.id
    """, (token,))
    loan_data = c.fetchone()

    if not loan_data:
        conn.close()
        flash("Invalid or expired access link", "error")
        return render_template("borrower_portal_error.html"), 404

    # Unpack loan data
    loan_id, borrower, amount, date_borrowed, date_due, note, repayment_amount, repayment_frequency, bank_name, borrower_email, amount_repaid = loan_data

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
        'date_borrowed': date_borrowed,
        'date_due': date_due,
        'note': note,
        'repayment_amount': repayment_amount,
        'repayment_frequency': repayment_frequency,
        'bank_name': bank_name,
        'borrower_email': borrower_email,
        'amount_repaid': amount_repaid,
        'outstanding': outstanding
    }

    return render_template("borrower_portal.html", loan=loan, transactions=transactions)


@app.route("/loan/<int:loan_id>/send-invite", methods=["GET", "POST"])
@login_required
def send_borrower_invite(loan_id):
    """Send invitation email to borrower with portal access link."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Verify loan ownership and get loan details
    c.execute("""
        SELECT id, borrower, borrower_access_token, borrower_email, amount,
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

        if borrower and amount:
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            # Generate unique access token for borrower
            access_token = generate_borrower_access_token()
            c.execute("""
                INSERT INTO loans (borrower, bank_name, amount, note, date_borrowed, repayment_amount, repayment_frequency, user_id, borrower_access_token, loan_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (borrower,
                  bank_name if bank_name else None,
                  float(amount), note, date_borrowed,
                  float(repayment_amount) if repayment_amount else None,
                  repayment_frequency if repayment_frequency else None,
                  get_current_user_id(),
                  access_token,
                  loan_type))
            conn.commit()
            conn.close()
        return redirect("/")

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.note, l.date_borrowed,
               COALESCE(SUM(at.amount), 0) as amount_repaid,
               l.repayment_amount, l.repayment_frequency, l.bank_name, l.created_at,
               l.borrower_access_token, l.borrower_email, l.loan_type
        FROM loans l
        LEFT JOIN applied_transactions at ON l.id = at.loan_id
        WHERE l.user_id = ?
        GROUP BY l.id
        ORDER BY l.created_at DESC
    """, (get_current_user_id(),))

    loans = c.fetchall()
    conn.close()

    return render_template("index.html", loans=loans, app_url=app.config['APP_URL'])


@app.route("/repay/<int:loan_id>", methods=["POST"])
@login_required
def repay(loan_id):
    repayment_amount = request.form.get("repayment_amount")

    if repayment_amount:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        # Get loan details with current repaid amount
        c.execute("""
            SELECT l.id, l.borrower, l.borrower_email, l.borrower_access_token, l.amount,
                   COALESCE(SUM(at.amount), 0) as current_repaid
            FROM loans l
            LEFT JOIN applied_transactions at ON l.id = at.loan_id
            WHERE l.id = ? AND l.user_id = ?
            GROUP BY l.id
        """, (loan_id, get_current_user_id()))
        loan_details = c.fetchone()

        if loan_details:
            loan_id_db, borrower_name, borrower_email, access_token, loan_amount, current_repaid = loan_details
            payment_amount = float(repayment_amount)

            # Record manual repayment as applied transaction
            c.execute("""
                INSERT INTO applied_transactions (date, description, amount, loan_id)
                VALUES (date('now'), 'Manual repayment', ?, ?)
            """, (payment_amount, loan_id))
            conn.commit()

            # Calculate new balance
            new_balance = loan_amount - (current_repaid + payment_amount)

            # Send email notification if borrower has email and access token
            if borrower_email and access_token:
                portal_link = f"{app.config['APP_URL']}/borrower/{access_token}"
                lender_name = session.get('user_name') or session.get('user_email', 'Your lender')

                try:
                    from services.email_sender import send_payment_notification_email
                    from datetime import date
                    success, message = send_payment_notification_email(
                        to_email=borrower_email,
                        borrower_name=borrower_name,
                        portal_link=portal_link,
                        lender_name=lender_name,
                        payment_amount=payment_amount,
                        payment_date=date.today().isoformat(),
                        payment_description='Manual repayment',
                        new_balance=new_balance,
                        original_amount=loan_amount
                    )

                    if success:
                        app.logger.info(f"Payment notification sent to {borrower_email}")
                except Exception as e:
                    app.logger.error(f"Error sending payment notification: {e}")

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
               l.bank_name
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

    return render_template("loan_transactions.html", loan=loan, transactions=transactions)


@app.route("/loan/<int:loan_id>/transactions/export")
@login_required
def export_loan_transactions(loan_id):
    """Export loan transactions as CSV."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Get loan details with calculated repaid amount
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.date_borrowed,
               COALESCE(SUM(at.amount), 0) as amount_repaid,
               l.bank_name
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


@app.route("/match", methods=["GET", "POST"])
@login_required
def match_transactions():
    if request.method == "POST":
        connector_type = request.form.get("connector_type", "csv")
        connector = None
        transactions = []

        try:
            if connector_type == "csv":
                # CSV Upload
                csv_content = request.form.get("transactions_csv")
                if not csv_content:
                    flash("Please provide CSV data", "error")
                    return render_template("match_upload.html",
                                         available_connectors=ConnectorRegistry.get_available_connectors())

                connector = CSVConnector(csv_content=csv_content)
                transactions = connector.get_transactions()

            else:
                # API Connector (e.g., Up Bank)
                connector = ConnectorRegistry.create_from_env(connector_type)

                if not connector:
                    flash(f"Unable to connect to your bank. Please contact support to set up automatic imports.", "error")
                    return render_template("match_upload.html",
                                         available_connectors=ConnectorRegistry.get_available_connectors())

                # Test connection first
                if not connector.test_connection():
                    flash(f"Unable to connect to {connector.connector_name}. Please try again or contact support if the issue persists.", "error")
                    return render_template("match_upload.html",
                                         available_connectors=ConnectorRegistry.get_available_connectors())

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
            return render_template("match_upload.html",
                                 available_connectors=ConnectorRegistry.get_available_connectors())
        except ValueError as e:
            flash(f"Authentication error: {str(e)}", "error")
            return render_template("match_upload.html",
                                 available_connectors=ConnectorRegistry.get_available_connectors())
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
            return render_template("match_upload.html",
                                 available_connectors=ConnectorRegistry.get_available_connectors())

    # GET request - show upload form
    return render_template("match_upload.html",
                         available_connectors=ConnectorRegistry.get_available_connectors())


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
                           COALESCE(SUM(at.amount), 0) as current_repaid, l.loan_type
                    FROM loans l
                    LEFT JOIN applied_transactions at ON l.id = at.loan_id
                    WHERE l.id = ? AND l.user_id = ?
                    GROUP BY l.id
                """, (loan_id, get_current_user_id()))
                loan_details = c.fetchone()

                if loan_details:
                    loan_id_db, borrower_name, borrower_email, access_token, loan_amount, current_repaid, loan_type = loan_details

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

                    # Send email notification if borrower has email and access token
                    if borrower_email and access_token:
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


if __name__ == "__main__":
    app.run(debug=True)
