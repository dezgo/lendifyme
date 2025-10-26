import sqlite3
import os
import json
import logging
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

# Configure logging
if not app.debug:
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.mkdir('logs')

    # File handler with rotation (max 10MB, keep 10 backup files)
    file_handler = RotatingFileHandler('logs/lendifyme.log', maxBytes=10240000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('LendifyMe startup')


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

        # Check if this transaction has already been applied (to any loan)
        c.execute("""
            SELECT COUNT(*) FROM applied_transactions
            WHERE date = ? AND description = ? AND amount = ?
        """, (transaction['date'], transaction['description'], transaction['amount']))

        applied_count = c.fetchone()[0]

        # Check if this transaction was rejected for this specific loan
        c.execute("""
            SELECT COUNT(*) FROM rejected_matches
            WHERE date = ? AND description = ? AND amount = ? AND loan_id = ?
        """, (transaction['date'], transaction['description'], transaction['amount'], loan_id))

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
        email = request.form.get("email")
        recovery_code = request.form.get("recovery_code")

        if not email:
            flash("Email is required", "error")
            return render_template("login.html")

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        c.execute("SELECT id, email, name, recovery_codes FROM users WHERE email = ?", (email,))
        user = c.fetchone()

        if not user:
            # Don't reveal if email exists or not for security
            flash("If that email is registered, you'll receive a magic link shortly.", "success")
            conn.close()
            return render_template("login.html")

        user_id, user_email, user_name, recovery_codes_json = user

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
        token = generate_magic_link_token()
        expires_at = get_magic_link_expiry(minutes=15)

        c.execute("""
            INSERT INTO magic_links (user_id, token, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, token, expires_at))
        conn.commit()
        conn.close()

        # Send email with magic link
        magic_link = f"{app.config['APP_URL']}/auth/magic/{token}"
        email_sent = False

        # Try Mailgun API first (recommended)
        success, message = send_magic_link_email(user_email, user_name, magic_link)
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


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        borrower = request.form.get("borrower")
        bank_name = request.form.get("bank_name")
        date_borrowed = request.form.get("date_borrowed")
        amount = request.form.get("amount")
        note = request.form.get("note")
        repayment_amount = request.form.get("repayment_amount")
        repayment_frequency = request.form.get("repayment_frequency")

        if borrower and amount:
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute("""
                INSERT INTO loans (borrower, bank_name, amount, note, date_borrowed, repayment_amount, repayment_frequency, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (borrower,
                  bank_name if bank_name else None,
                  float(amount), note, date_borrowed,
                  float(repayment_amount) if repayment_amount else None,
                  repayment_frequency if repayment_frequency else None,
                  get_current_user_id()))
            conn.commit()
            conn.close()
        return redirect("/")

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.note, l.date_borrowed,
               COALESCE(SUM(at.amount), 0) as amount_repaid,
               l.repayment_amount, l.repayment_frequency, l.bank_name, l.created_at
        FROM loans l
        LEFT JOIN applied_transactions at ON l.id = at.loan_id
        WHERE l.user_id = ?
        GROUP BY l.id
        ORDER BY l.created_at DESC
    """, (get_current_user_id(),))

    loans = c.fetchall()
    conn.close()

    return render_template("index.html", loans=loans)


@app.route("/repay/<int:loan_id>", methods=["POST"])
@login_required
def repay(loan_id):
    repayment_amount = request.form.get("repayment_amount")

    if repayment_amount:
        # Verify loan ownership
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE id = ? AND user_id = ?", (loan_id, get_current_user_id()))
        if c.fetchone():
            # Record manual repayment as applied transaction
            c.execute("""
                INSERT INTO applied_transactions (date, description, amount, loan_id)
                VALUES (date('now'), 'Manual repayment', ?, ?)
            """, (float(repayment_amount), loan_id))
            conn.commit()
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
                    flash(f"API credentials not configured for {connector_type}. Please add to .env file.", "error")
                    return render_template("match_upload.html",
                                         available_connectors=ConnectorRegistry.get_available_connectors())

                # Test connection first
                if not connector.test_connection():
                    flash(f"Failed to connect to {connector.connector_name}. Please check your API credentials.", "error")
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
                # Only consider incoming transactions
                transactions = connector.filter_incoming_only(all_transactions)

                flash(f"Successfully fetched {len(transactions)} incoming transactions from {connector.connector_name} since {since_date}", "success")

            # Convert Transaction objects to dicts
            transaction_dicts = [t.to_dict() for t in transactions]
            all_transactions_dicts = [t.to_dict() for t in all_transactions]

            # Get all loans for current user with calculated repaid amounts
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute("""
                SELECT l.id, l.borrower, l.amount, l.note, l.date_borrowed,
                       COALESCE(SUM(at.amount), 0) as amount_repaid,
                       l.repayment_amount, l.repayment_frequency, l.bank_name
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
                    'bank_name': row[8]
                })

            # Find matches
            matches = match_transactions_to_loans(transaction_dicts, loans)

            # Filter out already-applied transactions
            matches = filter_duplicate_transactions(matches)

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

            # Store matches and context transactions in session
            session['pending_matches'] = matches
            session['all_transactions'] = context_transactions

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
    matches = session.get('pending_matches', [])
    all_transactions = session.get('all_transactions', [])

    if not matches:
        flash("No pending matches. Import transactions first.", "error")
        return redirect("/match")

    return render_template("match_review.html", matches=matches, all_transactions=all_transactions)


@app.route("/apply-match", methods=["POST"])
@login_required
def apply_match():
    match_index = request.form.get("match_index")

    if match_index is not None and 'pending_matches' in session:
        matches = session['pending_matches']
        match_idx = int(match_index)

        if 0 <= match_idx < len(matches):
            match = matches[match_idx]
            loan_id = match['loan']['id']
            amount = match['transaction']['amount']
            transaction = match['transaction']

            # Record the applied transaction
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()

            # Verify loan ownership
            c.execute("SELECT id FROM loans WHERE id = ? AND user_id = ?", (loan_id, get_current_user_id()))
            if c.fetchone():
                # Record the applied transaction
                c.execute("""
                    INSERT INTO applied_transactions (date, description, amount, loan_id)
                    VALUES (?, ?, ?, ?)
                """, (transaction['date'], transaction['description'],
                      transaction['amount'], loan_id))
                conn.commit()

            conn.close()

            # Remove the applied match from session
            matches.pop(match_idx)
            session['pending_matches'] = matches

            flash(f"Applied ${amount:.2f} payment to {match['loan']['borrower']}", "success")

    # Return to review page with remaining matches
    return redirect("/match/review")


@app.route("/reject-match", methods=["POST"])
@login_required
def reject_match():
    match_index = request.form.get("match_index")

    if match_index is not None and 'pending_matches' in session:
        matches = session['pending_matches']
        match_idx = int(match_index)

        if 0 <= match_idx < len(matches):
            match = matches[match_idx]
            loan_id = match['loan']['id']
            transaction = match['transaction']

            # Record the rejected match to prevent future suggestions
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute("""
                INSERT INTO rejected_matches (date, description, amount, loan_id)
                VALUES (?, ?, ?, ?)
            """, (transaction['date'], transaction['description'],
                  transaction['amount'], loan_id))
            conn.commit()
            conn.close()

            # Remove the rejected match from session
            matches.pop(match_idx)
            session['pending_matches'] = matches

            flash(f"Marked transaction as not a match for {match['loan']['borrower']}", "success")

    # Return to review page with remaining matches
    return redirect("/match/review")


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
