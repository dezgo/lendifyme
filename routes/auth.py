"""
Authentication routes blueprint.

Handles user registration, login, logout, email verification, and recovery.
"""
from flask import Blueprint, render_template, request, redirect, session, flash, url_for, current_app
from flask_mail import Message
import sqlite3
import time
import os
from services.auth_helpers import (
    generate_recovery_codes,
    verify_recovery_code,
    generate_magic_link_token,
    get_magic_link_expiry,
    is_magic_link_expired
)
from services.email_sender import send_magic_link_email
from helpers.decorators import login_required
from helpers.utils import get_db_path, log_event, get_current_user_id

# Get ENV from environment
ENV = os.environ.get("FLASK_ENV") or "production"

# Create blueprint (no url_prefix since routes have mixed prefixes)
auth_bp = Blueprint('auth', __name__)

# Import mail from app context (will be set when blueprint is registered)
mail = None


def init_mail(mail_instance):
    """Initialize mail instance for this blueprint."""
    global mail
    mail = mail_instance


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """User registration - super simple, just email."""
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        # Anti-spam measure 1: Honeypot field check
        # Bots often fill in all fields, including hidden ones
        honeypot = request.form.get("website", "")
        if honeypot:
            current_app.logger.warning(f"Registration blocked: honeypot filled for {email}")
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
                    current_app.logger.warning(f"Registration blocked: too fast ({time_taken}s) for {email}")
                    flash("Please take a moment to review the form.", "error")
                    return render_template("register.html")
            except (ValueError, TypeError):
                current_app.logger.warning(f"Registration blocked: invalid timestamp for {email}")
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
            current_app.logger.warning(f"Registration blocked: rate limit exceeded for IP {client_ip}")
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
            return redirect(url_for('auth.login'))

        # Generate verification token
        from services.auth_helpers import generate_verification_token, get_verification_expiry
        verification_token = generate_verification_token()
        verification_sent_at = get_verification_expiry(hours=0)  # Current time

        # Create user - no name, no password required initially
        c.execute("""
            INSERT INTO users (email, auth_provider, onboarding_completed, email_verified, verification_token, verification_sent_at)
            VALUES (?, 'magic_link', 0, 0, ?, ?)
        """, (email, verification_token, verification_sent_at))
        conn.commit()

        user_id = c.lastrowid
        conn.close()

        # Log analytics event
        log_event('user_signed_up', user_id=user_id, event_data={'email': email})

        # Send verification email
        verification_link = f"{current_app.config['APP_URL']}/auth/verify/{verification_token}"
        from services.email_sender import send_verification_email
        try:
            success, message = send_verification_email(email, None, verification_link)
            if success:
                current_app.logger.info(f"Verification email sent to {email}")
            else:
                current_app.logger.warning(f"Failed to send verification email: {message}")
        except Exception as e:
            current_app.logger.error(f"Error sending verification email: {e}")

        # Log them in immediately (even though unverified - they can still use basic features)
        session.permanent = True  # Ensure session persists across redirects
        session['user_id'] = user_id
        session['user_email'] = email
        session['user_name'] = None

        # Redirect to onboarding
        return redirect("/onboarding")

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """User login - supports both password and magic link."""
    if request.method == "POST":
        current_app.logger.info("Login POST request received")
        email = request.form.get("email")
        password = request.form.get("password")
        current_app.logger.info(f"Login attempt for email: {email}")

        if not email:
            flash("Email is required", "error")
            return render_template("login.html")

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        c.execute("SELECT id, email, name, password_hash, auth_provider FROM users WHERE email = ?", (email,))
        user = c.fetchone()

        if not user:
            # Don't reveal if email exists or not for security
            current_app.logger.info(f"User not found for email: {email}")
            if password:
                flash("Invalid email or password", "error")
            else:
                flash("If that email is registered, you'll receive a magic link shortly.", "success")
            conn.close()
            return render_template("login.html")

        user_id, user_email, user_name, password_hash, auth_provider = user
        current_app.logger.info(f"User found: {user_id} - {user_email}")

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
                            current_app.logger.info(f"User {user_id} has {len(loans_to_migrate)} loans that need recovery key encryption, but key not in session")
                            session['needs_recovery_key_migration'] = len(loans_to_migrate)
                        else:
                            # We have the recovery key! Migrate the loans now
                            from services.encryption import (
                                decrypt_dek_with_password, encrypt_dek_with_recovery_phrase
                            )

                            migrated_count = 0
                            for loan_id, encrypted_dek in loans_to_migrate:
                                try:
                                    # Decrypt DEK with password
                                    dek = decrypt_dek_with_password(encrypted_dek, password, encryption_salt)

                                    # Re-encrypt with recovery phrase
                                    encrypted_dek_recovery = encrypt_dek_with_recovery_phrase(dek, master_recovery_key, encryption_salt)

                                    # Update loan
                                    c.execute("""
                                        UPDATE loans
                                        SET encrypted_dek_recovery = ?
                                        WHERE id = ?
                                    """, (encrypted_dek_recovery, loan_id))

                                    migrated_count += 1
                                except Exception as e:
                                    current_app.logger.error(f"Failed to migrate loan {loan_id}: {e}")

                            if migrated_count > 0:
                                conn.commit()
                                current_app.logger.info(f"Successfully migrated {migrated_count} loans for user {user_id}")
                                session.pop('needs_recovery_key_migration', None)

                conn.close()
                current_app.logger.info(f"Password login successful for {user_email}")
                log_event('login_success', user_id=user_id, event_data={'method': 'password'})

                # Clear any old sync results
                session.pop('sync_results', None)

                flash("Welcome back!", "success")
                return redirect("/")
            else:
                # Password incorrect
                conn.close()
                current_app.logger.warning(f"Invalid password for {user_email}")
                flash("Invalid email or password", "error")
                return render_template("login.html")

        # No password provided - send magic link
        user_id, user_email, user_name = user_id, user_email, user_name
        current_app.logger.info(f"User requested magic link for {user_id}")

        # Send magic link
        current_app.logger.info(f"Generating magic link for user {user_id}")
        token = generate_magic_link_token()
        expires_at = get_magic_link_expiry(minutes=15)

        c.execute("""
            INSERT INTO magic_links (user_id, token, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, token, expires_at))
        conn.commit()
        conn.close()
        current_app.logger.info(f"Magic link token saved to database")

        # Send email with magic link
        magic_link = f"{current_app.config['APP_URL']}/auth/magic/{token}"
        email_sent = False
        current_app.logger.info(f"About to send magic link email to {user_email}")

        # Try Mailgun API first (recommended)
        success, message = send_magic_link_email(user_email, user_name, magic_link)
        current_app.logger.info(f"send_magic_link_email returned: success={success}, message={message}")
        if success:
            current_app.logger.info(f"Magic link sent successfully to {user_email}")
            flash("Check your email! We've sent you a magic link to sign in.", "success")
            email_sent = True
        else:
            current_app.logger.warning(f"Mailgun failed for {user_email}: {message}")
            # Try Flask-Mail (SMTP) as fallback
            if current_app.config.get('MAIL_USERNAME') and current_app.config.get('MAIL_DEFAULT_SENDER'):
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
                    current_app.logger.info(f"Magic link sent via SMTP to {user_email}")
                    flash("Check your email! We've sent you a magic link to sign in.", "success")
                    email_sent = True
                except Exception as e:
                    current_app.logger.error(f"SMTP failed for {user_email}: {str(e)}")
                    flash(f"Error sending email: {str(e)}", "error")

        # Development mode - print link to console if email failed
        if not email_sent:
            current_app.logger.warning(f"No email provider configured. Magic link for {user_email}: {magic_link}")
            print("\n" + "="*70)
            print("🔗 MAGIC LINK (Development Mode - Email not configured)")
            print("="*70)
            print(f"User: {user_email}")
            print(f"Link: {magic_link}")
            print("="*70 + "\n")
            flash("Email not configured. Check the console for your magic link!", "success")

        return render_template("login.html")

    return render_template("login.html")


@auth_bp.route("/auth/magic/<token>")
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
        return redirect(url_for('auth.login'))

    link_id, user_id, expires_at, used, user_email, user_name, user_role = result

    # Check if already used
    if used:
        flash("This login link has already been used", "error")
        conn.close()
        return redirect(url_for('auth.login'))

    # Check if expired
    if is_magic_link_expired(expires_at):
        flash("This login link has expired. Request a new one.", "error")
        conn.close()
        return redirect(url_for('auth.login'))

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


@auth_bp.route("/auth/verify/<token>")
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
        return redirect(url_for('auth.login'))

    user_id, user_email, user_name, verification_sent_at, email_verified = result

    # Check if already verified
    if email_verified:
        flash("Your email is already verified!", "success")
        conn.close()
        return redirect(url_for('auth.login'))

    # Check if expired (24 hours)
    if verification_sent_at and is_verification_expired(verification_sent_at, hours=24):
        flash("This verification link has expired. Request a new one from your account settings.", "error")
        conn.close()
        return redirect(url_for('auth.login'))

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


@auth_bp.route("/resend-verification", methods=["POST"])
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
    verification_link = f"{current_app.config['APP_URL']}/auth/verify/{verification_token}"
    from services.email_sender import send_verification_email
    try:
        success, message = send_verification_email(email, name, verification_link)
        if success:
            current_app.logger.info(f"Verification email resent to {email}")
            flash("Verification email sent! Check your inbox.", "success")
        else:
            current_app.logger.warning(f"Failed to resend verification email: {message}")
            flash("Failed to send email. Please try again later.", "error")
    except Exception as e:
        current_app.logger.error(f"Error sending verification email: {e}")
        flash("Failed to send email. Please try again later.", "error")

    return redirect("/")


@auth_bp.route("/auth/recovery-phrase")
@login_required
def show_recovery_phrase():
    """Show master recovery phrase after password setup (one-time view)."""
    if 'show_master_recovery_phrase' not in session:
        flash("No recovery phrase to show", "error")
        return redirect(url_for('index'))

    master_recovery_phrase = session.get('show_master_recovery_phrase')
    redirect_to = request.args.get('redirect')  # Where to redirect after showing phrase

    # Clear from session after showing once
    session.pop('show_master_recovery_phrase', None)

    return render_template("recovery_phrase.html", master_recovery_phrase=master_recovery_phrase, redirect_to=redirect_to)


@auth_bp.route("/logout")
def logout():
    """User logout."""
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for('index'))
