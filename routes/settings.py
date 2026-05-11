"""
Settings routes - password, recovery phrase, bank connections management.
"""
from flask import Blueprint, render_template, request, session, redirect, flash, current_app as app
from helpers.decorators import login_required
from helpers.session_helpers import get_current_user_id, is_email_verified
from helpers.events import log_event
from helpers.db import get_db_connection, get_db_path


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


# Create blueprint
settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


@settings_bp.route("")
@login_required
def settings():
    """Settings hub page."""
    return render_template("settings.html")


@settings_bp.route("/password", methods=["GET", "POST"])
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

            flash("Account upgraded successfully.", "success")
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


@settings_bp.route("/password/success")
@login_required
def password_change_success():
    """Show success page after password change."""
    return render_template("password_success.html")


@settings_bp.route("/recovery", methods=["GET", "POST"])
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


