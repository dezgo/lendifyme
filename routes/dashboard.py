"""
Dashboard blueprint: landing/dashboard at /, password unlock, onboarding,
and the public feedback-submit endpoint.
"""
import sqlite3

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)

from helpers.db import get_db_connection
from helpers.decorators import login_required
from helpers.events import log_event
from helpers.session_helpers import (
    get_current_user_id,
    get_user_encryption_salt,
    get_user_password_from_session,
    is_email_verified,
)
from schemas.feedback import ValidationError, validate_feedback_input
from services.feedback_service import submit_feedback
from services.loans import (
    check_loan_limit,
    decrypt_loans,
    encrypt_loan_data,
    get_user_subscription_tier,
)


dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route("/", methods=["GET", "POST"])
def index():
    # Public landing
    current_app.logger.info(f"Index route hit. Session user_id: {session.get('user_id')}")
    if not session.get("user_id"):
        current_app.logger.info("No user_id in session, showing landing page")
        return render_template("landing.html")

    # Create loan (POST)
    if request.method == "POST":
        redirect_to = _handle_index_post(request.form)
        return redirect(redirect_to)

    # Dashboard (GET)
    context_or_redirect = _build_dashboard_context()
    if isinstance(context_or_redirect, dict):
        # Pop any prefill data saved before the subscribe redirect
        prefill = session.pop('prefill_loan', None) or {}
        return render_template(
            "index.html",
            loans=context_or_redirect["loans"],
            app_url=current_app.config["APP_URL"],
            email_verified=context_or_redirect["email_verified"],
            has_password=context_or_redirect["has_password"],
            needs_password_unlock=context_or_redirect.get("needs_password_unlock", False),
            prefill=prefill,
        )
    return redirect(context_or_redirect)


@dashboard_bp.route("/unlock", methods=["POST"])
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
    c.execute(
        "SELECT password_hash, master_recovery_key_hash, encryption_salt FROM users WHERE id = ?",
        (get_current_user_id(),),
    )
    user_row = c.fetchone()
    conn.close()

    if not user_row:
        flash("User not found", "error")
        return redirect("/")

    password_hash, recovery_key_hash, _ = user_row

    if password:
        if not password_hash:
            flash("No password set for this account", "error")
            return redirect("/")

        from werkzeug.security import check_password_hash
        if check_password_hash(password_hash, password):
            session['user_password'] = password
            flash("Loans unlocked successfully!", "success")
            return redirect("/")
        flash("Incorrect password", "error")
        return redirect("/")

    if recovery_phrase:
        if not recovery_key_hash:
            flash("No recovery phrase set for this account", "error")
            return redirect("/")

        from werkzeug.security import check_password_hash
        from services.encryption import normalize_recovery_phrase

        normalized_phrase = normalize_recovery_phrase(recovery_phrase)

        if check_password_hash(recovery_key_hash, normalized_phrase):
            session['user_password'] = normalized_phrase
            # Also store the recovery key itself for future loan creation
            session['master_recovery_key'] = normalized_phrase
            flash("Loans unlocked successfully with recovery phrase!", "success")
            return redirect("/")
        flash("Incorrect recovery phrase", "error")
        return redirect("/")

    return redirect("/")


@dashboard_bp.route("/onboarding")
@login_required
def onboarding():
    """Onboarding flow for new users."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT onboarding_completed FROM users WHERE id = ?", (get_current_user_id(),))
    user = c.fetchone()
    conn.close()

    if user and user[0]:
        return redirect("/")

    # Skip step 1 (email confirmation) as it's confusing after registration
    step = request.args.get('step', '2')

    if step == '1':
        # Kept for backwards compatibility, but skipped by default
        return render_template("onboarding_step1.html", email=session.get('user_email'))

    if step == '2':
        user_password = get_user_password_from_session()
        encryption_salt = get_user_encryption_salt()

        if not user_password or not encryption_salt:
            flash("First, let's secure your account with a password to encrypt your loan data.", "info")
            return redirect("/settings/password?redirect=onboarding")

        if not is_email_verified():
            flash(
                "We sent a verification link to your email. Click it to add your first loan.",
                "info",
            )
            return redirect("/")

        return render_template("onboarding_step2.html")

    if step == 'complete':
        user_id = get_current_user_id()
        if not user_id:
            current_app.logger.error("Session lost during onboarding completion")
            flash("Session expired. Please log in again.", "error")
            return redirect("/login")

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET onboarding_completed = 1 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        current_app.logger.info(f"Onboarding completed for user {user_id}")
        flash("Welcome to LendifyMe! 🎉", "success")
        return redirect("/")

    return redirect("/onboarding?step=2")


@dashboard_bp.route("/onboarding/update-email", methods=["POST"])
@login_required
def onboarding_update_email():
    """Update email during onboarding."""
    new_email = request.form.get("email", "").strip()

    if not new_email:
        flash("Email is required", "error")
        return redirect("/onboarding?step=1")

    conn = get_db_connection()
    c = conn.cursor()

    c.execute(
        "SELECT id FROM users WHERE email = ? AND id != ?",
        (new_email, get_current_user_id()),
    )
    if c.fetchone():
        flash("That email is already in use", "error")
        conn.close()
        return redirect("/onboarding?step=1")

    c.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, get_current_user_id()))
    conn.commit()
    conn.close()

    session['user_email'] = new_email

    flash("Email updated!", "success")
    return redirect("/onboarding?step=1")


@dashboard_bp.route("/feedback/submit", methods=["POST"])
def feedback_submit_route():
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

    try:
        fb_id, _ = submit_feedback(data)
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), getattr(e, "status_code", 400)

    return jsonify({"success": True, "id": fb_id})


# -----------------------------
# Internal helpers
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
    onboarding_flag = form.get("onboarding")

    # Gate: email verification required before any loan creation
    if not is_email_verified():
        session['prefill_loan'] = {
            'borrower': borrower,
            'bank_name': bank_name,
            'date_borrowed': date_borrowed,
            'amount': amount,
            'note': note,
            'repayment_amount': repayment_amount,
            'repayment_frequency': repayment_frequency,
            'loan_type': loan_type,
        }
        flash(
            "Please verify your email to create your first loan. "
            "Check your inbox for the verification link.",
            "error",
        )
        return "/"

    # Gate: subscription limits
    _, max_loans, can_create = check_loan_limit()
    if not can_create:
        tier_name = get_user_subscription_tier().title()
        if max_loans is not None:
            flash(
                f"You've reached the limit of {max_loans} loans on the {tier_name} plan. "
                "Upgrade to create more!",
                "error",
            )
        session['pending_loan_form'] = {
            'borrower': borrower,
            'bank_name': bank_name,
            'date_borrowed': date_borrowed,
            'amount': amount,
            'note': note,
            'repayment_amount': repayment_amount,
            'repayment_frequency': repayment_frequency,
            'loan_type': loan_type,
        }
        return "/pricing"

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
            return "/"

        try:
            log_event("loan_created", event_data={"loan_type": loan_type, "amount": float(amount)})
        except Exception:
            current_app.logger.exception("Failed to log loan_created event")

    if onboarding_flag == "1":
        return "/onboarding?step=complete"

    return "/"


def _safe_float_parse(value_str, field_name):
    """Safely parse a string to float with validation and error handling."""
    if not value_str or value_str.strip() == "":
        return None

    try:
        cleaned = value_str.replace('$', '').replace(',', '').strip()
        result = float(cleaned)

        if result < 0:
            flash(f"{field_name} cannot be negative", "error")
            return None

        if result > 999999999:
            flash(f"{field_name} is too large", "error")
            return None

        return result

    except (ValueError, TypeError):
        flash(f"Invalid {field_name}: '{value_str}'. Please enter a valid number.", "error")
        return None


def _create_encrypted_loan(
    *,
    borrower,
    bank_name,
    date_borrowed,
    amount_str,
    note,
    repayment_amount_str,
    repayment_frequency,
    loan_type,
):
    """Do the encryption + insert. Returns True on success and flashes on failure."""
    from services.encryption import (
        create_token_from_dek,
        encrypt_dek_with_password,
        encrypt_dek_with_recovery_phrase,
        generate_dek,
    )

    amount = _safe_float_parse(amount_str, "Loan amount")
    if amount is None:
        return False

    repayment_amount = _safe_float_parse(repayment_amount_str, "Repayment amount")

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
            "amount": amount,
            "note": note,
            "borrower_email": None,
            "repayment_amount": repayment_amount,
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
        current_app.logger.error(
            "Failed to create loan (likely needs migrations for nullable plaintext columns): %s",
            e,
        )
        flash("Database error. Please restart the application to run migrations.", "error")
        return False
    except Exception:
        current_app.logger.exception("Unhandled error creating encrypted loan")
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

        c.execute("SELECT COUNT(*) FROM loans WHERE user_id = ?", (get_current_user_id(),))
        loan_count = c.fetchone()[0]

        if not user_password and loan_count > 0:
            c.execute("SELECT password_hash FROM users WHERE id = ?", (get_current_user_id(),))
            user_row = c.fetchone()
            has_password_in_db = user_row and user_row[0] is not None

            if has_password_in_db:
                # User logged in via magic link but has encrypted loans
                return {
                    "loans": [],
                    "email_verified": is_email_verified(),
                    "has_password": True,
                    "needs_password_unlock": True,
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
