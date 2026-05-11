"""
Transaction matching routes - CSV import, matching, review, apply/reject.
"""
from flask import Blueprint, render_template, request, session, redirect, flash, jsonify, current_app as app
from helpers.decorators import login_required
from helpers.session_helpers import get_current_user_id, is_email_verified
from helpers.events import log_event
from helpers.db import get_db_connection, get_db_path
from services.loans import get_loan_dek, decrypt_loan_row
from services.transaction_matcher import match_transactions_to_loans, parse_csv_transactions
from datetime import datetime, timedelta
import json
import hashlib
import secrets
import sqlite3


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
        c.execute("""
            SELECT COUNT(*) FROM applied_transactions
            WHERE date = ? AND description = ? AND amount = ?
        """, (transaction['date'], transaction['description'], transaction_amount_abs))

        applied_count = c.fetchone()[0]

        # Check if this transaction was rejected for this specific loan
        # Check both abs and signed amounts for backwards compatibility with old data
        c.execute("""
            SELECT COUNT(*) FROM rejected_matches
            WHERE date = ? AND description = ?
            AND (amount = ? OR amount = ?)
            AND loan_id = ?
        """, (transaction['date'], transaction['description'],
              transaction_amount_abs, transaction['amount'], loan_id))

        rejected_count = c.fetchone()[0]

        if applied_count == 0 and rejected_count == 0:
            filtered_matches.append(match)

    conn.close()
    return filtered_matches


# Create blueprint
matching_bp = Blueprint('matching', __name__, url_prefix='/match')


@matching_bp.route("", methods=["GET", "POST"])
@login_required
def match_transactions():
    if not is_email_verified():
        flash("Please verify your email to use transaction matching. Check your inbox for the verification link.", "error")
        return redirect("/")

    if request.method == "POST":
        try:
            csv_content = request.form.get("transactions_csv")
            if not csv_content:
                flash("Please provide CSV data", "error")
                return render_template("match_upload.html")

            transaction_dicts = parse_csv_transactions(csv_content)

            # Get user password from session (required for decrypting loan data)
            user_password = session.get('user_password')
            if not user_password:
                flash("Please log in with your password to match transactions.", "error")
                return redirect("/login")

            # Get all loans for current user with calculated repaid amounts AND loan_type
            conn = sqlite3.connect(get_db_path())
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT l.id, l.borrower, l.borrower_encrypted, l.amount, l.amount_encrypted,
                       l.note, l.note_encrypted, l.date_borrowed,
                       COALESCE(SUM(at.amount), 0) as amount_repaid,
                       l.repayment_amount, l.repayment_amount_encrypted,
                       l.repayment_frequency, l.bank_name, l.bank_name_encrypted,
                       l.loan_type, l.encrypted_dek
                FROM loans l
                LEFT JOIN applied_transactions at ON l.id = at.loan_id
                WHERE l.user_id = ?
                GROUP BY l.id
            """, (get_current_user_id(),))
            loan_rows = c.fetchall()
            conn.close()

            loans = []
            for row in loan_rows:
                dek = get_loan_dek(row['id'], user_password=user_password)
                fields = decrypt_loan_row(row, dek)

                loans.append({
                    'id': row['id'],
                    'borrower': fields['borrower'],
                    'amount': fields['amount'] or 0.0,
                    'note': fields['note'] or '',
                    'date_borrowed': row['date_borrowed'],
                    'amount_repaid': row['amount_repaid'],
                    'repayment_amount': fields['repayment_amount'],
                    'repayment_frequency': fields['repayment_frequency'],
                    'bank_name': fields['bank_name'],
                    'loan_type': row['loan_type']
                })

            matches = match_transactions_to_loans(transaction_dicts, loans)
            matches = filter_duplicate_transactions(matches)

            # Add unique IDs to each match to avoid index sync issues
            for match in matches:
                match_str = f"{match['transaction']['date']}-{match['transaction']['description']}-{match['transaction']['amount']}-{match['loan']['id']}"
                match['match_id'] = hashlib.md5(match_str.encode()).hexdigest()[:16]

            # Store context transactions (within ±7 days of any match) for the review UI
            context_transactions = []
            if matches:
                match_dates = set()
                for match in matches:
                    try:
                        match_dates.add(datetime.strptime(match['transaction']['date'], '%Y-%m-%d'))
                    except ValueError:
                        pass

                for t in transaction_dicts:
                    try:
                        t_date = datetime.strptime(t['date'], '%Y-%m-%d')
                        for match_date in match_dates:
                            if abs((t_date - match_date).days) <= 7:
                                context_transactions.append(t)
                                break
                    except (ValueError, KeyError):
                        pass

            # Store matches and context transactions in DB (avoid cookie size limits)
            session_key = secrets.token_urlsafe(16)
            expires_at = (datetime.now() + timedelta(hours=24)).isoformat()

            conn = get_db_connection()
            c = conn.cursor()

            c.execute("DELETE FROM pending_matches_data WHERE user_id = ? AND expires_at < ?",
                     (get_current_user_id(), datetime.now().isoformat()))

            c.execute("""
                INSERT INTO pending_matches_data (user_id, session_key, matches_json, context_transactions_json, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (get_current_user_id(), session_key, json.dumps(matches), json.dumps(context_transactions), expires_at))
            conn.commit()
            conn.close()

            session['pending_matches_key'] = session_key

            app.logger.info(f"Stored {len(matches)} matches and {len(context_transactions)} context transactions in database")

            return redirect("/match/review")

        except Exception:
            app.logger.exception("Error processing CSV match upload")
            flash("Sorry, something went wrong processing your CSV. Please check the format and try again.", "error")
            return render_template("match_upload.html")

    return render_template("match_upload.html")


@matching_bp.route("/review")
@login_required
def review_matches():
    """Show pending matches for review."""
    session_key = session.get('pending_matches_key')

    if not session_key:
        flash("No pending matches. Import transactions first.", "error")
        return redirect("/match")

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


# Apply/reject match handlers — registered at app level (not under /match prefix) for URL compat
def apply_match_handler():
    """Apply a pending match from review."""
    from services.loans import has_feature

    match_id = request.form.get("match_id")
    session_key = session.get('pending_matches_key')

    if match_id and session_key:
        conn = get_db_connection()
        c = conn.cursor()

        c.execute("""
            SELECT id, matches_json
            FROM pending_matches_data
            WHERE user_id = ? AND session_key = ?
        """, (get_current_user_id(), session_key))

        result = c.fetchone()

        if result:
            db_id, matches_json = result
            matches = json.loads(matches_json)

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

                user_password = session.get('user_password')
                if not user_password:
                    conn.close()
                    return jsonify({'error': 'Please log in with your password'}), 401

                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("""
                    SELECT l.id, l.borrower, l.borrower_encrypted, l.borrower_email, l.borrower_email_encrypted,
                           l.borrower_access_token, l.amount, l.amount_encrypted,
                           COALESCE(SUM(at.amount), 0) as current_repaid, l.loan_type, l.borrower_notifications_enabled,
                           l.encrypted_dek
                    FROM loans l
                    LEFT JOIN applied_transactions at ON l.id = at.loan_id
                    WHERE l.id = ? AND l.user_id = ?
                    GROUP BY l.id
                """, (loan_id, get_current_user_id()))
                loan_row = c.fetchone()

                if loan_row:
                    dek = get_loan_dek(loan_row['id'], user_password=user_password)
                    fields = decrypt_loan_row(loan_row, dek)

                    borrower_name = fields['borrower']
                    borrower_email = fields['borrower_email']
                    loan_amount = fields['amount'] or 0.0

                    access_token = loan_row['borrower_access_token']
                    current_repaid = loan_row['current_repaid']
                    notifications_enabled = loan_row['borrower_notifications_enabled']

                    # For borrowing loans, transactions are negative (outgoing), but we store as positive repayments
                    amount_to_store = abs(transaction['amount'])

                    c.execute("""
                        INSERT INTO applied_transactions (date, description, amount, loan_id)
                        VALUES (?, ?, ?, ?)
                    """, (transaction['date'], transaction['description'],
                          amount_to_store, loan_id))

                    matches.pop(match_idx)
                    c.execute("""
                        UPDATE pending_matches_data
                        SET matches_json = ?
                        WHERE id = ?
                    """, (json.dumps(matches), db_id))

                    conn.commit()

                    new_balance = loan_amount - (current_repaid + amount_to_store)

                    log_event('transaction_matched', event_data={'loan_id': loan_id, 'amount': amount_to_store})

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
                    return ('', 204)

        conn.close()

    return ('', 400)


def reject_match_handler():
    """Reject a pending match from review."""
    match_id = request.form.get("match_id")
    session_key = session.get('pending_matches_key')

    if match_id and session_key:
        conn = get_db_connection()
        c = conn.cursor()

        c.execute("""
            SELECT id, matches_json
            FROM pending_matches_data
            WHERE user_id = ? AND session_key = ?
        """, (get_current_user_id(), session_key))

        result = c.fetchone()

        if result:
            db_id, matches_json = result
            matches = json.loads(matches_json)

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

                c.execute("""
                    INSERT INTO rejected_matches (date, description, amount, loan_id)
                    VALUES (?, ?, ?, ?)
                """, (transaction['date'], transaction['description'],
                      abs(transaction['amount']), loan_id))

                matches.pop(match_idx)
                c.execute("""
                    UPDATE pending_matches_data
                    SET matches_json = ?
                    WHERE id = ?
                """, (json.dumps(matches), db_id))

                conn.commit()
                conn.close()
                return ('', 204)

        conn.close()

    return ('', 400)
