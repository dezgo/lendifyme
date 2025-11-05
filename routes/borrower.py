"""
Borrower portal routes - self-service access for borrowers.
"""
from flask import Blueprint, render_template, request, session, redirect, flash, current_app as app
from helpers.decorators import login_required, get_current_user_id
from helpers.db import get_db_connection
from services.loans import get_loan_dek
from services.encryption import decrypt_field
import sqlite3

# Create blueprint
borrower_bp = Blueprint('borrower', __name__)


@borrower_bp.route("/borrower/<token>")
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


@borrower_bp.route("/borrower/<token>/notifications", methods=["POST"])
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


@borrower_bp.route("/loan/<int:loan_id>/send-invite", methods=["GET", "POST"])
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
