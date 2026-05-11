"""
Loan management routes blueprint.

Handles loan creation, editing, deletion, repayments, and transaction history.
"""
from flask import Blueprint, render_template, request, redirect, flash, Response, session, current_app
from io import StringIO
import csv
import sqlite3
from helpers.decorators import login_required
from helpers.session_helpers import get_current_user_id, get_user_password_from_session
from helpers.events import log_event
from helpers.db import get_db_path
from services.loans import (
    get_loan_dek,
    has_feature,
    decrypt_loan_row,
)

# Create blueprint
loan_bp = Blueprint('loan', __name__)


def _safe_float_parse(value_str: str | None, default: float | None = None) -> float | None:
    """Safely parse a string to float with error handling.

    Returns:
        float if parsing succeeds, default if value_str is None/empty, None on error
    """
    if not value_str or (isinstance(value_str, str) and value_str.strip() == ""):
        return default

    try:
        # Remove common formatting (currency symbols, commas)
        if isinstance(value_str, str):
            cleaned = value_str.replace('$', '').replace(',', '').strip()
        else:
            cleaned = str(value_str)
        return float(cleaned)
    except (ValueError, TypeError):
        return None


@loan_bp.route("/repay/<int:loan_id>", methods=["POST"])
@login_required
def repay(loan_id):
    repayment_amount = request.form.get("repayment_amount", "").strip()
    if not repayment_amount:
        flash("Repayment amount is required", "error")
        return redirect("/")

    try:
        payment_amount = float(repayment_amount.replace('$', '').replace(',', '').strip())
        if payment_amount <= 0:
            flash("Repayment amount must be greater than zero", "error")
            return redirect("/")
        if payment_amount > 999999999:
            flash("Repayment amount is too large", "error")
            return redirect("/")
    except (ValueError, TypeError):
        flash(f"Invalid repayment amount: '{repayment_amount}'. Please enter a valid number.", "error")
        return redirect("/")

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Verify ownership, then record the repayment
    c.execute(
        "SELECT 1 FROM loans WHERE id = ? AND user_id = ?",
        (loan_id, get_current_user_id()),
    )
    if not c.fetchone():
        conn.close()
        flash("Loan not found", "error")
        return redirect("/")

    c.execute(
        """
        INSERT INTO applied_transactions (date, description, amount, loan_id)
        VALUES (date('now'), 'Manual repayment', ?, ?)
        """,
        (payment_amount, loan_id),
    )
    conn.commit()
    conn.close()
    return redirect("/")


@loan_bp.route("/edit/<int:loan_id>", methods=["GET", "POST"])
@login_required
def edit_loan(loan_id):
    from services.encryption import encrypt_field  # local import to avoid circulars

    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT
            l.*,
            COALESCE(SUM(at.amount), 0) AS amount_repaid
        FROM loans l
        LEFT JOIN applied_transactions at ON l.id = at.loan_id
        WHERE l.id = ? AND l.user_id = ?
        GROUP BY l.id
    """, (loan_id, get_current_user_id()))
    loan_row = c.fetchone()

    if not loan_row:
        conn.close()
        flash("Loan not found", "error")
        return redirect("/")

    user_password = get_user_password_from_session()

    if request.method == "POST":
        borrower = request.form.get("borrower") or None
        bank_name = request.form.get("bank_name") or None
        amount = request.form.get("amount") or None
        date_borrowed = request.form.get("date_borrowed") or None
        note = request.form.get("note") or None
        repayment_amount = request.form.get("repayment_amount") or None
        repayment_frequency = request.form.get("repayment_frequency") or None

        if not (borrower and amount):
            conn.close()
            return redirect("/")

        amount_float = _safe_float_parse(amount)
        if amount_float is None:
            flash(f"Invalid loan amount: '{amount}'. Please enter a valid number.", "error")
            conn.close()
            return redirect(f"/edit/{loan_id}")

        repayment_amount_float = _safe_float_parse(repayment_amount)
        if repayment_amount and repayment_amount_float is None:
            flash(f"Invalid repayment amount: '{repayment_amount}'. Please enter a valid number.", "error")
            conn.close()
            return redirect(f"/edit/{loan_id}")

        dek = get_loan_dek(loan_id, user_password=user_password)
        if not dek:
            flash("Unable to decrypt loan data. Please log in with your password.", "error")
            conn.close()
            return redirect("/")

        c.execute(
            """
            UPDATE loans
            SET borrower_encrypted = ?,
                bank_name_encrypted = ?,
                amount_encrypted = ?,
                note_encrypted = ?,
                repayment_amount_encrypted = ?,
                repayment_frequency_encrypted = ?,
                date_borrowed = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                encrypt_field(borrower, dek),
                encrypt_field(bank_name, dek) if bank_name else None,
                encrypt_field(str(amount_float), dek),
                encrypt_field(note, dek) if note else None,
                encrypt_field(str(repayment_amount_float), dek) if repayment_amount_float else None,
                encrypt_field(repayment_frequency, dek) if repayment_frequency else None,
                date_borrowed,
                loan_id,
                get_current_user_id(),
            ),
        )
        conn.commit()
        conn.close()
        log_event('loan_updated', event_data={'loan_id': loan_id})
        flash("Loan updated successfully", "success")
        return redirect("/")

    # GET: build decrypted model for the template
    dek = get_loan_dek(loan_id, user_password=user_password)
    fields = decrypt_loan_row(loan_row, dek)

    loan_for_form = {
        "id": loan_row["id"],
        "borrower": fields['borrower'],
        "bank_name": fields['bank_name'],
        "amount": fields['amount'],
        "date_borrowed": loan_row["date_borrowed"],
        "note": fields['note'],
        "repayment_amount": fields['repayment_amount'],
        "repayment_frequency": fields['repayment_frequency'],
        "amount_repaid": loan_row["amount_repaid"],
    }

    conn.close()
    return render_template("edit_loan.html", loan=loan_for_form)


@loan_bp.route("/delete/<int:loan_id>", methods=["POST"])
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


@loan_bp.route("/loan/<int:loan_id>/transactions")
@login_required
def loan_transactions(loan_id):
    """View all applied transactions for a specific loan."""
    from services.loans import get_loan_dek

    # Get user password from session for decryption
    user_password = session.get('user_password')
    if not user_password:
        flash("Please log in with your password to view transactions.", "error")
        return redirect("/login")

    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Get loan details (query both plaintext and encrypted columns)
    c.execute("""
        SELECT l.id, l.borrower, l.borrower_encrypted, l.amount, l.amount_encrypted,
               l.date_borrowed, l.bank_name, l.bank_name_encrypted, l.note, l.note_encrypted,
               l.encrypted_dek
        FROM loans l
        WHERE l.id = ? AND l.user_id = ?
    """, (loan_id, get_current_user_id()))
    loan_row = c.fetchone()

    if not loan_row:
        flash("Loan not found", "error")
        return redirect("/")

    # Get DEK for decryption using user password
    dek = get_loan_dek(loan_row['id'], user_password=user_password)
    fields = decrypt_loan_row(loan_row, dek)
    amount = fields['amount'] or 0.0

    # Transactions are stored as plaintext (description, amount) — no decryption needed
    c.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM applied_transactions WHERE loan_id = ?",
        (loan_id,),
    )
    amount_repaid = float(c.fetchone()[0] or 0.0)

    # Build loan tuple for template compatibility
    loan = (loan_row['id'], fields['borrower'], amount, loan_row['date_borrowed'], amount_repaid, fields['bank_name'], fields['note'])

    c.execute("""
        SELECT id, date, description, amount, applied_at
        FROM applied_transactions
        WHERE loan_id = ?
        ORDER BY date DESC
    """, (loan_id,))
    transaction_rows = c.fetchall()

    conn.close()

    transactions = [
        (
            row['id'],
            row['date'],
            row['description'],
            float(row['amount']) if row['amount'] is not None else 0.0,
            row['applied_at'],
        )
        for row in transaction_rows
    ]

    has_export = has_feature(get_current_user_id(), 'transaction_export')
    return render_template("loan_transactions.html", loan=loan, transactions=transactions, has_export=has_export)


@loan_bp.route("/loan/<int:loan_id>/transactions/export")
@login_required
def export_loan_transactions(loan_id):
    """Export loan transactions as CSV."""
    from services.loans import get_loan_dek

    # Check if user has transaction export feature
    if not has_feature(get_current_user_id(), 'transaction_export'):
        flash("Transaction export is available on Basic and Pro plans. Upgrade to export your transactions!", "error")
        return redirect("/pricing")

    # Get user password from session for decryption
    user_password = session.get('user_password')
    if not user_password:
        flash("Please log in with your password to export transactions.", "error")
        return redirect("/login")

    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Get loan details (query both plaintext and encrypted columns)
    c.execute("""
        SELECT l.id, l.borrower, l.borrower_encrypted, l.amount, l.amount_encrypted,
               l.date_borrowed, l.bank_name, l.bank_name_encrypted, l.note, l.note_encrypted,
               l.encrypted_dek
        FROM loans l
        WHERE l.id = ? AND l.user_id = ?
    """, (loan_id, get_current_user_id()))
    loan_row = c.fetchone()

    if not loan_row:
        flash("Loan not found", "error")
        return redirect("/")

    # Get DEK for decryption using user password
    dek = get_loan_dek(loan_row['id'], user_password=user_password)
    fields = decrypt_loan_row(loan_row, dek)
    amount = fields['amount'] or 0.0

    # Transactions are stored as plaintext (description, amount) — no decryption needed
    c.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM applied_transactions WHERE loan_id = ?",
        (loan_id,),
    )
    amount_repaid = float(c.fetchone()[0] or 0.0)

    # Build loan tuple for CSV generation
    loan = (loan_row['id'], fields['borrower'], amount, loan_row['date_borrowed'], amount_repaid, fields['bank_name'], fields['note'])

    c.execute("""
        SELECT id, date, description, amount, applied_at
        FROM applied_transactions
        WHERE loan_id = ?
        ORDER BY date DESC
    """, (loan_id,))
    transaction_rows = c.fetchall()

    conn.close()

    transactions = [
        (
            row['id'],
            row['date'],
            row['description'],
            float(row['amount']) if row['amount'] is not None else 0.0,
            row['applied_at'],
        )
        for row in transaction_rows
    ]

    # Build CSV content
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
    csv_content = output.getvalue()
    output.close()

    # Generate safe filename (handle None borrower name)
    borrower_safe = loan[1].replace(" ", "_") if loan[1] else "unknown"

    response = Response(csv_content, mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename=loan_{loan_id}_{borrower_safe}_transactions.csv'

    return response


@loan_bp.route("/remove-transaction/<int:transaction_id>", methods=["POST"])
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
