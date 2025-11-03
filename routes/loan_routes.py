"""
Loan management routes blueprint.

Handles loan creation, editing, deletion, repayments, and transaction history.
"""
from flask import Blueprint, render_template, request, redirect, flash, Response
from io import StringIO
import csv
import sqlite3
from helpers.decorators import login_required
from helpers.utils import get_db_path, log_event, get_current_user_id
from helpers.session_helpers import get_user_password_from_session
from services.loans import (
    get_loan_dek,
    has_feature
)

# Create blueprint
loan_bp = Blueprint('loan', __name__)


@loan_bp.route("/repay/<int:loan_id>", methods=["POST"])
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


@loan_bp.route("/edit/<int:loan_id>", methods=["GET", "POST"])
@login_required
def edit_loan(loan_id):
    from services.encryption import decrypt_field, encrypt_field  # local import to avoid circulars

    # Always load the loan first to know if it's encrypted
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

    # Helper: get DEK only if we need it
    user_password = get_user_password_from_session()
    dek = None
    def need_dek() -> bool:
        # Any encrypted column present?
        for col in ("borrower_encrypted", "amount_encrypted", "note_encrypted",
                    "bank_name_encrypted", "repayment_amount_encrypted",
                    "repayment_frequency_encrypted"):
            if col in loan_row.keys() and loan_row[col]:
                return True
        return False

    if request.method == "POST":
        borrower = request.form.get("borrower") or None
        bank_name = request.form.get("bank_name") or None
        amount = request.form.get("amount") or None
        date_borrowed = request.form.get("date_borrowed") or None
        note = request.form.get("note") or None
        repayment_amount = request.form.get("repayment_amount") or None
        repayment_frequency = request.form.get("repayment_frequency") or None

        if borrower and amount:
            # If this loan uses encrypted columns, update those; else update plaintext columns
            uses_encryption = need_dek()
            if uses_encryption:
                if dek is None:
                    dek = get_loan_dek(loan_id, user_password=user_password)

                # Encrypt the sensitive fields if the encrypted columns exist
                updates = []
                params = []

                # Borrower
                if "borrower_encrypted" in loan_row.keys():
                    updates.append("borrower_encrypted = ?")
                    params.append(encrypt_field(borrower, dek))
                    # keep plaintext NULL for zero-knowledge discipline
                    if "borrower" in loan_row.keys():
                        updates.append("borrower = NULL")

                elif "borrower" in loan_row.keys():
                    updates.append("borrower = ?")
                    params.append(borrower)

                # Bank name (less sensitive—store as plaintext unless you actually created *_encrypted)
                if "bank_name_encrypted" in loan_row.keys():
                    updates.append("bank_name_encrypted = ?")
                    params.append(encrypt_field(bank_name, dek) if bank_name else None)
                    if "bank_name" in loan_row.keys():
                        updates.append("bank_name = NULL")
                elif "bank_name" in loan_row.keys():
                    updates.append("bank_name = ?")
                    params.append(bank_name)

                # Amount
                if "amount_encrypted" in loan_row.keys():
                    updates.append("amount_encrypted = ?")
                    params.append(encrypt_field(str(float(amount)), dek))
                    if "amount" in loan_row.keys():
                        updates.append("amount = NULL")
                elif "amount" in loan_row.keys():
                    updates.append("amount = ?")
                    params.append(float(amount))

                # Date borrowed (usually non-sensitive: keep plaintext)
                if "date_borrowed" in loan_row.keys():
                    updates.append("date_borrowed = ?")
                    params.append(date_borrowed)

                # Note
                if "note_encrypted" in loan_row.keys():
                    updates.append("note_encrypted = ?")
                    params.append(encrypt_field(note, dek) if note else None)
                    if "note" in loan_row.keys():
                        updates.append("note = NULL")
                elif "note" in loan_row.keys():
                    updates.append("note = ?")
                    params.append(note)

                # Repayment amount
                if "repayment_amount_encrypted" in loan_row.keys():
                    updates.append("repayment_amount_encrypted = ?")
                    params.append(encrypt_field(str(float(repayment_amount)), dek) if repayment_amount else None)
                    if "repayment_amount" in loan_row.keys():
                        updates.append("repayment_amount = NULL")
                elif "repayment_amount" in loan_row.keys():
                    updates.append("repayment_amount = ?")
                    params.append(float(repayment_amount) if repayment_amount else None)

                # Repayment frequency (string)
                if "repayment_frequency_encrypted" in loan_row.keys():
                    updates.append("repayment_frequency_encrypted = ?")
                    params.append(encrypt_field(repayment_frequency, dek) if repayment_frequency else None)
                    if "repayment_frequency" in loan_row.keys():
                        updates.append("repayment_frequency = NULL")
                elif "repayment_frequency" in loan_row.keys():
                    updates.append("repayment_frequency = ?")
                    params.append(repayment_frequency if repayment_frequency else None)

                # Finalize
                params.extend([loan_id, get_current_user_id()])
                c.execute(f"""
                    UPDATE loans
                    SET {", ".join(updates)}
                    WHERE id = ? AND user_id = ?
                """, tuple(params))
                conn.commit()
            else:
                # Legacy plaintext update (your current code, but using Row + None handling)
                c.execute("""
                    UPDATE loans
                    SET borrower = ?, bank_name = ?, amount = ?, date_borrowed = ?, note = ?,
                        repayment_amount = ?, repayment_frequency = ?
                    WHERE id = ? AND user_id = ?
                """, (
                    borrower,
                    bank_name,
                    float(amount),
                    date_borrowed,
                    note,
                    float(repayment_amount) if repayment_amount else None,
                    repayment_frequency if repayment_frequency else None,
                    loan_id, get_current_user_id()
                ))
                conn.commit()

            conn.close()
            log_event('loan_updated', event_data={'loan_id': loan_id})
            flash("Loan updated successfully", "success")
        else:
            conn.close()

        return redirect("/")

    # -------- GET: build decrypted model for the template --------
    if need_dek():
        if dek is None:
            dek = get_loan_dek(loan_id, user_password=user_password)

    def pick(name: str, enc: str | None = None, cast=None):
        val = None
        if enc and enc.endswith("_encrypted") and enc in loan_row.keys():
            raw = loan_row[enc]
            if raw not in (None, ""):
                # Only decrypt strings/bytes; never numbers
                if isinstance(raw, (bytes, bytearray)):
                    v = decrypt_field(raw.decode(), dek)
                elif isinstance(raw, str):
                    v = decrypt_field(raw, dek)
                else:
                    # If somehow a non-string landed here, just use it as-is
                    v = raw
                val = v
        elif name in loan_row.keys():
            val = loan_row[name]

        if cast and val is not None:
            try:
                return cast(val)
            except Exception:
                return val
        return val

    loan_for_form = {
        "id": loan_row["id"],
        "borrower": pick("borrower", "borrower_encrypted"),
        "bank_name": pick("bank_name", "bank_name_encrypted"),
        "amount": pick("amount", "amount_encrypted", cast=float),
        "date_borrowed": loan_row["date_borrowed"],
        "note": pick("note", "note_encrypted"),
        "repayment_amount": pick("repayment_amount", "repayment_amount_encrypted", cast=lambda x: float(x) if x not in (None, "") else None),
        "repayment_frequency": pick("repayment_frequency", "repayment_frequency_encrypted"),
        "amount_repaid": loan_row["amount_repaid"],  # computed, no enc
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


@loan_bp.route("/loan/<int:loan_id>/transactions/export")
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

    response = Response(csv_content, mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename=loan_{loan_id}_{loan[1].replace(" ", "_")}_transactions.csv'

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
