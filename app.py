import sqlite3
import os
import json
from datetime import datetime, timedelta
from services import migrations
from services.transaction_matcher import match_transactions_to_loans
from services.connectors.registry import ConnectorRegistry
from services.connectors.csv_connector import CSVConnector
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, flash


# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Config
app.config['DATABASE'] = 'lendifyme.db'
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')


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


@app.route("/", methods=["GET", "POST"])
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
                INSERT INTO loans (borrower, bank_name, amount, note, date_borrowed, repayment_amount, repayment_frequency)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (borrower,
                  bank_name if bank_name else None,
                  float(amount), note, date_borrowed,
                  float(repayment_amount) if repayment_amount else None,
                  repayment_frequency if repayment_frequency else None))
            conn.commit()
            conn.close()
        return redirect("/")

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("""
        SELECT id, borrower, amount, note, date_borrowed, amount_repaid,
               repayment_amount, repayment_frequency, bank_name, created_at
        FROM loans
        ORDER BY created_at DESC
    """)

    loans = c.fetchall()
    conn.close()

    return render_template("index.html", loans=loans)


@app.route("/repay/<int:loan_id>", methods=["POST"])
def repay(loan_id):
    repayment_amount = request.form.get("repayment_amount")

    if repayment_amount:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute("""
            UPDATE loans
            SET amount_repaid = amount_repaid + ?
            WHERE id = ?
        """, (float(repayment_amount), loan_id))
        conn.commit()
        conn.close()

    return redirect("/")


@app.route("/edit/<int:loan_id>", methods=["GET", "POST"])
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
                WHERE id = ?
            """, (borrower,
                  bank_name if bank_name else None,
                  float(amount), date_borrowed, note,
                  float(repayment_amount) if repayment_amount else None,
                  repayment_frequency if repayment_frequency else None,
                  loan_id))
            conn.commit()
            conn.close()
            flash("Loan updated successfully", "success")

        return redirect("/")

    # GET request - show edit form
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("""
        SELECT id, borrower, amount, note, date_borrowed, amount_repaid,
               repayment_amount, repayment_frequency, bank_name
        FROM loans
        WHERE id = ?
    """, (loan_id,))
    loan = c.fetchone()
    conn.close()

    if not loan:
        flash("Loan not found", "error")
        return redirect("/")

    return render_template("edit_loan.html", loan=loan)


@app.route("/delete/<int:loan_id>", methods=["POST"])
def delete_loan(loan_id):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("DELETE FROM loans WHERE id = ?", (loan_id,))
    conn.commit()
    conn.close()

    flash("Loan deleted successfully", "success")
    return redirect("/")


@app.route("/loan/<int:loan_id>/transactions")
def loan_transactions(loan_id):
    """View all applied transactions for a specific loan."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Get loan details
    c.execute("""
        SELECT id, borrower, amount, date_borrowed, amount_repaid, bank_name
        FROM loans
        WHERE id = ?
    """, (loan_id,))
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
def export_loan_transactions(loan_id):
    """Export loan transactions as CSV."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Get loan details
    c.execute("""
        SELECT id, borrower, amount, date_borrowed, amount_repaid, bank_name
        FROM loans
        WHERE id = ?
    """, (loan_id,))
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

            # Get all loans
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute("""
                SELECT id, borrower, amount, note, date_borrowed, amount_repaid,
                       repayment_amount, repayment_frequency, bank_name
                FROM loans
            """)
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
def review_matches():
    """Show pending matches for review."""
    matches = session.get('pending_matches', [])
    all_transactions = session.get('all_transactions', [])

    if not matches:
        flash("No pending matches. Import transactions first.", "error")
        return redirect("/match")

    return render_template("match_review.html", matches=matches, all_transactions=all_transactions)


@app.route("/apply-match", methods=["POST"])
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

            # Apply the repayment
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute("""
                UPDATE loans
                SET amount_repaid = amount_repaid + ?
                WHERE id = ?
            """, (amount, loan_id))

            # Record the applied transaction to prevent duplicates
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
def remove_transaction(transaction_id):
    """Remove an applied transaction and reverse its effect on the loan."""
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()

    # Get the transaction details before deleting
    c.execute("""
        SELECT loan_id, amount, description, date
        FROM applied_transactions
        WHERE id = ?
    """, (transaction_id,))

    transaction = c.fetchone()

    if transaction:
        loan_id, amount, description, date = transaction

        # Reverse the repayment
        c.execute("""
            UPDATE loans
            SET amount_repaid = amount_repaid - ?
            WHERE id = ?
        """, (amount, loan_id))

        # Delete the applied transaction
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
