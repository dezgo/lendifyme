"""
Transaction matching routes - CSV/API import, matching, review, apply/reject.
"""
from flask import Blueprint, render_template, request, session, redirect, flash, current_app as app
from helpers.decorators import login_required, get_current_user_id
from helpers.db import get_db_connection
from helpers.utils import get_db_path
from services.loans import has_feature, get_user_subscription_tier
from services.transaction_matcher import match_transactions_to_loans
from services.connectors.registry import ConnectorRegistry
from services.connectors.csv_connector import CSVConnector
from datetime import datetime, timedelta
import json
import hashlib
import secrets


# Helper function to log events
def log_event(event_name, event_data=None, user_id=None):
    """Log an event to the events table."""
    if user_id is None:
        user_id = get_current_user_id()

    conn = get_db_connection()
    c = conn.cursor()

    event_data_json = json.dumps(event_data) if event_data else '{}'

    c.execute("""
        INSERT INTO events (user_id, event_name, event_data, created_at)
        VALUES (?, ?, ?, datetime('now'))
    """, (user_id, event_name, event_data_json))

    conn.commit()
    conn.close()


def is_email_verified():
    """Check if current user has verified their email."""
    user_id = get_current_user_id()
    if not user_id:
        return False

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email_verified FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result and result[0] == 1


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


# Create blueprint
matching_bp = Blueprint('matching', __name__, url_prefix='/match')


def get_user_connected_bank():
    """Get user's connected bank info (from simplified bank connection system)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT connected_bank, basiq_user_id, bank_credentials_encrypted
        FROM users
        WHERE id = ?
    """, (get_current_user_id(),))
    result = c.fetchone()
    conn.close()

    if result and result[0]:
        return {
            'bank_id': result[0],
            'basiq_user_id': result[1],
            'credentials_encrypted': result[2]
        }
    return None


@matching_bp.route("", methods=["GET", "POST"])
@login_required
def match_transactions():
    # Require email verification for transaction matching
    if not is_email_verified():
        flash("Please verify your email to use transaction matching. Check your inbox for the verification link.", "error")
        return redirect("/")

    if request.method == "POST":
        import_source = request.form.get("import_source", "csv")
        connector = None
        transactions = []

        # Check if using the simplified connected bank system
        if import_source == "connected_bank":
            connected_bank = get_user_connected_bank()

            if not connected_bank:
                flash("No bank connected. Please connect your bank first.", "error")
                return redirect("/connect-bank")

            # Check if trying to use bank API without access
            if not has_feature(get_current_user_id(), 'bank_api'):
                flash("Bank API connections are only available on the Pro plan. Upgrade to access this feature!", "error")
                return redirect("/pricing")

            try:
                bank_id = connected_bank['bank_id']
                basiq_user_id = connected_bank.get('basiq_user_id')
                credentials_encrypted = connected_bank.get('credentials_encrypted')

                # For API key banks (like Up Bank), decrypt credentials
                if credentials_encrypted:
                    from services.encryption import decrypt_credentials
                    import os
                    encryption_key = os.getenv('ENCRYPTION_KEY')
                    creds = decrypt_credentials(credentials_encrypted, encryption_key)
                    connector = ConnectorRegistry.create_connector(bank_id, api_key=creds['api_key'])
                # For OAuth banks, use Basiq user ID
                elif basiq_user_id:
                    connector = ConnectorRegistry.create_from_env(bank_id, basiq_user_id=basiq_user_id)
                else:
                    flash("Bank connection misconfigured", "error")
                    return redirect("/connect-bank")

                if not connector:
                    flash("Failed to create bank connector", "error")
                    return redirect("/connect-bank")

                # Get transactions
                since_date = request.form.get("since_date")
                if not since_date:
                    # Default to last 30 days
                    from datetime import datetime, timedelta
                    since_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')

                all_transactions = connector.get_incoming_transactions(since_date=since_date)
                transactions = all_transactions

            except Exception as e:
                flash(f"Error fetching transactions: {str(e)}", "error")
                return redirect("/match")

        # Check if trying to use bank API without access (for old bank_connections system)
        elif import_source != "csv" and not has_feature(get_current_user_id(), 'bank_api'):
            flash("Bank API connections are only available on the Pro plan. Upgrade to access this feature!", "error")
            return redirect("/pricing")

        try:
            if import_source == "csv":
                # CSV Upload
                csv_content = request.form.get("transactions_csv")
                if not csv_content:
                    flash("Please provide CSV data", "error")
                    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
                    return render_template("match_upload.html", user_connections=user_connections)

                connector = CSVConnector(csv_content=csv_content)
                transactions = connector.get_transactions()
                all_transactions = transactions  # For CSV, all and filtered transactions are the same

            else:
                # Bank Connection - import_source is the connection_id
                try:
                    connection_id = int(import_source)
                except ValueError:
                    flash("Invalid bank connection", "error")
                    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
                    return render_template("match_upload.html", user_connections=user_connections)

                # Get user password from session (required for decryption)
                user_password = session.get('user_password')
                if not user_password:
                    flash("Please log in with your password to sync bank transactions.", "error")
                    return redirect("/login")

                connector = ConnectorRegistry.create_from_connection(
                    get_db_path(),
                    connection_id,
                    get_current_user_id(),
                    user_password
                )

                if not connector:
                    flash(f"Unable to connect to your bank. Please check your connection settings or log in with your password.", "error")
                    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
                    return render_template("match_upload.html", user_connections=user_connections)

                # Test connection first
                if not connector.test_connection():
                    flash(f"Unable to connect to {connector.connector_name}. Please try again or check your connection settings.", "error")
                    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
                    return render_template("match_upload.html", user_connections=user_connections)

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
            conn = get_db_connection()
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
            for match in matches:
                # Create unique ID from transaction details + loan ID
                match_str = f"{match['transaction']['date']}-{match['transaction']['description']}-{match['transaction']['amount']}-{match['loan']['id']}"
                match['match_id'] = hashlib.md5(match_str.encode()).hexdigest()[:16]

            # Only store context transactions (within ±7 days of any match) to avoid session size limits
            context_transactions = []
            if matches:
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
            session_key = secrets.token_urlsafe(16)
            expires_at = (datetime.now() + timedelta(hours=24)).isoformat()

            conn = get_db_connection()
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
            user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
            return render_template("match_upload.html", user_connections=user_connections)
        except ValueError as e:
            flash(f"Authentication error: {str(e)}", "error")
            user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
            return render_template("match_upload.html", user_connections=user_connections)
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
            user_connections = ConnectorRegistry.get_user_connections(get_db_path(), get_current_user_id())
            return render_template("match_upload.html", user_connections=user_connections)

    # GET request - show upload form
    user_id = get_current_user_id()
    has_bank_api_access = has_feature(user_id, 'bank_api')
    user_connections = ConnectorRegistry.get_user_connections(get_db_path(), user_id) if has_bank_api_access else []
    tier = get_user_subscription_tier(user_id)

    # Get user's connected bank (from simplified system)
    connected_bank = get_user_connected_bank()
    connected_bank_name = None
    if connected_bank:
        try:
            connector_class = ConnectorRegistry.get_connector_class(connected_bank['bank_id'])
            if connector_class:
                # Get credential schema to determine instantiation method
                schema = connector_class.get_credential_schema()
                if schema.get('auth_type') == 'oauth':
                    # OAuth banks need basiq_user_id parameter
                    instance = connector_class(api_key="dummy", basiq_user_id=None)
                else:
                    # API key banks just need api_key
                    instance = connector_class(api_key="dummy")
                connected_bank_name = instance.connector_name
        except Exception as e:
            from flask import current_app as app
            app.logger.error(f"Failed to get connected bank name: {e}")
            pass

    return render_template("match_upload.html",
                         user_connections=user_connections,
                         has_bank_api=has_bank_api_access,
                         current_tier=tier,
                         connected_bank=connected_bank,
                         connected_bank_name=connected_bank_name)


@matching_bp.route("/review")
@login_required
def review_matches():
    """Show pending matches for review."""
    session_key = session.get('pending_matches_key')

    if not session_key:
        flash("No pending matches. Import transactions first.", "error")
        return redirect("/match")

    # Load directly from database (no session caching to avoid cookie size limits)
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


# Apply/reject match routes are at app-level (not /match prefix) for backward compatibility
# They will be registered separately in app.py

def apply_match_handler():
    """Apply a pending match from review."""
    match_id = request.form.get("match_id")
    session_key = session.get('pending_matches_key')

    if match_id and session_key:
        conn = get_db_connection()
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
                           COALESCE(SUM(at.amount), 0) as current_repaid, l.loan_type, l.borrower_notifications_enabled
                    FROM loans l
                    LEFT JOIN applied_transactions at ON l.id = at.loan_id
                    WHERE l.id = ? AND l.user_id = ?
                    GROUP BY l.id
                """, (loan_id, get_current_user_id()))
                loan_details = c.fetchone()

                if loan_details:
                    loan_id_db, borrower_name, borrower_email, access_token, loan_amount, current_repaid, loan_type, notifications_enabled = loan_details

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

                    # Log analytics event
                    log_event('transaction_matched', event_data={'loan_id': loan_id, 'amount': amount_to_store})

                    # Send email notification if borrower has email, access token, notifications enabled, AND lender has email feature
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
                    return ('', 204)  # Success, no content

        conn.close()

    return ('', 400)  # Bad request


def reject_match_handler():
    """Reject a pending match from review."""
    match_id = request.form.get("match_id")
    session_key = session.get('pending_matches_key')

    if match_id and session_key:
        conn = get_db_connection()
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


# Sync banks route - registered separately in app.py at /sync-banks
def sync_banks_handler():
    """Manually trigger bank sync."""
    user_password = session.get('user_password')
    if not user_password:
        flash("Please log in with your password to sync bank transactions.", "error")
        return redirect("/login")

    try:
        from services.auto_sync import sync_all_bank_connections
        sync_results = sync_all_bank_connections(get_db_path(), get_current_user_id(), user_password)

        # Store results in session for dashboard display
        session['sync_results'] = {
            'auto_applied_count': len(sync_results['auto_applied']),
            'pending_review_count': len(sync_results['pending_review']),
            'connections_synced': sync_results['connections_synced'],
            'total_transactions_fetched': sync_results['total_transactions_fetched'],
            'new_transactions_found': sync_results['new_transactions_found'],
            'already_applied_count': sync_results['already_applied_count'],
            'connection_details': sync_results['connection_details'],
            'errors': sync_results['errors'],
            'timestamp': datetime.now().isoformat()
        }

        # Store pending matches for review page
        if sync_results['pending_review']:
            session['pending_matches'] = [
                {
                    'transaction': t,  # Already a dict
                    'loan': l,
                    'confidence': c
                }
                for t, l, c in sync_results['pending_review']
            ]

        if sync_results['new_transactions_found'] > 0:
            flash(f"Sync complete! Found {sync_results['new_transactions_found']} new transaction(s).", "success")
        else:
            flash("Sync complete. No new transactions found.", "info")

        if sync_results['errors']:
            for error in sync_results['errors']:
                flash(error, "error")

    except Exception as e:
        app.logger.error(f"Manual sync failed: {str(e)}")
        flash(f"Sync failed: {str(e)}", "error")

    return redirect("/")


@matching_bp.route("/review-pending")
@login_required
def review_pending_auto_matches():
    """Review pending matches from auto-sync."""
    pending_matches = session.get('pending_matches', [])

    if not pending_matches:
        flash("No pending matches to review.", "info")
        return redirect("/")

    return render_template("match_review_pending.html", matches=pending_matches)


@matching_bp.route("/apply-pending", methods=["POST"])
@login_required
def apply_pending_match():
    """Apply a pending match from auto-sync."""
    match_index = int(request.form.get("match_index", -1))
    pending_matches = session.get('pending_matches', [])

    if match_index < 0 or match_index >= len(pending_matches):
        flash("Invalid match.", "error")
        return redirect("/match/review-pending")

    match = pending_matches[match_index]
    transaction = match['transaction']
    loan = match['loan']
    confidence = match['confidence']

    # Apply the match
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        INSERT INTO applied_transactions
        (date, description, amount, loan_id, auto_applied, confidence_score)
        VALUES (?, ?, ?, ?, 0, ?)
    """, (transaction['date'], transaction['description'], transaction['amount'],
          loan['id'], confidence))

    conn.commit()
    conn.close()

    # Remove from pending list
    pending_matches.pop(match_index)
    session['pending_matches'] = pending_matches

    flash(f"Applied ${transaction['amount']:.2f} payment to {loan['borrower']}'s loan.", "success")

    if pending_matches:
        return redirect("/match/review-pending")
    else:
        return redirect("/")


@matching_bp.route("/reject-pending", methods=["POST"])
@login_required
def reject_pending_match():
    """Reject a pending match from auto-sync."""
    match_index = int(request.form.get("match_index", -1))
    pending_matches = session.get('pending_matches', [])

    if match_index < 0 or match_index >= len(pending_matches):
        flash("Invalid match.", "error")
        return redirect("/match/review-pending")

    match = pending_matches[match_index]
    transaction = match['transaction']
    loan = match['loan']

    # Record rejection
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        INSERT INTO rejected_matches (date, description, amount, loan_id)
        VALUES (?, ?, ?, ?)
    """, (transaction['date'], transaction['description'], transaction['amount'], loan['id']))

    conn.commit()
    conn.close()

    # Remove from pending list
    pending_matches.pop(match_index)
    session['pending_matches'] = pending_matches

    flash("Match rejected.", "info")

    if pending_matches:
        return redirect("/match/review-pending")
    else:
        return redirect("/")


@matching_bp.route("/undo/<int:transaction_id>", methods=["POST"])
@login_required
def undo_auto_match(transaction_id):
    """Undo an auto-applied match."""
    conn = get_db_connection()
    c = conn.cursor()

    # Verify ownership and that it was auto-applied
    c.execute("""
        SELECT at.id, at.loan_id, at.amount, l.user_id
        FROM applied_transactions at
        JOIN loans l ON l.id = at.loan_id
        WHERE at.id = ? AND at.auto_applied = 1
    """, (transaction_id,))

    result = c.fetchone()

    if not result:
        flash("Transaction not found or not eligible for undo.", "error")
        conn.close()
        return redirect("/")

    trans_id, loan_id, amount, owner_id = result

    if owner_id != get_current_user_id():
        flash("Unauthorized", "error")
        conn.close()
        return redirect("/")

    # Delete the applied transaction
    c.execute("DELETE FROM applied_transactions WHERE id = ?", (transaction_id,))
    conn.commit()
    conn.close()

    log_event('auto_match_undone', event_data={'transaction_id': transaction_id, 'loan_id': loan_id})

    flash(f"Undid auto-applied payment of ${amount:.2f}. The transaction can be re-matched if needed.", "success")
    return redirect("/")
