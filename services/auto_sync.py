# services/auto_sync.py
"""
Auto-sync service for automatically fetching and matching bank transactions.

When users log in, this service:
1. Fetches new transactions from all connected banks
2. Runs matching algorithm against unpaid/partially-paid loans
3. Auto-applies high-confidence matches (≥80%)
4. Flags medium-confidence matches (50-79%) for review
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Dict
from services.connectors.registry import ConnectorRegistry
from services.transaction_matcher import match_transactions_to_loans
from services.loans import get_loan_dek
from services.encryption import decrypt_field
from helpers.db import get_db_connection


def sync_all_bank_connections(db_path: str, user_id: int, user_password: str) -> Dict:
    """
    Sync all bank connections for a user and auto-match transactions.

    Args:
        db_path: Path to database
        user_id: User ID
        user_password: User's password for decryption

    Returns:
        Dict with sync results:
        {
            'auto_applied': [(transaction, loan, confidence), ...],
            'pending_review': [(transaction, loan, confidence), ...],
            'errors': ['Error message', ...]
        }
    """
    results = {
        'auto_applied': [],
        'pending_review': [],
        'errors': [],
        'connections_synced': 0,
        'total_transactions_fetched': 0,
        'new_transactions_found': 0,
        'already_applied_count': 0,
        'connection_details': []
    }

    # Get all active bank connections
    connections = ConnectorRegistry.get_user_connections(db_path, user_id)

    if not connections:
        return results

    conn = get_db_connection()

    for connection in connections:
        try:
            # Create connector instance
            connector = ConnectorRegistry.create_from_connection(
                db_path,
                connection['id'],
                user_id,
                user_password
            )

            if not connector:
                results['errors'].append(f"Could not connect to {connection['display_name']}")
                continue

            # Determine date range
            since_date = connection['last_synced_at']
            if not since_date:
                # First sync - go back to earliest unpaid loan date
                c = conn.cursor()
                c.execute("""
                    SELECT MIN(date_borrowed) FROM loans
                    WHERE user_id = ? AND loan_type = 'lending'
                    AND (SELECT COALESCE(SUM(amount), 0) FROM applied_transactions WHERE loan_id = loans.id) < amount
                """, (user_id,))
                earliest_loan = c.fetchone()[0]

                if earliest_loan:
                    since_date = earliest_loan
                else:
                    # No unpaid loans, just check last 30 days
                    since_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            else:
                # Parse the datetime and get just the date
                since_date = since_date.split('T')[0] if 'T' in since_date else since_date.split(' ')[0]

            # Fetch transactions (no limit - connector will paginate as needed)
            all_transactions = connector.get_transactions(since_date=since_date)
            results['total_transactions_fetched'] += len(all_transactions)

            # Filter to incoming transactions only (positive amounts)
            incoming_transactions = [t for t in all_transactions if t.amount > 0]

            connection_detail = {
                'name': connection['display_name'],
                'transactions_fetched': len(all_transactions),
                'incoming_transactions': len(incoming_transactions),
                'date_range': since_date
            }
            results['connection_details'].append(connection_detail)

            if not incoming_transactions:
                # Update last_synced_at even if no transactions
                c = conn.cursor()
                c.execute("""
                    UPDATE bank_connections
                    SET last_synced_at = ?
                    WHERE id = ?
                """, (datetime.now().isoformat(), connection['id']))
                conn.commit()
                results['connections_synced'] += 1
                continue

            # Convert Transaction objects to dicts for matching
            transactions = [
                {
                    'date': t.date,
                    'description': t.description,
                    'amount': t.amount,
                    'raw_data': t.raw_data
                }
                for t in incoming_transactions
            ]

            # Get unpaid/partially-paid loans for this user
            # Query both plaintext AND encrypted columns to support encrypted loans
            c = conn.cursor()
            conn.row_factory = sqlite3.Row
            c.execute("""
                SELECT
                    id, borrower, borrower_encrypted, amount, amount_encrypted,
                    date_borrowed, repayment_amount, repayment_amount_encrypted,
                    repayment_frequency, bank_name, bank_name_encrypted, encrypted_dek,
                    (SELECT COALESCE(SUM(amount), 0)
                     FROM applied_transactions
                     WHERE loan_id = loans.id) as amount_repaid
                FROM loans
                WHERE user_id = ? AND loan_type = 'lending'
            """, (user_id,))

            loans = []
            for row in c.fetchall():
                # Get DEK for this loan using user's password
                dek = get_loan_dek(row['id'], user_password=user_password)

                # Decrypt fields if they're encrypted, otherwise use plaintext
                borrower = decrypt_field(row['borrower_encrypted'], dek) if row['borrower_encrypted'] and dek else row['borrower']
                amount_str = decrypt_field(row['amount_encrypted'], dek) if row['amount_encrypted'] and dek else row['amount']
                bank_name = decrypt_field(row['bank_name_encrypted'], dek) if row['bank_name_encrypted'] and dek else row['bank_name']
                repayment_amount_str = decrypt_field(row['repayment_amount_encrypted'], dek) if row['repayment_amount_encrypted'] and dek else row['repayment_amount']

                # Convert numeric strings to floats
                amount = float(amount_str) if amount_str is not None else 0.0
                repayment_amount = float(repayment_amount_str) if repayment_amount_str is not None else None

                remaining = amount - row['amount_repaid']
                if remaining > 0:  # Only include loans with remaining balance
                    loans.append({
                        'id': row['id'],
                        'borrower': borrower,
                        'amount': amount,
                        'date_borrowed': row['date_borrowed'],
                        'repayment_amount': repayment_amount,
                        'repayment_frequency': row['repayment_frequency'],
                        'bank_name': bank_name,
                        'amount_repaid': row['amount_repaid'],
                        'remaining': remaining
                    })

            if not loans:
                # Update last_synced_at even if no loans to match
                c.execute("""
                    UPDATE bank_connections
                    SET last_synced_at = ?
                    WHERE id = ?
                """, (datetime.now().isoformat(), connection['id']))
                conn.commit()
                results['connections_synced'] += 1
                continue

            # Match transactions to loans
            matches = match_transactions_to_loans(transactions, loans)

            # Filter out already applied and rejected transactions
            filtered_matches = []
            for match in matches:
                transaction = match['transaction']
                loan_id = match['loan']['id']
                confidence = match['confidence']

                # Check if already applied (to any loan)
                c.execute("""
                    SELECT id FROM applied_transactions
                    WHERE date = ? AND description = ? AND amount = ?
                """, (transaction['date'], transaction['description'], transaction['amount']))

                if c.fetchone():
                    results['already_applied_count'] += 1
                    continue  # Already applied

                # Check if rejected for this specific loan
                c.execute("""
                    SELECT id FROM rejected_matches
                    WHERE date = ? AND description = ? AND amount = ? AND loan_id = ?
                """, (transaction['date'], transaction['description'], transaction['amount'], loan_id))

                if c.fetchone():
                    continue  # Rejected for this loan

                filtered_matches.append(match)
                results['new_transactions_found'] += 1

            # Process filtered matches
            for match in filtered_matches:
                confidence = match['confidence']
                transaction = match['transaction']
                loan = match['loan']

                if confidence >= 80:
                    # Auto-apply high-confidence matches
                    try:
                        _apply_match(conn, transaction, loan, confidence, connection['id'], user_id)
                        results['auto_applied'].append((transaction, loan, confidence))
                    except Exception as e:
                        results['errors'].append(f"Failed to auto-apply match: {str(e)}")

                elif confidence >= 50:
                    # Flag for review
                    results['pending_review'].append((transaction, loan, confidence))

            # Update last_synced_at
            c.execute("""
                UPDATE bank_connections
                SET last_synced_at = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), connection['id']))
            conn.commit()
            results['connections_synced'] += 1

        except Exception as e:
            results['errors'].append(f"Error syncing {connection.get('display_name', 'connection')}: {str(e)}")

    conn.close()
    return results


def _apply_match(conn: sqlite3.Connection, transaction: Dict, loan: Dict, confidence: float,
                 connection_id: int, user_id: int):
    """
    Apply a matched transaction to a loan.

    Args:
        conn: Database connection
        transaction: Transaction dict
        loan: Loan dict
        confidence: Match confidence score
        connection_id: Bank connection ID
        user_id: User ID for logging
    """
    c = conn.cursor()

    # Record in applied_transactions
    c.execute("""
        INSERT INTO applied_transactions
        (date, description, amount, loan_id, auto_applied, confidence_score, connection_id)
        VALUES (?, ?, ?, ?, 1, ?, ?)
    """, (transaction['date'], transaction['description'], transaction['amount'],
          loan['id'], confidence, connection_id))

    conn.commit()

    # Log event
    try:
        from app import log_event
        log_event('auto_match_applied', user_id=user_id, event_data={
            'loan_id': loan['id'],
            'amount': transaction['amount'],
            'confidence': confidence
        })
    except:
        pass  # Don't fail if logging fails
