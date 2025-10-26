#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Debug script to investigate why transactions aren't matching.
Usage: python debug_transactions.py [--since-date YYYY-MM-DD]
"""

import sqlite3
import sys
import io
from datetime import datetime, timedelta
from dotenv import load_dotenv
from services.connectors.registry import ConnectorRegistry
from services.transaction_matcher import match_transactions_to_loans

# Fix Windows console encoding issues
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

load_dotenv()

def check_database(borrower_name=None, date=None):
    """Check if transactions are in applied_transactions or rejected_matches."""
    conn = sqlite3.connect('lendifyme.db')
    c = conn.cursor()

    print("\n=== APPLIED TRANSACTIONS ===")
    if date:
        c.execute("SELECT * FROM applied_transactions WHERE date LIKE ?", (f'%{date}%',))
    else:
        c.execute("SELECT * FROM applied_transactions ORDER BY date DESC LIMIT 20")

    rows = c.fetchall()
    if rows:
        for row in rows:
            print(f"  {row[1]} | {row[2]} | ${row[3]:.2f} | Loan {row[4]} | Applied: {row[5]}")
    else:
        print("  No applied transactions found")

    print("\n=== REJECTED MATCHES ===")
    if date:
        c.execute("SELECT * FROM rejected_matches WHERE date LIKE ?", (f'%{date}%',))
    else:
        c.execute("SELECT * FROM rejected_matches ORDER BY date DESC LIMIT 20")

    rows = c.fetchall()
    if rows:
        for row in rows:
            print(f"  {row[1]} | {row[2]} | ${row[3]:.2f} | Loan {row[4]} | Rejected: {row[5]}")
    else:
        print("  No rejected matches found")

    conn.close()


def fetch_and_analyze(since_date):
    """Fetch transactions from Up Bank and show matching analysis."""

    # Get connector
    connector = ConnectorRegistry.create_from_env('up_bank')
    if not connector:
        print("ERROR: Up Bank API credentials not found in .env")
        sys.exit(1)

    if not connector.test_connection():
        print("ERROR: Failed to connect to Up Bank API")
        sys.exit(1)

    print(f"\n=== FETCHING TRANSACTIONS (since {since_date}) ===")
    print("Fetching from Up Bank API in 3-month chunks (this may take a moment for large date ranges)...")
    print("This works around API pagination limits by breaking into smaller date ranges.")
    all_transactions = connector.get_transactions(since_date=since_date)
    incoming = connector.filter_incoming_only(all_transactions)

    print(f"Total transactions fetched: {len(all_transactions)}")
    print(f"Incoming transactions: {len(incoming)}")

    if incoming:
        earliest = min(t.date for t in incoming)
        latest = max(t.date for t in incoming)
        print(f"Date range: {earliest} to {latest}")

    # Show all incoming transactions
    print("\n=== ALL INCOMING TRANSACTIONS ===")
    for t in incoming:
        print(f"  {t.date} | {t.description[:50]:<50} | ${t.amount:>8.2f}")

    # Get loans
    conn = sqlite3.connect('lendifyme.db')
    c = conn.cursor()
    c.execute("""
        SELECT id, borrower, amount, note, date_borrowed, amount_repaid,
               repayment_amount, repayment_frequency, bank_name
        FROM loans
    """)
    loan_rows = c.fetchall()
    conn.close()

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

    print(f"\n=== LOANS ===")
    for loan in loans:
        bank_display = f" (Bank: {loan['bank_name']})" if loan['bank_name'] else ""
        print(f"  #{loan['id']} {loan['borrower']}{bank_display} | ${loan['amount']:.2f} | Repaid: ${loan['amount_repaid']:.2f}")

    # Match transactions
    transaction_dicts = [t.to_dict() for t in incoming]
    matches = match_transactions_to_loans(transaction_dicts, loans)

    print(f"\n=== MATCHES FOUND ({len(matches)}) ===")
    for match in matches:
        print(f"\n  Transaction: {match['transaction']['date']} | {match['transaction']['description'][:40]} | ${match['transaction']['amount']:.2f}")
        print(f"  Loan: #{match['loan']['id']} {match['loan']['borrower']}")
        print(f"  Confidence: {match['confidence']:.0f}%")
        print(f"  Reasons:")
        for reason in match['reasons']:
            print(f"    - {reason}")

    # Show transactions that didn't match
    matched_transactions = set((m['transaction']['date'], m['transaction']['description']) for m in matches)
    unmatched = [t for t in incoming if (t.date, t.description) not in matched_transactions]

    if unmatched:
        print(f"\n=== UNMATCHED TRANSACTIONS ({len(unmatched)}) ===")
        for t in unmatched:
            print(f"  {t.date} | {t.description[:50]:<50} | ${t.amount:>8.2f}")


if __name__ == "__main__":
    # Parse arguments
    since_date = None
    check_date = None

    if len(sys.argv) > 1:
        if sys.argv[1] == '--since-date' and len(sys.argv) > 2:
            since_date = sys.argv[2]
        else:
            since_date = sys.argv[1]

    if not since_date:
        # Default to 90 days ago
        since = datetime.now() - timedelta(days=600)
        since_date = since.strftime("%Y-%m-%d")

    print(f"LendifyMe Transaction Debugger")
    print(f"=" * 60)

    # Check database first
    check_database(date="2024-10-16")

    # Fetch and analyze
    fetch_and_analyze(since_date)
