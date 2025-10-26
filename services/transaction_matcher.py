# services/transaction_matcher.py
import csv
import io
from datetime import datetime
from difflib import SequenceMatcher


def parse_csv_transactions(csv_content):
    """
    Parse CSV bank transactions. Expects columns: Date, Description, Amount
    Returns list of transaction dicts.
    """
    transactions = []
    reader = csv.DictReader(io.StringIO(csv_content))

    for row in reader:
        try:
            # Normalize column names (handle different banks)
            date = row.get('Date') or row.get('date') or row.get('DATE')
            description = row.get('Description') or row.get('description') or row.get('DESC') or row.get('Memo')
            amount = row.get('Amount') or row.get('amount') or row.get('AMOUNT')

            if date and description and amount:
                # Parse amount (handle negative values, currency symbols)
                amount_clean = amount.replace('$', '').replace(',', '').strip()
                amount_float = float(amount_clean)

                # Only consider positive amounts (incoming payments)
                if amount_float > 0:
                    transactions.append({
                        'date': date,
                        'description': description.strip(),
                        'amount': amount_float
                    })
        except (ValueError, AttributeError):
            continue

    return transactions


def calculate_similarity(text1, text2):
    """Calculate similarity between two strings (0-1 scale)."""
    return SequenceMatcher(None, text1.lower(), text2.lower()).ratio()


def match_transactions_to_loans(transactions, loans):
    """
    Match bank transactions to loans.
    Returns list of suggested matches with confidence scores.

    Match format: {
        'transaction': {...},
        'loan': {...},
        'confidence': float,
        'reasons': [str]
    }
    """
    matches = []

    for transaction in transactions:
        for loan in loans:
            # Skip if loan is fully paid
            remaining = loan['amount'] - loan['amount_repaid']
            if remaining <= 0:
                continue

            confidence = 0
            reasons = []

            # 1. Check if borrower name appears in transaction description
            # Use bank_name if available, otherwise use borrower name
            name_to_match = loan.get('bank_name') or loan['borrower']
            name_similarity = calculate_similarity(name_to_match, transaction['description'])
            if name_similarity > 0.6:
                confidence += 40 * name_similarity
                reasons.append(f"Name match ({int(name_similarity * 100)}%)")

            # 2. Check if amount matches exactly
            if abs(transaction['amount'] - remaining) < 0.01:
                confidence += 40
                reasons.append("Exact amount match (full remaining balance)")
            elif abs(transaction['amount'] - loan['amount']) < 0.01:
                confidence += 35
                reasons.append("Exact amount match (original loan amount)")
            elif loan.get('repayment_amount') and abs(transaction['amount'] - loan['repayment_amount']) < 0.01:
                # Matches scheduled repayment amount
                confidence += 45
                frequency = loan.get('repayment_frequency', '')
                reasons.append(f"Matches {frequency} repayment schedule (${loan['repayment_amount']:.2f})")
            elif transaction['amount'] < remaining and transaction['amount'] > 0:
                # Partial payment - check if it's a round number
                if transaction['amount'] % 10 == 0 or transaction['amount'] % 5 == 0:
                    confidence += 20
                    reasons.append("Round number partial payment")
                else:
                    confidence += 10
                    reasons.append("Partial payment")

            # 3. Check date is after loan was borrowed
            try:
                trans_date = datetime.strptime(transaction['date'], '%Y-%m-%d')
                loan_date = datetime.strptime(loan['date_borrowed'], '%Y-%m-%d')
                if trans_date >= loan_date:
                    confidence += 10
                    reasons.append("Date after loan")
                else:
                    # Transaction before loan - very unlikely to be a match
                    confidence -= 50
            except ValueError:
                pass

            # Only include matches with reasonable confidence
            if confidence >= 30:
                matches.append({
                    'transaction': transaction,
                    'loan': loan,
                    'confidence': min(confidence, 100),  # Cap at 100
                    'reasons': reasons
                })

    # Sort by confidence (highest first)
    matches.sort(key=lambda x: x['confidence'], reverse=True)

    return matches
