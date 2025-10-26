import pytest
from services.transaction_matcher import (
    parse_csv_transactions,
    calculate_similarity,
    match_transactions_to_loans
)


class TestParseCSVTransactions:
    """Test CSV transaction parsing."""

    def test_parse_standard_format(self):
        """Test parsing with standard column names."""
        csv_content = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00
2025-10-20,Payment Bob,25.50"""

        transactions = parse_csv_transactions(csv_content)

        assert len(transactions) == 2
        assert transactions[0]['date'] == '2025-10-15'
        assert transactions[0]['description'] == 'Transfer from Alice'
        assert transactions[0]['amount'] == 50.00
        assert transactions[1]['amount'] == 25.50

    def test_parse_lowercase_columns(self):
        """Test parsing with lowercase column names."""
        csv_content = """date,description,amount
2025-10-15,Payment from Alice,100.00"""

        transactions = parse_csv_transactions(csv_content)

        assert len(transactions) == 1
        assert transactions[0]['amount'] == 100.00

    def test_parse_alternative_column_names(self):
        """Test parsing with alternative column names (DESC, Memo)."""
        csv_content = """Date,DESC,Amount
2025-10-15,Transfer Alice,75.00"""

        transactions = parse_csv_transactions(csv_content)

        assert len(transactions) == 1
        assert transactions[0]['description'] == 'Transfer Alice'

    def test_parse_with_currency_symbols(self):
        """Test parsing amounts with currency symbols."""
        csv_content = """Date,Description,Amount
2025-10-15,Payment Alice,$50.00
2025-10-20,Transfer Bob,$125.50"""

        transactions = parse_csv_transactions(csv_content)

        assert len(transactions) == 2
        assert transactions[0]['amount'] == 50.00
        assert transactions[1]['amount'] == 125.50

    def test_parse_with_commas_in_amounts(self):
        """Test parsing amounts with comma separators."""
        csv_content = """Date,Description,Amount
2025-10-15,Large payment,$1,250.00"""

        transactions = parse_csv_transactions(csv_content)

        assert len(transactions) == 1
        assert transactions[0]['amount'] == 1250.00

    def test_ignore_negative_amounts(self):
        """Test that negative amounts (outgoing payments) are ignored."""
        csv_content = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00
2025-10-16,Payment to Store,-25.00
2025-10-17,Transfer from Bob,100.00"""

        transactions = parse_csv_transactions(csv_content)

        assert len(transactions) == 2
        assert all(t['amount'] > 0 for t in transactions)

    def test_ignore_invalid_rows(self):
        """Test that invalid rows are skipped."""
        csv_content = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00
2025-10-16,Invalid row,not_a_number
2025-10-17,Transfer from Bob,100.00"""

        transactions = parse_csv_transactions(csv_content)

        assert len(transactions) == 2

    def test_empty_csv(self):
        """Test parsing empty CSV."""
        csv_content = """Date,Description,Amount"""

        transactions = parse_csv_transactions(csv_content)

        assert len(transactions) == 0


class TestCalculateSimilarity:
    """Test string similarity calculation."""

    def test_identical_strings(self):
        """Test similarity of identical strings."""
        similarity = calculate_similarity("Alice", "Alice")
        assert similarity == 1.0

    def test_case_insensitive(self):
        """Test that comparison is case-insensitive."""
        similarity = calculate_similarity("Alice", "alice")
        assert similarity == 1.0

    def test_partial_match(self):
        """Test partial string matching."""
        similarity = calculate_similarity("Alice", "Alice Smith")
        assert similarity > 0.5

    def test_no_match(self):
        """Test completely different strings."""
        similarity = calculate_similarity("Alice", "Bob")
        assert similarity < 0.3

    def test_substring_match(self):
        """Test substring matching."""
        similarity = calculate_similarity("Bob", "Payment from Bob Johnson")
        assert similarity > 0.3


class TestMatchTransactionsToLoans:
    """Test transaction to loan matching logic."""

    def test_exact_name_and_amount_match(self):
        """Test matching with exact name and amount."""
        transactions = [{
            'date': '2025-10-15',
            'description': 'Transfer from Alice',
            'amount': 100.00
        }]

        loans = [{
            'id': 1,
            'borrower': 'Alice',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 0,
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        assert len(matches) == 1
        assert matches[0]['confidence'] >= 70
        assert matches[0]['loan']['id'] == 1

    def test_partial_payment_match(self):
        """Test matching partial payment."""
        transactions = [{
            'date': '2025-10-15',
            'description': 'Payment from Alice Smith',
            'amount': 50.00
        }]

        loans = [{
            'id': 1,
            'borrower': 'Alice',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 0,
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        assert len(matches) == 1
        assert matches[0]['transaction']['amount'] == 50.00

    def test_round_number_payment(self):
        """Test that round number payments get bonus confidence."""
        transactions = [{
            'date': '2025-10-15',
            'description': 'Transfer from Alice',
            'amount': 50.00  # Round number
        }]

        loans = [{
            'id': 1,
            'borrower': 'Alice',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 0,
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        assert len(matches) == 1
        # Should have higher confidence due to round number
        assert any('Round number' in reason for reason in matches[0]['reasons'])

    def test_ignore_fully_paid_loans(self):
        """Test that fully paid loans are not matched."""
        transactions = [{
            'date': '2025-10-15',
            'description': 'Transfer from Alice',
            'amount': 50.00
        }]

        loans = [{
            'id': 1,
            'borrower': 'Alice',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 100.00,  # Fully paid
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        assert len(matches) == 0

    def test_transaction_before_loan_date(self):
        """Test that transactions before loan date have reduced confidence."""
        transactions = [{
            'date': '2025-09-15',  # Before loan
            'description': 'Transfer from Alice',
            'amount': 100.00
        }]

        loans = [{
            'id': 1,
            'borrower': 'Alice',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 0,
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        # Should either have no matches or very low confidence
        assert len(matches) == 0 or matches[0]['confidence'] < 30

    def test_multiple_loans_same_borrower(self):
        """Test matching when same borrower has multiple loans."""
        transactions = [{
            'date': '2025-10-15',
            'description': 'Transfer from Alice',
            'amount': 50.00
        }]

        loans = [
            {
                'id': 1,
                'borrower': 'Alice',
                'amount': 50.00,
                'date_borrowed': '2025-10-01',
                'amount_repaid': 0,
                'note': ''
            },
            {
                'id': 2,
                'borrower': 'Alice',
                'amount': 100.00,
                'date_borrowed': '2025-10-05',
                'amount_repaid': 0,
                'note': ''
            }
        ]

        matches = match_transactions_to_loans(transactions, loans)

        # Should match both loans, but first one should have higher confidence (exact amount)
        assert len(matches) >= 1
        # The exact amount match should be ranked higher
        if len(matches) > 1:
            assert matches[0]['confidence'] > matches[1]['confidence']

    def test_no_matches_below_confidence_threshold(self):
        """Test that low confidence matches are filtered out."""
        transactions = [{
            'date': '2025-10-15',
            'description': 'Coffee shop payment',  # Unrelated description
            'amount': 5.00
        }]

        loans = [{
            'id': 1,
            'borrower': 'Alice',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 0,
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        # Should have no matches due to low confidence
        assert len(matches) == 0

    def test_match_with_full_name_in_description(self):
        """Test matching with full name in transaction description."""
        transactions = [{
            'date': '2025-10-15',
            'description': 'Zelle from Alice Smith - thanks!',
            'amount': 50.00
        }]

        loans = [{
            'id': 1,
            'borrower': 'Alice Smith',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 0,
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        assert len(matches) == 1
        assert matches[0]['confidence'] >= 40

    def test_matches_sorted_by_confidence(self):
        """Test that matches are sorted by confidence (highest first)."""
        transactions = [
            {
                'date': '2025-10-15',
                'description': 'Transfer from Alice',  # High confidence
                'amount': 100.00
            },
            {
                'date': '2025-10-16',
                'description': 'Payment',  # Low confidence
                'amount': 50.00
            }
        ]

        loans = [{
            'id': 1,
            'borrower': 'Alice',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 0,
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        # First match should have higher confidence than second
        if len(matches) > 1:
            for i in range(len(matches) - 1):
                assert matches[i]['confidence'] >= matches[i + 1]['confidence']

    def test_remaining_balance_calculation(self):
        """Test that remaining balance is calculated correctly."""
        transactions = [{
            'date': '2025-10-15',
            'description': 'Transfer from Alice',
            'amount': 30.00
        }]

        loans = [{
            'id': 1,
            'borrower': 'Alice',
            'amount': 100.00,
            'date_borrowed': '2025-10-01',
            'amount_repaid': 70.00,  # $30 remaining
            'note': ''
        }]

        matches = match_transactions_to_loans(transactions, loans)

        assert len(matches) == 1
        # Should recognize exact match to remaining balance
        remaining = loans[0]['amount'] - loans[0]['amount_repaid']
        assert remaining == 30.00
        assert any('Exact amount match' in reason for reason in matches[0]['reasons'])
