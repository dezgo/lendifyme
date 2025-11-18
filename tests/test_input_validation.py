"""
Comprehensive input validation tests to catch errors from user input.

These tests verify that the application handles invalid, malformed, or malicious
user input gracefully without raising unhandled exceptions.
"""
import pytest
import sqlite3
from helpers.db import get_db_connection


class TestLoanCreationInputValidation:
    """Test input validation for loan creation."""

    def test_create_loan_with_empty_amount(self, logged_in_client):
        """Test that empty amount field is handled gracefully."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': '',  # Empty amount
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200
        # Should not crash - either redirect or show error

    def test_create_loan_with_non_numeric_amount(self, logged_in_client):
        """Test that non-numeric amount is handled gracefully."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': 'abc',  # Non-numeric
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200
        # Should not crash with ValueError

    def test_create_loan_with_amount_containing_currency_symbol(self, logged_in_client):
        """Test that amount with currency symbols is handled."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': '$100.00',  # Contains dollar sign
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_create_loan_with_amount_containing_commas(self, logged_in_client):
        """Test that amount with thousand separators is handled."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': '1,000.00',  # Contains commas
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_create_loan_with_negative_amount(self, logged_in_client):
        """Test that negative amounts are handled."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': '-100.00',  # Negative
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_create_loan_with_zero_amount(self, logged_in_client):
        """Test that zero amount is handled."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': '0',  # Zero
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_create_loan_with_extremely_large_amount(self, logged_in_client):
        """Test that extremely large amounts are handled."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': '999999999999999.99',  # Very large
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_create_loan_with_empty_borrower(self, logged_in_client):
        """Test that empty borrower name is handled."""
        response = logged_in_client.post('/', data={
            'borrower': '',  # Empty
            'amount': '100.00',
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_create_loan_with_invalid_date(self, logged_in_client):
        """Test that invalid dates are handled."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': '100.00',
            'date_borrowed': 'not-a-date',  # Invalid date
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_create_loan_with_xss_in_borrower_name(self, logged_in_client):
        """Test that XSS attempts in borrower name are handled."""
        response = logged_in_client.post('/', data={
            'borrower': '<script>alert("xss")</script>',
            'amount': '100.00',
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200
        # Check that script is not executed (escaped in HTML)
        assert b'<script>' not in response.data or b'&lt;script&gt;' in response.data

    def test_create_loan_with_sql_injection_in_borrower(self, logged_in_client):
        """Test that SQL injection attempts are handled."""
        response = logged_in_client.post('/', data={
            'borrower': "'; DROP TABLE loans;--",
            'amount': '100.00',
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

        # Verify loans table still exists
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM loans")
        count = c.fetchone()[0]
        conn.close()
        # Table should still exist (query didn't execute)
        assert count is not None

    def test_create_loan_with_extremely_long_text(self, logged_in_client):
        """Test that extremely long text fields are handled."""
        response = logged_in_client.post('/', data={
            'borrower': 'A' * 10000,  # 10,000 characters
            'amount': '100.00',
            'note': 'B' * 50000,  # 50,000 characters
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_create_loan_with_invalid_repayment_amount(self, logged_in_client):
        """Test that invalid repayment amounts are handled."""
        response = logged_in_client.post('/', data={
            'borrower': 'Alice',
            'amount': '100.00',
            'repayment_amount': 'abc',  # Non-numeric
            'repayment_frequency': 'weekly',
            'date_borrowed': '2025-10-25',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200


class TestLoanRepaymentInputValidation:
    """Test input validation for loan repayments."""

    @pytest.fixture
    def loan_id(self, logged_in_client, app):
        """Create a test loan and return its ID."""
        logged_in_client.post('/', data={
            'borrower': 'Bob',
            'amount': '100.00',
            'date_borrowed': '2025-10-20',
            'loan_type': 'lending'
        })

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM loans ORDER BY id DESC LIMIT 1")
        loan_id = c.fetchone()[0]
        conn.close()
        return loan_id

    def test_repay_with_empty_amount(self, logged_in_client, loan_id):
        """Test that empty repayment amount is handled."""
        response = logged_in_client.post(f'/repay/{loan_id}', data={
            'repayment_amount': ''  # Empty
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_repay_with_non_numeric_amount(self, logged_in_client, loan_id):
        """Test that non-numeric repayment amount is handled."""
        response = logged_in_client.post(f'/repay/{loan_id}', data={
            'repayment_amount': 'abc'  # Non-numeric
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_repay_with_negative_amount(self, logged_in_client, loan_id):
        """Test that negative repayment amount is handled."""
        response = logged_in_client.post(f'/repay/{loan_id}', data={
            'repayment_amount': '-50.00'  # Negative
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_repay_with_zero_amount(self, logged_in_client, loan_id):
        """Test that zero repayment amount is handled."""
        response = logged_in_client.post(f'/repay/{loan_id}', data={
            'repayment_amount': '0'  # Zero
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_repay_with_amount_exceeding_loan(self, logged_in_client, loan_id):
        """Test that overpayment is handled (not necessarily blocked)."""
        response = logged_in_client.post(f'/repay/{loan_id}', data={
            'repayment_amount': '500.00'  # More than loan amount
        }, follow_redirects=True)

        assert response.status_code == 200


class TestLoanEditInputValidation:
    """Test input validation for loan editing."""

    @pytest.fixture
    def loan_id(self, logged_in_client, app):
        """Create a test loan and return its ID."""
        logged_in_client.post('/', data={
            'borrower': 'Charlie',
            'amount': '150.00',
            'date_borrowed': '2025-10-20',
            'loan_type': 'lending'
        })

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM loans ORDER BY id DESC LIMIT 1")
        loan_id = c.fetchone()[0]
        conn.close()
        return loan_id

    def test_edit_with_invalid_loan_id(self, logged_in_client):
        """Test that invalid loan IDs are handled."""
        # Non-numeric ID
        response = logged_in_client.get('/edit/abc', follow_redirects=True)
        assert response.status_code in [200, 404]

        # Negative ID
        response = logged_in_client.get('/edit/-1', follow_redirects=True)
        assert response.status_code in [200, 404]

        # Non-existent ID
        response = logged_in_client.get('/edit/999999', follow_redirects=True)
        assert response.status_code == 200
        # Should redirect to dashboard with error

    def test_edit_with_empty_amount(self, logged_in_client, loan_id):
        """Test that empty amount in edit is handled."""
        response = logged_in_client.post(f'/edit/{loan_id}', data={
            'borrower': 'Charlie Updated',
            'amount': '',  # Empty
            'date_borrowed': '2025-10-20'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_edit_with_non_numeric_amount(self, logged_in_client, loan_id):
        """Test that non-numeric amount in edit is handled."""
        response = logged_in_client.post(f'/edit/{loan_id}', data={
            'borrower': 'Charlie Updated',
            'amount': 'xyz',  # Non-numeric
            'date_borrowed': '2025-10-20'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_edit_with_invalid_repayment_amount(self, logged_in_client, loan_id):
        """Test that invalid repayment amount in edit is handled."""
        response = logged_in_client.post(f'/edit/{loan_id}', data={
            'borrower': 'Charlie Updated',
            'amount': '150.00',
            'repayment_amount': 'not-a-number',  # Non-numeric
            'repayment_frequency': 'weekly',
            'date_borrowed': '2025-10-20'
        }, follow_redirects=True)

        assert response.status_code == 200


class TestSendInviteInputValidation:
    """Test input validation for send invite feature."""

    @pytest.fixture
    def encrypted_loan_id(self, logged_in_client, app):
        """Create an encrypted test loan and return its ID."""
        # Create loan through normal flow (will be encrypted)
        logged_in_client.post('/', data={
            'borrower': 'David',
            'amount': '200.00',
            'date_borrowed': '2025-10-20',
            'loan_type': 'lending'
        }, follow_redirects=True)

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM loans ORDER BY id DESC LIMIT 1")
        loan_id = c.fetchone()[0]
        conn.close()
        return loan_id

    def test_send_invite_with_encrypted_loan(self, logged_in_client, encrypted_loan_id):
        """Test that send invite page loads correctly with encrypted loan data."""
        response = logged_in_client.get(f'/loan/{encrypted_loan_id}/send-invite')

        # This is the bug - should not crash with TypeError
        assert response.status_code == 200
        # Should show loan amount properly formatted
        assert b'Loan Amount' in response.data
        assert b'Amount Repaid' in response.data

    def test_send_invite_with_null_amount_repaid(self, logged_in_client, encrypted_loan_id):
        """Test that loans with no repayments display correctly."""
        response = logged_in_client.get(f'/loan/{encrypted_loan_id}/send-invite')

        assert response.status_code == 200
        # Should show $0.00 for amount repaid, not crash
        assert b'$' in response.data


class TestTransactionMatchingInputValidation:
    """Test input validation for transaction matching."""

    def test_match_with_empty_csv(self, logged_in_client):
        """Test that empty CSV is handled."""
        response = logged_in_client.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': ''  # Empty
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_match_with_malformed_csv(self, logged_in_client):
        """Test that malformed CSV is handled."""
        response = logged_in_client.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': 'not,valid,csv\ndata'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_match_with_invalid_date_in_csv(self, logged_in_client):
        """Test that invalid dates in CSV are handled."""
        csv_data = """Date,Description,Amount
not-a-date,Payment,50.00"""

        response = logged_in_client.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_match_with_invalid_amount_in_csv(self, logged_in_client):
        """Test that invalid amounts in CSV are handled."""
        csv_data = """Date,Description,Amount
2025-10-15,Payment,not-a-number"""

        response = logged_in_client.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_match_with_csv_injection(self, logged_in_client):
        """Test that CSV injection attempts are handled."""
        csv_data = """Date,Description,Amount
2025-10-15,=cmd|'/c calc'!A1,50.00"""

        response = logged_in_client.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_match_with_invalid_connection_id(self, logged_in_client):
        """Test that invalid connection IDs are handled."""
        response = logged_in_client.post('/match', data={
            'import_source': 'abc'  # Non-numeric connection ID
        }, follow_redirects=True)

        assert response.status_code == 200


class TestAuthenticationInputValidation:
    """Test input validation for authentication."""

    def test_register_with_invalid_email(self, client):
        """Test that invalid email format is handled."""
        response = client.post('/register', data={
            'email': 'not-an-email'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_register_with_empty_email(self, client):
        """Test that empty email is handled."""
        response = client.post('/register', data={
            'email': ''
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_register_with_xss_in_email(self, client):
        """Test that XSS in email is handled."""
        response = client.post('/register', data={
            'email': '<script>alert("xss")</script>@test.com'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_register_with_sql_injection_in_email(self, client):
        """Test that SQL injection in email is handled."""
        response = client.post('/register', data={
            'email': "'; DROP TABLE users;--@test.com"
        }, follow_redirects=True)

        assert response.status_code == 200

        # Verify users table still exists
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        count = c.fetchone()[0]
        conn.close()
        assert count is not None


class TestAuthorizationValidation:
    """Test authorization checks - users accessing other users' data."""

    @pytest.fixture
    def two_users(self, client, app):
        """Create two users and their loans."""
        # User 1
        client.post('/register', data={'email': 'user1@test.com'})
        with client.session_transaction() as sess:
            user1_id = sess.get('user_id')

        client.post('/', data={
            'borrower': 'Alice',
            'amount': '100.00',
            'date_borrowed': '2025-10-20',
            'loan_type': 'lending'
        })

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE user_id = ?", (user1_id,))
        user1_loan_id = c.fetchone()[0]
        conn.close()

        # Logout user 1
        client.get('/logout')

        # User 2
        client.post('/register', data={'email': 'user2@test.com'})
        with client.session_transaction() as sess:
            user2_id = sess.get('user_id')

        return {'user1_loan_id': user1_loan_id, 'user2_id': user2_id}

    def test_cannot_edit_another_users_loan(self, client, two_users):
        """Test that users cannot edit other users' loans."""
        response = client.post(f'/edit/{two_users["user1_loan_id"]}', data={
            'borrower': 'Hacker',
            'amount': '999.00',
            'date_borrowed': '2025-10-20'
        }, follow_redirects=True)

        # Should redirect or show error, not actually edit
        assert response.status_code == 200

        # Verify loan was not modified
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT borrower FROM loans WHERE id = ?", (two_users['user1_loan_id'],))
        result = c.fetchone()
        conn.close()

        # Borrower should still be 'Alice' (or encrypted, so check it's not 'Hacker')
        if result and result[0]:
            assert result[0] != 'Hacker'

    def test_cannot_delete_another_users_loan(self, client, two_users):
        """Test that users cannot delete other users' loans."""
        response = client.post(f'/delete/{two_users["user1_loan_id"]}', follow_redirects=True)

        # Verify loan was not deleted
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM loans WHERE id = ?", (two_users['user1_loan_id'],))
        count = c.fetchone()[0]
        conn.close()

        assert count == 1  # Loan still exists

    def test_cannot_add_repayment_to_another_users_loan(self, client, two_users):
        """Test that users cannot add repayments to other users' loans."""
        response = client.post(f'/repay/{two_users["user1_loan_id"]}', data={
            'repayment_amount': '50.00'
        }, follow_redirects=True)

        # Verify repayment was not added
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT COUNT(*) FROM applied_transactions
            WHERE loan_id = ? AND description = 'Manual repayment'
        """, (two_users['user1_loan_id'],))
        count = c.fetchone()[0]
        conn.close()

        assert count == 0  # No repayment added
