import pytest
import sqlite3
import json


@pytest.fixture
def client_with_loan(app, logged_in_client):
    """Create logged-in client with a sample loan."""
    # Use the app's configured database, not a separate tmpdir
    db_path = app.config['DATABASE']
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Get user_id
    c.execute("SELECT id FROM users WHERE email = ?", ('test@example.com',))
    user_id = c.fetchone()[0]

    # Generate access token for borrower portal
    from services.auth_helpers import generate_magic_link_token
    access_token = generate_magic_link_token()

    # Create loan with access token
    c.execute("""
        INSERT INTO loans (user_id, borrower, amount, note, date_borrowed, loan_type, borrower_access_token)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, 'Alice Smith', 100.00, 'Test loan', '2025-10-01', 'lending', access_token))
    conn.commit()
    conn.close()

    yield logged_in_client


class TestDashboard:
    """Test authenticated dashboard."""

    def test_dashboard_requires_login(self, client):
        """Test that dashboard shows landing page when not logged in."""
        response = client.get('/')

        assert response.status_code == 200
        # Should show landing page, not dashboard
        assert b'Track Your Loans, Effortlessly' in response.data

    def test_dashboard_loads_for_logged_in_user(self, logged_in_client):
        """Test that dashboard loads for logged-in users."""
        response = logged_in_client.get('/')

        assert response.status_code == 200
        assert b'Add New Loan' in response.data
        assert b'Match Transactions' in response.data

    def test_dashboard_shows_loans(self, client_with_loan):
        """Test that dashboard displays user loans."""
        response = client_with_loan.get('/')

        assert response.status_code == 200
        assert b'Alice Smith' in response.data
        assert b'100' in response.data

    def test_add_loan_via_dashboard(self, logged_in_client, tmpdir):
        """Test creating a loan via dashboard form."""
        response = logged_in_client.post('/', data={
            'borrower': 'Bob Jones',
            'amount': '250.00',
            'note': 'Emergency loan',
            'date_borrowed': '2025-10-20',
            'loan_type': 'lending'
        }, follow_redirects=True)

        assert response.status_code == 200

        # Verify loan was created (data is now encrypted, so check encrypted columns)
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id, borrower_encrypted, amount_encrypted, note_encrypted FROM loans ORDER BY id DESC LIMIT 1")
        loan = c.fetchone()
        conn.close()

        assert loan is not None
        # Verify encrypted fields exist (they should start with Fernet signature)
        assert loan[1] is not None and loan[1].startswith('gAAAAA')  # borrower_encrypted
        assert loan[2] is not None and loan[2].startswith('gAAAAA')  # amount_encrypted
        assert loan[3] is not None and loan[3].startswith('gAAAAA')  # note_encrypted

    def test_dashboard_shows_summary_stats(self, client_with_loan):
        """Test that dashboard shows summary statistics."""
        response = client_with_loan.get('/')

        assert response.status_code == 200
        # Should show summary cards
        assert b'Total Lent' in response.data or b'Lending' in response.data


class TestEditLoan:
    """Test loan editing functionality."""

    def test_edit_page_requires_login(self, client):
        """Test that edit page requires authentication."""
        response = client.get('/edit/1', follow_redirects=False)

        # Should redirect to landing/login
        assert response.status_code == 302

    def test_edit_page_loads(self, client_with_loan, tmpdir):
        """Test that edit page loads with loan data."""
        # Get loan ID
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan_id = c.fetchone()[0]
        conn.close()

        response = client_with_loan.get(f'/edit/{loan_id}')

        assert response.status_code == 200
        assert b'Edit Loan' in response.data
        assert b'Alice Smith' in response.data
        assert b'Save Changes' in response.data

    def test_edit_loan_updates_data(self, client_with_loan, tmpdir):
        """Test that editing a loan updates the database."""
        # Get loan ID
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan_id = c.fetchone()[0]
        conn.close()

        # Update loan
        response = client_with_loan.post(f'/edit/{loan_id}', data={
            'borrower': 'Alice Johnson',
            'amount': '150.00',
            'note': 'Updated note',
            'date_borrowed': '2025-10-01',
            'repayment_amount': '50.00',
            'repayment_frequency': 'weekly',
            'bank_name': 'Alice J'
        }, follow_redirects=True)

        assert response.status_code == 200

        # Verify changes
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("""
            SELECT borrower, amount, note, repayment_amount, repayment_frequency, bank_name
            FROM loans WHERE id = ?
        """, (loan_id,))
        loan = c.fetchone()
        conn.close()

        assert loan[0] == 'Alice Johnson'
        assert loan[1] == 150.00
        assert loan[2] == 'Updated note'
        assert loan[3] == 50.00
        assert loan[4] == 'weekly'
        assert loan[5] == 'Alice J'


class TestDeleteLoan:
    """Test loan deletion."""

    def test_delete_loan_requires_login(self, client):
        """Test that delete requires authentication."""
        response = client.post('/delete/1', follow_redirects=False)

        assert response.status_code == 302

    def test_delete_loan_removes_from_database(self, client_with_loan, tmpdir):
        """Test that deleting a loan removes it from database."""
        # Get loan ID
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan_id = c.fetchone()[0]
        conn.close()

        # Delete loan
        response = client_with_loan.post(f'/delete/{loan_id}', follow_redirects=True)

        assert response.status_code == 200

        # Verify deletion
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM loans WHERE id = ?", (loan_id,))
        count = c.fetchone()[0]
        conn.close()

        assert count == 0


class TestLoanTransactions:
    """Test loan transactions view."""

    def test_transactions_page_requires_login(self, client):
        """Test that transactions page requires authentication."""
        response = client.get('/loan/1/transactions', follow_redirects=False)

        assert response.status_code == 302

    def test_transactions_page_loads(self, client_with_loan, tmpdir):
        """Test that transactions page loads."""
        # Get loan ID
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan_id = c.fetchone()[0]
        conn.close()

        response = client_with_loan.get(f'/loan/{loan_id}/transactions')

        assert response.status_code == 200
        assert b'Alice Smith' in response.data
        assert b'Payment History' in response.data or b'Transactions' in response.data

    def test_transactions_page_shows_applied_transactions(self, client_with_loan, tmpdir):
        """Test that transactions page shows applied transactions."""
        # Get loan ID
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan_id = c.fetchone()[0]

        # Add an applied transaction
        c.execute("""
            INSERT INTO applied_transactions (loan_id, date, description, amount, applied_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (loan_id, '2025-10-15', 'Payment from Alice', 50.00))
        conn.commit()
        conn.close()

        response = client_with_loan.get(f'/loan/{loan_id}/transactions')

        assert response.status_code == 200
        assert b'Payment from Alice' in response.data
        assert b'50' in response.data

    def test_export_transactions_csv(self, app, client_with_loan):
        """Test exporting transactions as CSV."""
        # Get loan ID
        db_path = app.config['DATABASE']
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan_id = c.fetchone()[0]

        # Add transaction
        c.execute("""
            INSERT INTO applied_transactions (loan_id, date, description, amount, applied_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (loan_id, '2025-10-15', 'Payment', 50.00))
        conn.commit()
        conn.close()

        response = client_with_loan.get(f'/loan/{loan_id}/transactions/export')

        assert response.status_code == 200
        assert response.content_type == 'text/csv; charset=utf-8'
        assert b'Date,Description,Amount' in response.data
        assert b'Payment' in response.data

    def test_remove_transaction(self, client_with_loan, tmpdir):
        """Test removing an applied transaction."""
        # Get loan ID and add transaction
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan_id = c.fetchone()[0]

        # Add transaction
        c.execute("""
            INSERT INTO applied_transactions (loan_id, date, description, amount, applied_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (loan_id, '2025-10-15', 'Payment', 50.00))
        transaction_id = c.lastrowid

        # Remove transaction
        response = client_with_loan.post(f'/remove-transaction/{transaction_id}', follow_redirects=True)

        assert response.status_code == 200

        # Verify transaction removed
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM applied_transactions WHERE id = ?", (transaction_id,))
        count = c.fetchone()[0]

        assert count == 0


class TestSendInvite:
    """Test borrower portal invite functionality."""

    def test_send_invite_page_requires_login(self, client):
        """Test that send invite page requires authentication."""
        response = client.get('/loan/1/send-invite', follow_redirects=False)

        assert response.status_code == 302

    def test_send_invite_page_loads(self, client_with_loan, tmpdir):
        """Test that send invite page loads."""
        # Get loan ID
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan_id = c.fetchone()[0]
        conn.close()

        response = client_with_loan.get(f'/loan/{loan_id}/send-invite')

        assert response.status_code == 200
        assert b'Send Invitation Email' in response.data
        assert b'Alice Smith' in response.data


class TestBorrowerPortal:
    """Test borrower portal (public access)."""

    def test_borrower_portal_with_valid_token(self, client_with_loan, tmpdir):
        """Test that borrower portal loads with valid token."""
        # Get loan with borrower_access_token
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT id, borrower_access_token FROM loans WHERE borrower = ?", ('Alice Smith',))
        loan = c.fetchone()
        loan_id, borrower_access_token = loan
        conn.close()

        # If no portal token, create one
        if not borrower_access_token:
            from services.auth_helpers import generate_magic_link_token
            borrower_access_token = generate_magic_link_token()
            conn = sqlite3.connect(str(db_path))
            c = conn.cursor()
            c.execute("UPDATE loans SET borrower_access_token = ? WHERE id = ?", (borrower_access_token, loan_id))
            conn.commit()
            conn.close()

        response = client_with_loan.get(f'/borrower/{borrower_access_token}')

        assert response.status_code == 200
        assert b'Alice Smith' in response.data or b'Loan Details' in response.data

    def test_borrower_portal_with_invalid_token(self, client):
        """Test that invalid token shows error page."""
        response = client.get('/borrower/invalid-token-12345')

        assert response.status_code == 404
        assert b'Invalid Access Link' in response.data or b'error' in response.data.lower()
