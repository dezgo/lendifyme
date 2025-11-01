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
    """, (user_id, 'Alice', 100.00, 'Test loan', '2025-10-01', 'lending', access_token))
    conn.commit()
    conn.close()

    yield logged_in_client


class TestMatchUploadRoute:
    """Test /match GET route (upload page)."""

    def test_match_page_loads(self, logged_in_client):
        """Test that match upload page loads successfully."""
        response = logged_in_client.get('/match')

        assert response.status_code == 200
        assert b'Match Bank Transactions' in response.data
        assert b'Paste Bank Transactions' in response.data

    def test_match_page_has_instructions(self, logged_in_client):
        """Test that upload page has instructions."""
        response = logged_in_client.get('/match')

        assert b'How it works' in response.data
        assert b'CSV' in response.data


class TestMatchSubmissionRoute:
    """Test /match POST route (transaction submission)."""

    def test_submit_transactions_with_match(self, client_with_loan):
        """Test submitting transactions that match a loan."""
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        response = client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Suggested Matches' in response.data or b'Review Matches' in response.data
        assert b'Alice' in response.data
        assert b'50' in response.data

    def test_submit_transactions_no_match(self, client_with_loan):
        """Test submitting transactions with no matches."""
        csv_data = """Date,Description,Amount
2025-10-15,Coffee shop payment,3.47"""

        response = client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200
        # Should redirect back to upload page with message about no matches
        assert b'No pending matches' in response.data or b'Import transactions' in response.data

    def test_submit_empty_csv(self, client_with_loan):
        """Test submitting empty CSV."""
        csv_data = """Date,Description,Amount"""

        response = client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200
        # Should redirect back to upload page with message about no matches
        assert b'No pending matches' in response.data or b'Import transactions' in response.data

    def test_submit_multiple_transactions(self, client_with_loan):
        """Test submitting multiple transactions."""
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,25.00
2025-10-16,Transfer from Alice,25.00
2025-10-17,Transfer from Alice,50.00"""

        response = client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Suggested Matches' in response.data or b'Review Matches' in response.data


class TestApplyMatchRoute:
    """Test /apply-match POST route."""

    def test_apply_match_updates_loan(self, app, client_with_loan):
        """Test that applying a match updates the loan."""
        # Submit transactions to create matches
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        response = client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200

        # Get the session key and load matches from database
        db_path = app.config['DATABASE']
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        with client_with_loan.session_transaction() as sess:
            session_key = sess.get('pending_matches_key')

        c.execute("SELECT matches_json FROM pending_matches_data WHERE session_key = ?", (session_key,))
        matches_json = c.fetchone()[0]
        matches = json.loads(matches_json)
        match_id = matches[0]['match_id']
        conn.close()

        # Apply the match
        response = client_with_loan.post('/apply-match', data={
            'match_id': match_id
        }, follow_redirects=False)

        assert response.status_code in [200, 204]  # 204 No Content is valid for successful operations

        # Verify transaction was recorded in applied_transactions
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT SUM(amount) FROM applied_transactions WHERE loan_id = 1")
        amount_repaid = c.fetchone()[0]
        conn.close()

        assert amount_repaid == 50.00

    def test_apply_match_invalid_id(self, client_with_loan):
        """Test applying match with invalid ID returns error."""
        # Create matches first
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        # Try to apply with invalid match_id
        response = client_with_loan.post('/apply-match', data={
            'match_id': 'invalid-id-12345'
        })

        # Should return 400 or handle gracefully
        assert response.status_code in [200, 400]


class TestMatchWorkflow:
    """Test complete matching workflow integration."""

    def test_full_workflow(self, app, logged_in_client):
        """Test complete workflow: create loan, upload transactions, apply match."""
        db_path = app.config['DATABASE']

        # Get user_id
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", ('test@example.com',))
        user_id = c.fetchone()[0]

        # 1. Create a loan
        c.execute("""
            INSERT INTO loans (user_id, borrower, amount, note, date_borrowed, loan_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, 'Bob', 200.00, 'Test loan', '2025-10-01', 'lending'))
        loan_id = c.lastrowid
        conn.commit()
        conn.close()

        # 2. Submit transactions
        csv_data = """Date,Description,Amount
2025-10-15,Zelle from Bob Johnson,100.00"""

        response = logged_in_client.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Bob' in response.data
        assert b'100' in response.data

        # 3. Load matches from database and get match_id
        with logged_in_client.session_transaction() as sess:
            session_key = sess.get('pending_matches_key')
            assert session_key is not None

        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT matches_json FROM pending_matches_data WHERE session_key = ?", (session_key,))
        matches_json = c.fetchone()[0]
        matches = json.loads(matches_json)
        match_id = matches[0]['match_id']
        conn.close()

        # 4. Apply the match
        response = logged_in_client.post('/apply-match', data={
            'match_id': match_id
        })

        # 5. Verify loan was updated
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT SUM(amount) FROM applied_transactions WHERE loan_id = ?", (loan_id,))
        amount_repaid = c.fetchone()[0]
        conn.close()

        assert amount_repaid == 100.00

    def test_multiple_matches_workflow(self, app, logged_in_client):
        """Test workflow with multiple loans and transactions."""
        db_path = app.config['DATABASE']

        # Get user_id
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", ('test@example.com',))
        user_id = c.fetchone()[0]

        # Create multiple loans
        c.execute("""
            INSERT INTO loans (user_id, borrower, amount, note, date_borrowed, loan_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, 'Alice', 100.00, 'Loan 1', '2025-10-01', 'lending'))
        c.execute("""
            INSERT INTO loans (user_id, borrower, amount, note, date_borrowed, loan_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, 'Bob', 200.00, 'Loan 2', '2025-10-01', 'lending'))
        conn.commit()
        conn.close()

        # Submit transactions for both
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00
2025-10-16,Payment Bob,100.00"""

        response = logged_in_client.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Alice' in response.data
        assert b'Bob' in response.data


class TestDateRangeFeature:
    """Test date range selection for API connectors."""

    def test_match_page_has_date_range_selector(self, logged_in_client):
        """Test that match page includes date range selector."""
        response = logged_in_client.get('/match')

        assert response.status_code == 200
        assert b'Date Range' in response.data
        assert b'Last 7 days' in response.data
        assert b'Last 30 days' in response.data
        assert b'Last 90 days' in response.data
        assert b'Custom date' in response.data

    def test_csv_upload_ignores_date_range(self, client_with_loan):
        """Test that CSV upload works regardless of date_range parameter."""
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        response = client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data,
            'date_range': '90'  # Should be ignored for CSV
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Alice' in response.data


class TestRejectMatch:
    """Test /reject-match POST route."""

    def test_reject_match_records_in_database(self, app, client_with_loan):
        """Test that rejecting a match records it in rejected_matches."""
        # Create matches first
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        # Get the match_id
        db_path = app.config['DATABASE']
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        with client_with_loan.session_transaction() as sess:
            session_key = sess.get('pending_matches_key')

        c.execute("SELECT matches_json FROM pending_matches_data WHERE session_key = ?", (session_key,))
        matches_json = c.fetchone()[0]
        matches = json.loads(matches_json)
        match_id = matches[0]['match_id']
        conn.close()

        # Reject the match
        response = client_with_loan.post('/reject-match', data={
            'match_id': match_id
        })

        assert response.status_code in [200, 204]  # 204 No Content is valid for successful operations

        # Verify rejected match was recorded
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("""
            SELECT date, description, amount, loan_id
            FROM rejected_matches
            WHERE description = ?
        """, ('Transfer from Alice',))
        rejected = c.fetchone()
        conn.close()

        assert rejected is not None
        assert rejected[0] == '2025-10-15'
        assert rejected[1] == 'Transfer from Alice'
        assert rejected[2] == 50.00
        assert rejected[3] == 1


class TestMatchReviewPage:
    """Test /match/review GET route."""

    def test_review_page_requires_matches_in_session(self, client_with_loan):
        """Test that review page redirects when no matches in session."""
        response = client_with_loan.get('/match/review', follow_redirects=False)

        assert response.status_code == 302
        assert '/match' in response.location

    def test_review_page_shows_matches(self, client_with_loan):
        """Test that review page displays pending matches."""
        # Create matches via the match route
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        response = client_with_loan.get('/match/review')

        assert response.status_code == 200
        assert b'Suggested Matches' in response.data or b'Review Matches' in response.data
        assert b'Alice' in response.data
        assert b'50' in response.data


class TestDuplicateTransactionPrevention:
    """Test that duplicate transactions are prevented."""

    def test_applied_transaction_not_suggested_again(self, app, client_with_loan):
        """Test that already applied transactions are not suggested."""
        # Add an applied transaction
        db_path = app.config['DATABASE']
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO applied_transactions (loan_id, date, description, amount, applied_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (1, '2025-10-15', 'Transfer from Alice', 50.00))
        conn.commit()
        conn.close()

        # Submit the same transaction again
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        response = client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200
        # Should redirect back to upload page with no matches message
        assert b'No pending matches' in response.data or b'Import transactions' in response.data

    def test_rejected_transaction_not_suggested_for_same_loan(self, app, client_with_loan):
        """Test that rejected transactions are not suggested for the same loan."""
        # Add a rejected match
        db_path = app.config['DATABASE']
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO rejected_matches (loan_id, date, description, amount, rejected_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (1, '2025-10-15', 'Transfer from Alice', 50.00))
        conn.commit()
        conn.close()

        # Submit the same transaction again
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        response = client_with_loan.post('/match', data={
            'import_source': 'csv',
            'transactions_csv': csv_data
        }, follow_redirects=True)

        assert response.status_code == 200
        # Should redirect back to upload page with no matches message
        assert b'No pending matches' in response.data or b'Import transactions' in response.data
