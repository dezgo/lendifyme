import pytest
import sqlite3
from app import app as flask_app


@pytest.fixture
def app():
    """Create test app with secret key."""
    flask_app.config['TESTING'] = True
    flask_app.config['SECRET_KEY'] = 'test-secret-key'
    return flask_app


@pytest.fixture
def client(app, tmpdir):
    """Create test client with temporary database."""
    db_path = str(tmpdir.join('test.db'))
    app.config['DATABASE'] = db_path

    with app.test_client() as client:
        # Initialize database
        conn = sqlite3.connect(db_path)
        from services.migrations import run_migrations
        run_migrations(conn)
        conn.close()

        yield client


@pytest.fixture
def client_with_loan(client, tmpdir):
    """Create test client with a sample loan."""
    db_path = tmpdir.join('test.db')
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("""
        INSERT INTO loans (borrower, amount, note, date_borrowed, amount_repaid)
        VALUES (?, ?, ?, ?, ?)
    """, ('Alice', 100.00, 'Test loan', '2025-10-01', 0))
    conn.commit()
    conn.close()

    yield client


class TestMatchUploadRoute:
    """Test /match GET route (upload page)."""

    def test_match_page_loads(self, client):
        """Test that match upload page loads successfully."""
        response = client.get('/match')

        assert response.status_code == 200
        assert b'Match Bank Transactions' in response.data
        assert b'Paste Bank Transactions' in response.data

    def test_match_page_has_instructions(self, client):
        """Test that upload page has instructions."""
        response = client.get('/match')

        assert b'How it works' in response.data
        assert b'CSV' in response.data


class TestMatchSubmissionRoute:
    """Test /match POST route (transaction submission)."""

    def test_submit_transactions_with_match(self, client_with_loan):
        """Test submitting transactions that match a loan."""
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        response = client_with_loan.post('/match', data={
            'transactions_csv': csv_data
        }, follow_redirects=False)

        assert response.status_code == 200
        assert b'Suggested Matches' in response.data
        assert b'Alice' in response.data
        assert b'50.00' in response.data

    def test_submit_transactions_no_match(self, client_with_loan):
        """Test submitting transactions with no matches."""
        csv_data = """Date,Description,Amount
2025-10-15,Coffee shop payment,5.00"""

        response = client_with_loan.post('/match', data={
            'transactions_csv': csv_data
        }, follow_redirects=False)

        assert response.status_code == 200
        assert b'No Matches Found' in response.data

    def test_submit_empty_csv(self, client_with_loan):
        """Test submitting empty CSV."""
        csv_data = """Date,Description,Amount"""

        response = client_with_loan.post('/match', data={
            'transactions_csv': csv_data
        }, follow_redirects=False)

        assert response.status_code == 200
        assert b'No Matches Found' in response.data

    def test_submit_multiple_transactions(self, client_with_loan):
        """Test submitting multiple transactions."""
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,25.00
2025-10-16,Transfer from Alice,25.00
2025-10-17,Transfer from Alice,50.00"""

        response = client_with_loan.post('/match', data={
            'transactions_csv': csv_data
        }, follow_redirects=False)

        assert response.status_code == 200
        assert b'Suggested Matches' in response.data


class TestApplyMatchRoute:
    """Test /apply-match POST route."""

    def test_apply_match_updates_loan(self, client_with_loan, tmpdir):
        """Test that applying a match updates the loan."""
        # First, submit transactions to create matches
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00"""

        with client_with_loan.session_transaction() as sess:
            sess['pending_matches'] = [{
                'transaction': {
                    'date': '2025-10-15',
                    'description': 'Transfer from Alice',
                    'amount': 50.00
                },
                'loan': {
                    'id': 1,
                    'borrower': 'Alice',
                    'amount': 100.00,
                    'date_borrowed': '2025-10-01',
                    'amount_repaid': 0,
                    'note': 'Test loan'
                },
                'confidence': 80,
                'reasons': ['Test match']
            }]

        response = client_with_loan.post('/apply-match', data={
            'match_index': '0'
        }, follow_redirects=False)

        assert response.status_code == 302  # Redirect
        assert response.location == '/match'

        # Verify loan was updated
        db_path = tmpdir.join('test.db')
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT amount_repaid FROM loans WHERE id = 1")
        amount_repaid = c.fetchone()[0]
        conn.close()

        assert amount_repaid == 50.00

    def test_apply_match_removes_from_session(self, client_with_loan):
        """Test that applying a match removes it from session."""
        with client_with_loan.session_transaction() as sess:
            sess['pending_matches'] = [
                {
                    'transaction': {'date': '2025-10-15', 'description': 'Alice', 'amount': 50.00},
                    'loan': {'id': 1, 'borrower': 'Alice', 'amount': 100.00, 'date_borrowed': '2025-10-01', 'amount_repaid': 0, 'note': ''},
                    'confidence': 80,
                    'reasons': []
                },
                {
                    'transaction': {'date': '2025-10-16', 'description': 'Alice', 'amount': 25.00},
                    'loan': {'id': 1, 'borrower': 'Alice', 'amount': 100.00, 'date_borrowed': '2025-10-01', 'amount_repaid': 0, 'note': ''},
                    'confidence': 70,
                    'reasons': []
                }
            ]

        client_with_loan.post('/apply-match', data={'match_index': '0'})

        with client_with_loan.session_transaction() as sess:
            assert len(sess['pending_matches']) == 1

    def test_apply_match_invalid_index(self, client_with_loan):
        """Test applying match with invalid index."""
        with client_with_loan.session_transaction() as sess:
            sess['pending_matches'] = []

        response = client_with_loan.post('/apply-match', data={
            'match_index': '99'
        }, follow_redirects=False)

        # Should redirect without error
        assert response.status_code == 302

    def test_apply_match_no_session_data(self, client_with_loan):
        """Test applying match when no session data exists."""
        response = client_with_loan.post('/apply-match', data={
            'match_index': '0'
        }, follow_redirects=False)

        # Should redirect without error
        assert response.status_code == 302


class TestMatchWorkflow:
    """Test complete matching workflow integration."""

    def test_full_workflow(self, client, tmpdir):
        """Test complete workflow: create loan, upload transactions, apply match."""
        db_path = tmpdir.join('test.db')

        # 1. Create a loan
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("""
            INSERT INTO loans (borrower, amount, note, date_borrowed, amount_repaid)
            VALUES (?, ?, ?, ?, ?)
        """, ('Bob', 200.00, 'Test loan', '2025-10-01', 0))
        loan_id = c.lastrowid
        conn.commit()
        conn.close()

        # 2. Submit transactions
        csv_data = """Date,Description,Amount
2025-10-15,Zelle from Bob Johnson,100.00"""

        response = client.post('/match', data={
            'transactions_csv': csv_data
        })

        assert response.status_code == 200
        assert b'Bob' in response.data
        assert b'100.00' in response.data

        # 3. Apply the match
        with client.session_transaction() as sess:
            matches = sess.get('pending_matches', [])
            assert len(matches) > 0

        response = client.post('/apply-match', data={
            'match_index': '0'
        })

        # 4. Verify loan was updated
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("SELECT amount_repaid FROM loans WHERE id = ?", (loan_id,))
        amount_repaid = c.fetchone()[0]
        conn.close()

        assert amount_repaid == 100.00

    def test_multiple_matches_workflow(self, client, tmpdir):
        """Test workflow with multiple loans and transactions."""
        db_path = tmpdir.join('test.db')

        # Create multiple loans
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("""
            INSERT INTO loans (borrower, amount, note, date_borrowed, amount_repaid)
            VALUES (?, ?, ?, ?, ?)
        """, ('Alice', 100.00, 'Loan 1', '2025-10-01', 0))
        c.execute("""
            INSERT INTO loans (borrower, amount, note, date_borrowed, amount_repaid)
            VALUES (?, ?, ?, ?, ?)
        """, ('Bob', 200.00, 'Loan 2', '2025-10-01', 0))
        conn.commit()
        conn.close()

        # Submit transactions for both
        csv_data = """Date,Description,Amount
2025-10-15,Transfer from Alice,50.00
2025-10-16,Payment Bob,100.00"""

        response = client.post('/match', data={
            'transactions_csv': csv_data
        })

        assert response.status_code == 200
        assert b'Alice' in response.data
        assert b'Bob' in response.data


class TestDateRangeFeature:
    """Test date range selection for API connectors."""

    def test_match_page_has_date_range_selector(self, client):
        """Test that match page includes date range selector."""
        response = client.get('/match')

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
            'connector_type': 'csv',
            'transactions_csv': csv_data,
            'date_range': '90'  # Should be ignored for CSV
        }, follow_redirects=False)

        assert response.status_code == 200
        assert b'Alice' in response.data
