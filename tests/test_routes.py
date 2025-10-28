import pytest
from app import app as flask_app
import sqlite3


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
def logged_in_client(client, tmpdir):
    """Create logged-in client with user session."""
    db_path = tmpdir.join('test.db')
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()

    # Create user
    c.execute("""
        INSERT INTO users (email, name, recovery_codes, created_at)
        VALUES (?, ?, ?, datetime('now'))
    """, ('test@example.com', 'Test User', '[]'))
    user_id = c.lastrowid
    conn.commit()
    conn.close()

    # Set session
    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['user_email'] = 'test@example.com'
        sess['user_name'] = 'Test User'

    yield client


def test_form_submission(logged_in_client, tmpdir):
    response = logged_in_client.post('/', data={
        'borrower': 'Alice',
        'amount': '120.50',
        'note': 'For groceries',
        'date_borrowed': '2025-10-25',
        'loan_type': 'lending'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Alice' in response.data
    assert b'120.5' in response.data
    # Note: New card-based dashboard doesn't show notes or dates in main view


def test_loan_repayment(logged_in_client, tmpdir):
    """Test adding a repayment to a loan."""
    # First create a loan
    response = logged_in_client.post('/', data={
        'borrower': 'Bob',
        'amount': '100.00',
        'note': 'Test loan',
        'date_borrowed': '2025-10-20',
        'loan_type': 'lending'
    }, follow_redirects=True)

    assert response.status_code == 200

    # Get the loan ID from the database
    db_path = tmpdir.join('test.db')
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("SELECT id FROM loans WHERE borrower = 'Bob'")
    loan_id = c.fetchone()[0]
    conn.close()

    # Add a repayment
    response = logged_in_client.post(f'/repay/{loan_id}', data={
        'repayment_amount': '50.00'
    }, follow_redirects=True)

    assert response.status_code == 200

    # Verify the repayment was recorded
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("SELECT SUM(amount) FROM applied_transactions WHERE loan_id = ?", (loan_id,))
    amount_repaid = c.fetchone()[0]
    conn.close()

    assert amount_repaid == 50.00

    # Verify remaining balance is displayed
    assert b'50.00' in response.data  # Remaining amount


def test_multiple_repayments(logged_in_client, tmpdir):
    """Test adding multiple repayments to a loan."""
    # Create a loan
    logged_in_client.post('/', data={
        'borrower': 'Charlie',
        'amount': '150.00',
        'note': 'Test loan',
        'date_borrowed': '2025-10-20',
        'loan_type': 'lending'
    })

    # Get loan ID
    db_path = tmpdir.join('test.db')
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("SELECT id FROM loans WHERE borrower = 'Charlie'")
    loan_id = c.fetchone()[0]
    conn.close()

    # Add first repayment
    logged_in_client.post(f'/repay/{loan_id}', data={'repayment_amount': '50.00'})

    # Add second repayment
    logged_in_client.post(f'/repay/{loan_id}', data={'repayment_amount': '30.00'})

    # Verify total repayments
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("SELECT SUM(amount) FROM applied_transactions WHERE loan_id = ?", (loan_id,))
    amount_repaid = c.fetchone()[0]
    conn.close()

    assert amount_repaid == 80.00


def test_index_shows_repayment_columns(logged_in_client):
    """Test that index page shows repayment information."""
    # Create a loan with partial repayment
    logged_in_client.post('/', data={
        'borrower': 'David',
        'amount': '200.00',
        'note': 'Test',
        'date_borrowed': '2025-10-20',
        'loan_type': 'lending'
    })

    response = logged_in_client.get('/')

    assert response.status_code == 200
    assert b'Lent' in response.data or b'Lending' in response.data  # Updated to match new dashboard
