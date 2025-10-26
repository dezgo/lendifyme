import os
import tempfile
import pytest
from app import app as flask_app
import sqlite3

@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp()
    flask_app.config['TESTING'] = True
    flask_app.config['DATABASE'] = db_path
    flask_app.config['SECRET_KEY'] = 'test-secret-key'

    with flask_app.test_client() as client:
        with flask_app.app_context():
            conn = sqlite3.connect(db_path)
            from services.migrations import run_migrations
            run_migrations(conn)
            conn.close()
        yield client

    os.close(db_fd)
    os.unlink(db_path)

def test_form_submission(client):
    response = client.post('/', data={
        'borrower': 'Alice',
        'amount': '120.50',
        'note': 'For groceries',
        'date_borrowed': '2025-10-25'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Alice' in response.data
    assert b'120.5' in response.data
    assert b'For groceries' in response.data
    assert b'2025-10-25' in response.data


def test_loan_repayment(client):
    """Test adding a repayment to a loan."""
    # First create a loan
    response = client.post('/', data={
        'borrower': 'Bob',
        'amount': '100.00',
        'note': 'Test loan',
        'date_borrowed': '2025-10-20'
    }, follow_redirects=True)

    assert response.status_code == 200

    # Get the loan ID from the database
    conn = sqlite3.connect(flask_app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT id FROM loans WHERE borrower = 'Bob'")
    loan_id = c.fetchone()[0]
    conn.close()

    # Add a repayment
    response = client.post(f'/repay/{loan_id}', data={
        'repayment_amount': '50.00'
    }, follow_redirects=True)

    assert response.status_code == 200

    # Verify the repayment was recorded
    conn = sqlite3.connect(flask_app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT amount_repaid FROM loans WHERE id = ?", (loan_id,))
    amount_repaid = c.fetchone()[0]
    conn.close()

    assert amount_repaid == 50.00

    # Verify remaining balance is displayed
    assert b'50.00' in response.data  # Remaining amount


def test_multiple_repayments(client):
    """Test adding multiple repayments to a loan."""
    # Create a loan
    client.post('/', data={
        'borrower': 'Charlie',
        'amount': '150.00',
        'note': 'Test loan',
        'date_borrowed': '2025-10-20'
    })

    # Get loan ID
    conn = sqlite3.connect(flask_app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT id FROM loans WHERE borrower = 'Charlie'")
    loan_id = c.fetchone()[0]
    conn.close()

    # Add first repayment
    client.post(f'/repay/{loan_id}', data={'repayment_amount': '50.00'})

    # Add second repayment
    client.post(f'/repay/{loan_id}', data={'repayment_amount': '30.00'})

    # Verify total repayments
    conn = sqlite3.connect(flask_app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT amount_repaid FROM loans WHERE id = ?", (loan_id,))
    amount_repaid = c.fetchone()[0]
    conn.close()

    assert amount_repaid == 80.00


def test_index_shows_repayment_columns(client):
    """Test that index page shows repayment information."""
    # Create a loan with partial repayment
    client.post('/', data={
        'borrower': 'David',
        'amount': '200.00',
        'note': 'Test',
        'date_borrowed': '2025-10-20'
    })

    response = client.get('/')

    assert response.status_code == 200
    assert b'Repaid' in response.data
    assert b'Remaining' in response.data
    assert b'Add Repayment' in response.data
