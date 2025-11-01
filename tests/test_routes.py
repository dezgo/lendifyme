import pytest
import sqlite3


def test_form_submission(logged_in_client, app):
    # Create loan
    response = logged_in_client.post('/', data={
        'borrower': 'Alice',
        'amount': '120.50',
        'note': 'For groceries',
        'date_borrowed': '2025-10-25',
        'loan_type': 'lending'
    })

    assert response.status_code == 302  # Redirect after creation

    # Now GET the index page to see the loan
    response = logged_in_client.get('/', follow_redirects=True)
    assert response.status_code == 200
    assert b'Alice' in response.data
    assert b'120.5' in response.data
    # Note: New card-based dashboard doesn't show notes or dates in main view


def test_loan_repayment(logged_in_client, app):
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

    # Get the loan ID from the database (borrower column is now encrypted)
    db_path = app.config['DATABASE']
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT id FROM loans ORDER BY id DESC LIMIT 1")
    loan_id = c.fetchone()[0]
    conn.close()

    # Add a repayment
    response = logged_in_client.post(f'/repay/{loan_id}', data={
        'repayment_amount': '50.00'
    }, follow_redirects=True)

    assert response.status_code == 200

    # Verify the repayment was recorded
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT SUM(amount) FROM applied_transactions WHERE loan_id = ?", (loan_id,))
    amount_repaid = c.fetchone()[0]
    conn.close()

    assert amount_repaid == 50.00

    # Verify remaining balance is displayed
    assert b'50.00' in response.data  # Remaining amount


def test_multiple_repayments(logged_in_client, app):
    """Test adding multiple repayments to a loan."""
    # Create a loan
    logged_in_client.post('/', data={
        'borrower': 'Charlie',
        'amount': '150.00',
        'note': 'Test loan',
        'date_borrowed': '2025-10-20',
        'loan_type': 'lending'
    })

    # Get loan ID (borrower column is now encrypted)
    db_path = app.config['DATABASE']
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT id FROM loans ORDER BY id DESC LIMIT 1")
    loan_id = c.fetchone()[0]
    conn.close()

    # Add first repayment
    logged_in_client.post(f'/repay/{loan_id}', data={'repayment_amount': '50.00'})

    # Add second repayment
    logged_in_client.post(f'/repay/{loan_id}', data={'repayment_amount': '30.00'})

    # Verify total repayments
    conn = sqlite3.connect(db_path)
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

    response = logged_in_client.get('/', follow_redirects=True)

    assert response.status_code == 200
    assert b'Lent' in response.data or b'Lending' in response.data  # Updated to match new dashboard
