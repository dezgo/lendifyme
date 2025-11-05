"""
Tests for pending match review workflow (auto-sync).
"""
import pytest
from helpers.db import get_db_connection


@pytest.fixture
def client_with_pending_matches(logged_in_client):
    """Create client with pending matches in session."""
    with logged_in_client.session_transaction() as sess:
        sess['user_id'] = sess.get('user_id', 1)
        sess['pending_matches'] = [
            {
                'transaction': {
                    'date': '2025-11-01',
                    'description': 'Transfer from Alice',
                    'amount': 50.00
                },
                'loan': {
                    'id': 1,
                    'borrower': 'Alice Smith',
                    'amount': 100.00,
                    'amount_repaid': 0.00
                },
                'confidence': 85
            },
            {
                'transaction': {
                    'date': '2025-11-02',
                    'description': 'Payment Bob',
                    'amount': 25.00
                },
                'loan': {
                    'id': 2,
                    'borrower': 'Bob Jones',
                    'amount': 100.00,
                    'amount_repaid': 50.00
                },
                'confidence': 70
            }
        ]

    return logged_in_client


class TestPendingMatchReview:
    """Test pending match review page."""

    def test_review_pending_requires_login(self, client):
        """Test that review pending requires login."""
        response = client.get('/match/review-pending', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_review_pending_with_no_matches(self, logged_in_client):
        """Test review pending with no matches in session."""
        response = logged_in_client.get('/match/review-pending', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'

    def test_review_pending_page_loads(self, client_with_pending_matches):
        """Test that review pending page loads with matches."""
        response = client_with_pending_matches.get('/match/review-pending')

        assert response.status_code == 200
        assert b'Alice Smith' in response.data
        assert b'Bob Jones' in response.data
        assert b'50.00' in response.data
        assert b'85' in response.data  # confidence score


class TestApplyPendingMatch:
    """Test applying pending matches."""

    def test_apply_pending_requires_login(self, client):
        """Test that apply pending requires login."""
        response = client.post('/match/apply-pending', data={
            'match_index': 0
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_apply_pending_match_success(self, client_with_pending_matches, app):
        """Test successfully applying a pending match."""
        response = client_with_pending_matches.post('/match/apply-pending', data={
            'match_index': 0
        }, follow_redirects=False)

        assert response.status_code == 302

        # Verify transaction was applied to database
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT description, amount, loan_id, auto_applied, confidence_score
                    FROM applied_transactions
                    WHERE description = ?
                """, ('Transfer from Alice',))
                transaction = c.fetchone()

        assert transaction is not None
        assert transaction[0] == 'Transfer from Alice'
        assert transaction[1] == 50.00
        assert transaction[2] == 1  # loan_id
        assert transaction[3] == 0  # auto_applied = 0 (manually approved)
        assert transaction[4] == 85  # confidence_score

        # Verify match was removed from session
        with client_with_pending_matches.session_transaction() as sess:
            pending = sess.get('pending_matches', [])
            assert len(pending) == 1  # Should have 1 left
            assert pending[0]['transaction']['description'] == 'Payment Bob'

    def test_apply_pending_invalid_index(self, client_with_pending_matches):
        """Test applying with invalid match index."""
        response = client_with_pending_matches.post('/match/apply-pending', data={
            'match_index': 999
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/match/review-pending' in response.location

    def test_apply_pending_negative_index(self, client_with_pending_matches):
        """Test applying with negative index."""
        response = client_with_pending_matches.post('/match/apply-pending', data={
            'match_index': -1
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/match/review-pending' in response.location

    def test_apply_last_match_redirects_to_dashboard(self, logged_in_client, app):
        """Test that applying the last match redirects to dashboard."""
        # Set up session with only one match
        with logged_in_client.session_transaction() as sess:
            sess['pending_matches'] = [
                {
                    'transaction': {
                        'date': '2025-11-01',
                        'description': 'Single payment',
                        'amount': 100.00
                    },
                    'loan': {
                        'id': 1,
                        'borrower': 'Alice',
                        'amount': 100.00,
                        'amount_repaid': 0.00
                    },
                    'confidence': 90
                }
            ]

        response = logged_in_client.post('/match/apply-pending', data={
            'match_index': 0
        }, follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'


class TestRejectPendingMatch:
    """Test rejecting pending matches."""

    def test_reject_pending_requires_login(self, client):
        """Test that reject pending requires login."""
        response = client.post('/match/reject-pending', data={
            'match_index': 0
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_reject_pending_match_success(self, client_with_pending_matches, app):
        """Test successfully rejecting a pending match."""
        response = client_with_pending_matches.post('/match/reject-pending', data={
            'match_index': 0
        }, follow_redirects=False)

        assert response.status_code == 302

        # Verify rejection was recorded in database
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT description, amount, loan_id
                    FROM rejected_matches
                    WHERE description = ?
                """, ('Transfer from Alice',))
                rejection = c.fetchone()

        assert rejection is not None
        assert rejection[0] == 'Transfer from Alice'
        assert rejection[1] == 50.00
        assert rejection[2] == 1  # loan_id

        # Verify match was removed from session
        with client_with_pending_matches.session_transaction() as sess:
            pending = sess.get('pending_matches', [])
            assert len(pending) == 1  # Should have 1 left
            assert pending[0]['transaction']['description'] == 'Payment Bob'

    def test_reject_pending_invalid_index(self, client_with_pending_matches):
        """Test rejecting with invalid match index."""
        response = client_with_pending_matches.post('/match/reject-pending', data={
            'match_index': 999
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/match/review-pending' in response.location

    def test_reject_last_match_redirects_to_dashboard(self, logged_in_client):
        """Test that rejecting the last match redirects to dashboard."""
        # Set up session with only one match
        with logged_in_client.session_transaction() as sess:
            sess['pending_matches'] = [
                {
                    'transaction': {
                        'date': '2025-11-01',
                        'description': 'Single payment',
                        'amount': 100.00
                    },
                    'loan': {
                        'id': 1,
                        'borrower': 'Alice',
                        'amount': 100.00,
                        'amount_repaid': 0.00
                    },
                    'confidence': 90
                }
            ]

        response = logged_in_client.post('/match/reject-pending', data={
            'match_index': 0
        }, follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'


class TestUndoAutoMatch:
    """Test undoing auto-applied matches."""

    def test_undo_match_requires_login(self, client):
        """Test that undo requires login."""
        response = client.post('/match/undo/1', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_undo_match_success(self, logged_in_client, app):
        """Test successfully undoing an auto-applied match."""
        # First create an auto-applied transaction
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # Create a loan first
                c.execute("""
                    INSERT INTO loans (user_id, borrower, amount, date_borrowed, created_at)
                    VALUES (?, ?, ?, date('now'), datetime('now'))
                """, (1, 'Test Borrower', 100.00))  # Assuming logged_in user_id is 1

                loan_id = c.lastrowid

                # Create an auto-applied transaction
                c.execute("""
                    INSERT INTO applied_transactions
                    (date, description, amount, loan_id, auto_applied, confidence_score)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, ('2025-11-01', 'Auto payment', 50.00, loan_id, 1, 85))

                transaction_id = c.lastrowid
                conn.commit()

        # Now undo it
        response = logged_in_client.post(f'/match/undo/{transaction_id}', follow_redirects=True)

        assert response.status_code == 200

        # Verify transaction was deleted
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT id FROM applied_transactions WHERE id = ?", (transaction_id,))
                result = c.fetchone()

        assert result is None

    def test_undo_nonexistent_match(self, logged_in_client):
        """Test undoing a match that doesn't exist."""
        response = logged_in_client.post('/match/undo/99999', follow_redirects=True)

        # Should handle gracefully (either redirect or show error)
        assert response.status_code == 200
