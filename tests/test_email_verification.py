"""
Tests for email verification flow.
"""
import pytest
from helpers.db import get_db_connection
from datetime import datetime, timedelta


@pytest.fixture
def unverified_user_client(app, client):
    """Create client for unverified user."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            # Create unverified user with verification token
            verification_token = 'test_verification_token_123'
            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier,
                    verification_token, verification_sent_at
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, datetime('now'))
            """, (
                'unverified@example.com', 'Unverified User', '[]',
                0, 0, 'user', 'free', verification_token
            ))

            user_id = c.lastrowid
            conn.commit()

    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['user_email'] = 'unverified@example.com'
        sess['user_name'] = 'Unverified User'

    return client, user_id, verification_token


@pytest.fixture
def expired_verification_user_client(app, client):
    """Create client for user with expired verification token."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            # Create user with expired verification token (25 hours ago)
            verification_token = 'expired_token_456'
            expired_time = (datetime.now() - timedelta(hours=25)).strftime('%Y-%m-%d %H:%M:%S')

            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier,
                    verification_token, verification_sent_at
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?)
            """, (
                'expired@example.com', 'Expired User', '[]',
                0, 0, 'user', 'free', verification_token, expired_time
            ))

            user_id = c.lastrowid
            conn.commit()

    return client, user_id, verification_token


class TestEmailVerification:
    """Test email verification endpoint."""

    def test_verify_email_success(self, unverified_user_client, app):
        """Test successful email verification."""
        client, user_id, token = unverified_user_client

        response = client.get(f'/auth/verify/{token}', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'

        # Verify email_verified was set
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT email_verified, verification_token FROM users WHERE id = ?", (user_id,))
                result = c.fetchone()

        assert result[0] == 1  # email_verified
        assert result[1] is None  # verification_token cleared

    def test_verify_email_invalid_token(self, client):
        """Test verification with invalid token."""
        response = client.get('/auth/verify/invalid_token_xyz', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_verify_email_already_verified(self, logged_in_client, app):
        """Test verifying an already verified email."""
        # logged_in_client has email_verified = 1
        # Get the user's verification token (need to set one)
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # Get user_id from session
                with logged_in_client.session_transaction() as sess:
                    user_id = sess['user_id']

                # Set a verification token
                token = 'already_verified_token'
                c.execute("""
                    UPDATE users
                    SET verification_token = ?
                    WHERE id = ?
                """, (token, user_id))
                conn.commit()

        response = logged_in_client.get(f'/auth/verify/{token}', follow_redirects=False)

        assert response.status_code == 302
        # Should redirect to login with success message

    def test_verify_email_expired_token(self, expired_verification_user_client):
        """Test verification with expired token (24+ hours old)."""
        client, user_id, token = expired_verification_user_client

        response = client.get(f'/auth/verify/{token}', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_verify_email_logs_user_in(self, unverified_user_client):
        """Test that verification logs user in if not already logged in."""
        client, user_id, token = unverified_user_client

        # Clear session to simulate not being logged in
        with client.session_transaction() as sess:
            sess.clear()

        response = client.get(f'/auth/verify/{token}', follow_redirects=False)

        assert response.status_code == 302

        # Verify user is now logged in
        with client.session_transaction() as sess:
            assert sess.get('user_id') == user_id
            assert sess.get('user_email') == 'unverified@example.com'


class TestResendVerification:
    """Test resending verification email."""

    def test_resend_verification_requires_login(self, client):
        """Test that resend verification requires login."""
        response = client.post('/resend-verification', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_resend_verification_already_verified(self, logged_in_client):
        """Test resending when already verified."""
        # logged_in_client has email_verified = 1
        response = logged_in_client.post('/resend-verification', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'

    def test_resend_verification_success(self, unverified_user_client, app):
        """Test successfully resending verification email."""
        client, user_id, old_token = unverified_user_client

        response = client.post('/resend-verification', follow_redirects=False)

        assert response.status_code == 302

        # Verify new token was generated
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT verification_token, verification_sent_at FROM users WHERE id = ?", (user_id,))
                result = c.fetchone()

        new_token = result[0]
        assert new_token is not None
        assert new_token != old_token  # Should be a different token
        assert result[1] is not None  # verification_sent_at should be updated
