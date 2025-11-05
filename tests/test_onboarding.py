"""
Tests for onboarding flow.
"""
import pytest
from helpers.db import get_db_connection
from werkzeug.security import generate_password_hash
from services.encryption import generate_encryption_salt
import json


@pytest.fixture
def new_user_client(app, client):
    """Create logged-in client for user who hasn't completed onboarding."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            # Create user with onboarding_completed = 0
            encryption_salt = generate_encryption_salt()
            password_hash = generate_password_hash('testpass123')

            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier,
                    encryption_salt, password_hash
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?)
            """, (
                'newuser@example.com', 'New User', '[]',
                1, 0, 'user', 'free', encryption_salt, password_hash
            ))

            user_id = c.lastrowid
            conn.commit()

    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['user_email'] = 'newuser@example.com'
        sess['user_name'] = 'New User'
        sess['user_password'] = 'testpass123'  # Password in session for encryption

    return client


@pytest.fixture
def new_user_no_password_client(app, client):
    """Create logged-in client for user without password (magic link login)."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            # Create user WITHOUT password
            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?)
            """, (
                'magiclink@example.com', 'Magic User', '[]',
                1, 0, 'user', 'free'
            ))

            user_id = c.lastrowid
            conn.commit()

    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['user_email'] = 'magiclink@example.com'
        sess['user_name'] = 'Magic User'

    return client


class TestOnboardingFlow:
    """Test onboarding workflow."""

    def test_onboarding_requires_login(self, client):
        """Test that onboarding requires login."""
        response = client.get('/onboarding', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_onboarding_redirects_if_completed(self, logged_in_client):
        """Test that users who completed onboarding are redirected to dashboard."""
        # logged_in_client fixture has onboarding_completed = 1
        response = logged_in_client.get('/onboarding', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'

    def test_onboarding_step2_loads_with_password(self, new_user_client):
        """Test that onboarding step 2 loads for users with password."""
        response = new_user_client.get('/onboarding?step=2')

        assert response.status_code == 200
        # Should show create first loan step

    def test_onboarding_without_password_redirects_to_password_setup(self, new_user_no_password_client):
        """Test that users without password are redirected to password setup."""
        response = new_user_no_password_client.get('/onboarding?step=2', follow_redirects=False)

        assert response.status_code == 302
        assert '/settings/password' in response.location
        assert 'redirect=onboarding' in response.location

    def test_onboarding_completion(self, new_user_client, app):
        """Test marking onboarding as complete."""
        response = new_user_client.get('/onboarding?step=complete', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'

        # Verify onboarding_completed was set
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT onboarding_completed FROM users WHERE email = ?",
                         ('newuser@example.com',))
                result = c.fetchone()

        assert result[0] == 1

    def test_onboarding_step1_legacy(self, new_user_client):
        """Test that step 1 (legacy) still loads for backwards compatibility."""
        response = new_user_client.get('/onboarding?step=1')

        assert response.status_code == 200


class TestOnboardingEmailUpdate:
    """Test email update during onboarding."""

    def test_update_email_requires_login(self, client):
        """Test that email update requires login."""
        response = client.post('/onboarding/update-email', data={
            'email': 'newemail@example.com'
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_update_email_success(self, new_user_client, app):
        """Test successfully updating email during onboarding."""
        response = new_user_client.post('/onboarding/update-email', data={
            'email': 'updated@example.com'
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/onboarding' in response.location

        # Verify email was updated
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT email FROM users WHERE name = ?", ('New User',))
                result = c.fetchone()

        assert result[0] == 'updated@example.com'

        # Verify session was updated
        with new_user_client.session_transaction() as sess:
            assert sess['user_email'] == 'updated@example.com'

    def test_update_email_empty(self, new_user_client):
        """Test that empty email is rejected."""
        response = new_user_client.post('/onboarding/update-email', data={
            'email': ''
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'required' in response.data.lower()

    def test_update_email_already_taken(self, new_user_client, app):
        """Test that duplicate email is rejected."""
        # Create another user with the email we want to use
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO users (email, name, recovery_codes, created_at, email_verified, onboarding_completed, role, subscription_tier)
                    VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?)
                """, ('taken@example.com', 'Other User', '[]', 1, 1, 'user', 'free'))
                conn.commit()

        response = new_user_client.post('/onboarding/update-email', data={
            'email': 'taken@example.com'
        }, follow_redirects=True)

        assert response.status_code == 200

        # Verify email was NOT updated (should still be original email)
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT email FROM users WHERE name = ?", ('New User',))
                result = c.fetchone()

        # Email should still be the original email, not the taken one
        assert result[0] == 'newuser@example.com'
