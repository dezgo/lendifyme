"""
Tests for settings routes (password, recovery, banks).
"""
import pytest
from helpers.db import get_db_connection
from services.auth_helpers import hash_recovery_code
from services.encryption import generate_encryption_salt
from werkzeug.security import generate_password_hash
import json


@pytest.fixture
def logged_in_client_no_password(app, client):
    """Create logged-in client WITHOUT password (simulates magic link login)."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            # Insert user WITHOUT password
            c.execute("""
                INSERT INTO users (email, name, recovery_codes, created_at, email_verified, onboarding_completed, role, subscription_tier)
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?)
            """, ('nopassword@example.com', 'No Password User', '[]', 1, 1, 'user', 'free'))

            user_id = c.lastrowid
            conn.commit()

    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['user_email'] = 'nopassword@example.com'
        sess['user_name'] = 'No Password User'

    return client


class TestSettingsPage:
    """Test main settings page."""

    def test_settings_requires_login(self, client):
        """Test that settings page requires login."""
        response = client.get('/settings', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_settings_page_loads(self, logged_in_client):
        """Test that settings page loads for logged-in users."""
        response = logged_in_client.get('/settings')

        assert response.status_code == 200
        assert b'Settings' in response.data or b'settings' in response.data


class TestPasswordManagement:
    """Test password add, change, and security features."""

    def test_password_page_requires_login(self, client):
        """Test that password settings require login."""
        response = client.get('/settings/password', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_password_page_loads_for_user_with_password(self, logged_in_client):
        """Test password page loads for user with existing password."""
        response = logged_in_client.get('/settings/password')

        assert response.status_code == 200

    def test_password_page_loads_for_user_without_password(self, logged_in_client_no_password):
        """Test password page loads for user without password."""
        response = logged_in_client_no_password.get('/settings/password')

        assert response.status_code == 200
        # Should show "Add Password" option

    def test_add_password_success(self, logged_in_client_no_password, app):
        """Test successfully adding a password."""
        response = logged_in_client_no_password.post('/settings/password', data={
            'action': 'add',
            'new_password': 'NewSecurePass123!',
            'confirm_password': 'NewSecurePass123!',
        }, follow_redirects=False)

        # Should redirect to recovery phrase page
        assert response.status_code == 302
        assert '/auth/recovery-phrase' in response.location

        # Verify password was saved
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT password_hash, encryption_salt, master_recovery_key_hash FROM users WHERE email = ?",
                         ('nopassword@example.com',))
                user = c.fetchone()

        assert user is not None
        assert user[0] is not None  # password_hash should be set
        assert user[1] is not None  # encryption_salt should be set
        assert user[2] is not None  # master_recovery_key_hash should be set

    def test_add_password_too_short(self, logged_in_client_no_password):
        """Test that short passwords are rejected."""
        response = logged_in_client_no_password.post('/settings/password', data={
            'action': 'add',
            'new_password': 'short',
            'confirm_password': 'short',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'at least 8 characters' in response.data

    def test_add_password_common_password_rejected(self, logged_in_client_no_password):
        """Test that common passwords are rejected."""
        response = logged_in_client_no_password.post('/settings/password', data={
            'action': 'add',
            'new_password': 'password123',
            'confirm_password': 'password123',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'too common' in response.data or b'compromised' in response.data

    def test_add_password_mismatch(self, logged_in_client_no_password):
        """Test that mismatched passwords are rejected."""
        response = logged_in_client_no_password.post('/settings/password', data={
            'action': 'add',
            'new_password': 'NewSecurePass123!',
            'confirm_password': 'DifferentPass456!',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'do not match' in response.data

    def test_add_password_when_already_exists(self, logged_in_client, app):
        """Test that adding password when one exists is rejected."""
        response = logged_in_client.post('/settings/password', data={
            'action': 'add',
            'new_password': 'NewSecurePass123!',
            'confirm_password': 'NewSecurePass123!',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'already have a password' in response.data

    def test_change_password_success(self, logged_in_client, app):
        """Test successfully changing password."""
        # logged_in_client fixture creates user with password 'testpassword123'
        response = logged_in_client.post('/settings/password', data={
            'action': 'change',
            'current_password': 'testpassword123',
            'new_password': 'NewSecurePass456!',
            'confirm_password': 'NewSecurePass456!',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'success' in response.data.lower() or b'changed' in response.data.lower()

    def test_change_password_wrong_current(self, logged_in_client):
        """Test changing password with wrong current password."""
        response = logged_in_client.post('/settings/password', data={
            'action': 'change',
            'current_password': 'wrongpassword',
            'new_password': 'NewSecurePass456!',
            'confirm_password': 'NewSecurePass456!',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'incorrect' in response.data.lower() or b'wrong' in response.data.lower()

    def test_change_password_to_common_password(self, logged_in_client):
        """Test that changing to common password is rejected."""
        response = logged_in_client.post('/settings/password', data={
            'action': 'change',
            'current_password': 'testpassword123',
            'new_password': 'qwerty',
            'confirm_password': 'qwerty',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'too common' in response.data or b'compromised' in response.data


class TestBankSettings:
    """Test bank connection settings."""

    def test_banks_page_requires_login(self, client):
        """Test that bank settings require login."""
        response = client.get('/settings/banks', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_banks_page_loads(self, logged_in_client):
        """Test that bank settings page loads."""
        response = logged_in_client.get('/settings/banks')

        assert response.status_code == 200

    def test_banks_add_page_requires_login(self, client):
        """Test that add bank page requires login."""
        response = client.get('/settings/banks/add', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_banks_add_page_loads(self, logged_in_client):
        """Test that add bank page loads."""
        response = logged_in_client.get('/settings/banks/add')

        # Should load or redirect to password setup
        assert response.status_code in [200, 302]


class TestRecoverySettings:
    """Test recovery code management."""

    def test_recovery_page_requires_login(self, client):
        """Test that recovery settings require login."""
        response = client.get('/settings/recovery', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_recovery_page_loads(self, logged_in_client):
        """Test that recovery settings page loads."""
        response = logged_in_client.get('/settings/recovery')

        assert response.status_code == 200
