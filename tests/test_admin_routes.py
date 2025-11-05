"""
Tests for admin routes (user management, feedback, cleanup).
"""
import pytest
from helpers.db import get_db_connection
from services.auth_helpers import hash_recovery_code
from werkzeug.security import generate_password_hash
import json


@pytest.fixture
def admin_client(app, client):
    """Create logged-in admin user client."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            password_hash = generate_password_hash('adminpass123')

            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier,
                    password_hash
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?)
            """, (
                'admin@example.com', 'Admin User', '[]',
                1, 1, 'admin', 'pro', password_hash
            ))

            admin_id = c.lastrowid
            conn.commit()

    with client.session_transaction() as sess:
        sess['user_id'] = admin_id
        sess['user_email'] = 'admin@example.com'
        sess['user_name'] = 'Admin User'

    return client


@pytest.fixture
def regular_and_admin_client(app, client):
    """Create both a regular user and admin user, return admin client."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            # Create regular user
            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?)
            """, ('regular@example.com', 'Regular User', '[]', 1, 1, 'user', 'free'))

            regular_id = c.lastrowid

            # Create admin user
            password_hash = generate_password_hash('adminpass123')
            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier,
                    password_hash
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?)
            """, ('admin@example.com', 'Admin User', '[]', 1, 1, 'admin', 'pro', password_hash))

            admin_id = c.lastrowid
            conn.commit()

    with client.session_transaction() as sess:
        sess['user_id'] = admin_id
        sess['user_email'] = 'admin@example.com'
        sess['user_name'] = 'Admin User'

    return client, regular_id, admin_id


class TestAdminUsersPage:
    """Test admin users management page."""

    def test_admin_users_requires_login(self, client):
        """Test that admin users page requires login."""
        response = client.get('/admin/users', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_admin_users_requires_admin_role(self, logged_in_client):
        """Test that regular users can't access admin page."""
        # logged_in_client has role='user'
        response = logged_in_client.get('/admin/users', follow_redirects=False)

        assert response.status_code == 302
        # Should redirect away

    def test_admin_users_page_loads(self, admin_client):
        """Test that admin users page loads for admin."""
        response = admin_client.get('/admin/users')

        assert response.status_code == 200
        assert b'admin@example.com' in response.data

    def test_admin_users_shows_all_users(self, regular_and_admin_client):
        """Test that admin page shows all users."""
        client, regular_id, admin_id = regular_and_admin_client

        response = client.get('/admin/users')

        assert response.status_code == 200
        assert b'regular@example.com' in response.data
        assert b'admin@example.com' in response.data


class TestAdminUpgradeUser:
    """Test admin user tier upgrade."""

    def test_upgrade_user_requires_login(self, client):
        """Test that upgrade requires login."""
        response = client.post('/admin/user/1/upgrade', data={
            'tier': 'pro'
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_upgrade_user_requires_admin(self, logged_in_client):
        """Test that upgrade requires admin role."""
        response = logged_in_client.post('/admin/user/1/upgrade', data={
            'tier': 'pro'
        }, follow_redirects=False)

        assert response.status_code == 302

    def test_upgrade_user_success(self, regular_and_admin_client, app):
        """Test successfully upgrading a user."""
        client, regular_id, admin_id = regular_and_admin_client

        response = client.post(f'/admin/user/{regular_id}/upgrade', data={
            'tier': 'pro'
        }, follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/admin/users'

        # Verify user was upgraded
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT subscription_tier, manual_override FROM users WHERE id = ?", (regular_id,))
                result = c.fetchone()

        assert result[0] == 'pro'
        assert result[1] == 1  # manual_override

    def test_upgrade_user_invalid_tier(self, regular_and_admin_client):
        """Test upgrading to invalid tier."""
        client, regular_id, admin_id = regular_and_admin_client

        response = client.post(f'/admin/user/{regular_id}/upgrade', data={
            'tier': 'invalid_tier'
        }, follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/admin/users'

    def test_upgrade_user_to_all_valid_tiers(self, regular_and_admin_client, app):
        """Test upgrading to all valid tiers."""
        client, regular_id, admin_id = regular_and_admin_client

        valid_tiers = ['free', 'basic', 'pro']

        for tier in valid_tiers:
            response = client.post(f'/admin/user/{regular_id}/upgrade', data={
                'tier': tier
            }, follow_redirects=False)

            assert response.status_code == 302

            # Verify tier was set
            with app.app_context():
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT subscription_tier FROM users WHERE id = ?", (regular_id,))
                    result = c.fetchone()

            assert result[0] == tier


class TestAdminDeleteUser:
    """Test admin user deletion."""

    def test_delete_user_requires_login(self, client):
        """Test that delete requires login."""
        response = client.post('/admin/user/1/delete', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_delete_user_requires_admin(self, logged_in_client):
        """Test that delete requires admin role."""
        response = logged_in_client.post('/admin/user/1/delete', follow_redirects=False)

        assert response.status_code == 302

    def test_delete_user_success(self, regular_and_admin_client, app):
        """Test successfully deleting a user."""
        client, regular_id, admin_id = regular_and_admin_client

        response = client.post(f'/admin/user/{regular_id}/delete', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/admin/users'

        # Verify user was deleted
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT id FROM users WHERE id = ?", (regular_id,))
                result = c.fetchone()

        assert result is None

    def test_delete_user_cannot_delete_self(self, admin_client):
        """Test that admin cannot delete their own account."""
        # Get admin's user_id
        with admin_client.session_transaction() as sess:
            admin_id = sess['user_id']

        response = admin_client.post(f'/admin/user/{admin_id}/delete', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/admin/users'

    def test_delete_nonexistent_user(self, admin_client):
        """Test deleting a user that doesn't exist."""
        response = admin_client.post('/admin/user/99999/delete', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/admin/users'


class TestAdminFeedback:
    """Test admin feedback management."""

    def test_admin_feedback_requires_login(self, client):
        """Test that admin feedback page requires login."""
        response = client.get('/admin/feedback', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_admin_feedback_requires_admin_role(self, logged_in_client):
        """Test that regular users can't access admin feedback."""
        response = logged_in_client.get('/admin/feedback', follow_redirects=False)

        assert response.status_code == 302

    def test_admin_feedback_page_loads(self, admin_client):
        """Test that admin feedback page loads for admin."""
        response = admin_client.get('/admin/feedback')

        assert response.status_code == 200

    def test_admin_feedback_shows_submissions(self, admin_client, app):
        """Test that feedback page shows submissions."""
        # Create some feedback first (page_url is NOT NULL)
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO feedback (feedback_type, message, page_url, created_at)
                    VALUES (?, ?, ?, datetime('now'))
                """, ('bug', 'Test bug report', 'http://localhost/dashboard'))
                conn.commit()

        response = admin_client.get('/admin/feedback')

        assert response.status_code == 200
        assert b'Test bug report' in response.data


class TestAdminFeedbackUpdate:
    """Test updating feedback status."""

    def test_update_feedback_requires_login(self, client):
        """Test that update requires login."""
        response = client.post('/admin/feedback/1/update', data={
            'status': 'resolved'
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_update_feedback_requires_admin(self, logged_in_client):
        """Test that update requires admin role."""
        response = logged_in_client.post('/admin/feedback/1/update', data={
            'status': 'resolved'
        }, follow_redirects=False)

        assert response.status_code == 302

    def test_update_feedback_success(self, admin_client, app):
        """Test successfully updating feedback status."""
        # Create feedback first (page_url is NOT NULL)
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO feedback (feedback_type, message, page_url, status, created_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                """, ('bug', 'Test feedback', 'http://localhost/test', 'new'))
                feedback_id = c.lastrowid
                conn.commit()

        response = admin_client.post(f'/admin/feedback/{feedback_id}/update', data={
            'status': 'resolved'
        }, follow_redirects=False)

        assert response.status_code == 302

        # Verify status was updated
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT status FROM feedback WHERE id = ?", (feedback_id,))
                result = c.fetchone()

        assert result is not None
        assert result[0] == 'resolved'


class TestAdminCleanupInactive:
    """Test admin inactive user cleanup."""

    def test_cleanup_requires_login(self, client):
        """Test that cleanup requires login."""
        response = client.post('/admin/cleanup-inactive', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_cleanup_requires_admin(self, logged_in_client):
        """Test that cleanup requires admin role."""
        response = logged_in_client.post('/admin/cleanup-inactive', follow_redirects=False)

        assert response.status_code == 302

    def test_cleanup_page_accessible_to_admin(self, admin_client):
        """Test that cleanup endpoint is accessible to admin."""
        response = admin_client.post('/admin/cleanup-inactive', follow_redirects=False)

        # Should process (may redirect with success or error)
        assert response.status_code == 302
