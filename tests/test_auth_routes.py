from services.auth_helpers import hash_recovery_code
import json
import pytest
from helpers.db import get_db_connection
from services.migrations import run_migrations
from app import app as flask_app


@pytest.fixture
def app(tmpdir, monkeypatch):
    flask_app.config.update(
        TESTING=True,
        SECRET_KEY='test-secret-key',
        APP_URL='http://localhost:5000',
        DATABASE=str(tmpdir.join('test.db')),
    )

    # Run migrations on THIS DB inside app context so get_db_connection sees config
    with flask_app.app_context():
        with get_db_connection() as conn:
            run_migrations(conn)

    return flask_app


@pytest.fixture
def client(app):
    with app.test_client() as c:
        yield c


@pytest.fixture
def client_with_user(app, client):
    """Create a logged-out client but with a seeded user in the SAME DB."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            recovery_codes = ['CODE1', 'CODE2', 'CODE3']
            hashed_codes = [hash_recovery_code(code) for code in recovery_codes]
            codes_json = json.dumps(hashed_codes)

            # Insert a user record compatible with your current schema.
            # (Adjust columns if you’ve added NOT NULL constraints.)
            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?)
            """, (
                'test@example.com', 'Test User', codes_json,
                1, 1, 'user', 'free'
            ))

            conn.commit()

    # Return the same client (no re-init, no new DB)
    return client


class TestLandingPage:
    """Test landing page for non-logged-in users."""

    def test_landing_page_loads(self, client):
        """Test that landing page loads when not logged in."""
        response = client.get('/')

        assert response.status_code == 200
        assert b'Track Your Loans, Effortlessly' in response.data
        assert b'Get Started Free' in response.data
        assert b'Sign In' in response.data

    def test_landing_has_features(self, client):
        """Test that landing page shows key features."""
        response = client.get('/')

        assert b'Smart Matching' in response.data
        assert b'Borrower Portal' in response.data
        assert b'How It Works' in response.data


class TestRegisterRoute:
    """Test user registration."""

    def test_register_page_loads(self, client):
        """Test that register page loads."""
        response = client.get('/register')

        assert response.status_code == 200
        assert b'Start tracking your loans today' in response.data
        assert b'Get Started' in response.data

    def test_register_page_has_link_to_login(self, client):
        """Test that register page has link to login."""
        response = client.get('/register')

        assert b'Sign in' in response.data
        assert b'/login' in response.data

    def test_successful_registration(self, client, app):

        """Test successful user registration."""
        response = client.post('/register', data={
            'email': 'newuser@example.com',
        }, follow_redirects=False)

        # Should redirect to recovery codes page
        assert response.status_code == 302, response.data.decode()[:2000]
        assert '/onboarding' in response.location

        # Verify user was created
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT email, name FROM users WHERE email = ?", ('newuser@example.com',))
                user = c.fetchone()

        assert user is not None
        assert user[0] == 'newuser@example.com'

    def test_registration_without_name(self, client, app):
        """Test registration with only email (name optional)."""
        response = client.post('/register', data={
            'email': 'noname@example.com'
        }, follow_redirects=False)

        assert response.status_code == 302

        # Verify user was created
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT email, name FROM users WHERE email = ?", ('noname@example.com',))
                user = c.fetchone()

        assert user is not None
        assert user[0] == 'noname@example.com'

    def test_duplicate_email_registration(self, client_with_user):
        """Test that duplicate email registration just sends user their magic link """
        response = client_with_user.post('/register', data={
            'email': 'test@example.com',
            'name': 'Duplicate User'
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'magic link' in response.data or b'exists' in response.data


class TestLoginRoute:
    """Test user login."""

    def test_login_page_loads(self, client):
        """Test that login page loads."""
        response = client.get('/login')

        assert response.status_code == 200
        assert b'Welcome back!' in response.data
        assert b'Password (Optional)' in response.data

    def test_login_page_has_links(self, client):
        """Test that login page has all necessary links."""
        response = client.get('/login')

        assert b'Sign In' in response.data
        assert b'Sign up free' in response.data
        assert b'/register' in response.data

    def test_login_with_existing_user(self, client_with_user, app):
        """Test login request for existing user."""
        response = client_with_user.post('/login', data={
            'email': 'test@example.com'
        }, follow_redirects=True)

        assert response.status_code == 200

        # Verify magic link was created in database
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM magic_links WHERE user_id = (SELECT id FROM users WHERE email = ?)",
                          ('test@example.com',))
                count = c.fetchone()[0]

        assert count > 0

    def test_login_with_nonexistent_user(self, client):
        """Test login request for non-existent user."""
        response = client.post('/login', data={
            'email': 'nonexistent@example.com'
        }, follow_redirects=True)

        # Should not reveal whether user exists
        assert response.status_code == 200
        assert b'magic link' in response.data.lower()


class TestMagicLinkAuth:
    """Test magic link authentication."""

    def test_valid_magic_link(self, client_with_user, app):
        """Test authentication with valid magic link."""
        # Create a magic link
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                from services.auth_helpers import generate_magic_link_token, get_magic_link_expiry
                token = generate_magic_link_token()
                expires_at = get_magic_link_expiry(minutes=15)

                c.execute("SELECT id FROM users WHERE email = ?", ('test@example.com',))
                user_id = c.fetchone()[0]

                c.execute("""
                    INSERT INTO magic_links (user_id, token, expires_at, used)
                    VALUES (?, ?, ?, 0)
                """, (user_id, token, expires_at))
                conn.commit()

        # Test the magic link
        response = client_with_user.get(f'/auth/magic/{token}', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'

    def test_invalid_magic_link(self, client):
        """Test authentication with invalid magic link."""
        response = client.get('/auth/magic/invalid-token', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_used_magic_link(self, client_with_user, app):
        """Test that used magic links are rejected."""
        # Create a used magic link
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                from services.auth_helpers import generate_magic_link_token, get_magic_link_expiry
                token = generate_magic_link_token()
                expires_at = get_magic_link_expiry(minutes=15)

                c.execute("SELECT id FROM users WHERE email = ?", ('test@example.com',))
                user_id = c.fetchone()[0]

                c.execute("""
                    INSERT INTO magic_links (user_id, token, expires_at, used)
                    VALUES (?, ?, ?, 1)
                """, (user_id, token, expires_at))
                conn.commit()

        # Test the used magic link
        response = client_with_user.get(f'/auth/magic/{token}', follow_redirects=True)

        assert b'already been used' in response.data


class TestLogout:
    """Test logout functionality."""

    def test_logout_clears_session(self, client_with_user, app):
        """Test that logout clears user session."""
        # Log in first
        with client_with_user.session_transaction() as sess:
            with app.app_context():
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT id, email FROM users WHERE email = ?", ('test@example.com',))
                    user = c.fetchone()

            sess['user_id'] = user[0]
            sess['user_email'] = user[1]

        # Logout
        response = client_with_user.get('/logout', follow_redirects=False)

        assert response.status_code == 302
        assert response.location == '/'

        # Verify session is cleared
        with client_with_user.session_transaction() as sess:
            assert 'user_id' not in sess
            assert 'user_email' not in sess


class TestHealthCheck:
    """Test health check endpoint."""

    def test_health_endpoint(self, client):
        """Test that health endpoint returns OK."""
        response = client.get('/health')

        assert response.status_code == 200
        assert b'status: ok' in response.data
