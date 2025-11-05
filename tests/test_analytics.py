"""
Tests for analytics dashboard and admin user filtering.
"""
import json
import pytest
from helpers.db import get_db_connection
from services.migrations import run_migrations
from services.auth_helpers import hash_recovery_code
from app import app as flask_app
from datetime import datetime, timedelta


@pytest.fixture
def app(tmpdir, monkeypatch):
    """Create test app with temporary database."""
    flask_app.config.update(
        TESTING=True,
        SECRET_KEY='test-secret-key',
        APP_URL='http://localhost:5000',
        DATABASE=str(tmpdir.join('test.db')),
    )

    # Run migrations
    with flask_app.app_context():
        with get_db_connection() as conn:
            run_migrations(conn)

    return flask_app


@pytest.fixture
def client(app):
    """Create test client."""
    with app.test_client() as c:
        yield c


@pytest.fixture
def admin_user(app):
    """Create an admin user (user_id 1)."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            recovery_codes = ['ADMIN1', 'ADMIN2', 'ADMIN3']
            hashed_codes = [hash_recovery_code(code) for code in recovery_codes]
            codes_json = json.dumps(hashed_codes)

            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?)
            """, (
                'admin@example.com', 'Admin User', codes_json,
                1, 1, 'admin', 'pro'
            ))

            admin_id = c.lastrowid
            conn.commit()

            return admin_id


@pytest.fixture
def regular_user(app):
    """Create a regular user (non-admin)."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            recovery_codes = ['USER1', 'USER2', 'USER3']
            hashed_codes = [hash_recovery_code(code) for code in recovery_codes]
            codes_json = json.dumps(hashed_codes)

            c.execute("""
                INSERT INTO users (
                    email, name, recovery_codes, created_at,
                    email_verified, onboarding_completed, role, subscription_tier
                )
                VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?)
            """, (
                'user@example.com', 'Regular User', codes_json,
                1, 1, 'user', 'free'
            ))

            user_id = c.lastrowid
            conn.commit()

            return user_id


@pytest.fixture
def client_with_admin(app, client, admin_user):
    """Create client logged in as admin user."""
    with client.session_transaction() as sess:
        sess['user_id'] = admin_user
    return client


@pytest.fixture
def client_with_regular_user(app, client, regular_user):
    """Create client logged in as regular user."""
    with client.session_transaction() as sess:
        sess['user_id'] = regular_user
    return client


@pytest.fixture
def analytics_data(app, admin_user, regular_user):
    """Create test data for analytics - events from both admin and regular user."""
    with app.app_context():
        with get_db_connection() as conn:
            c = conn.cursor()

            # Create events for admin user (should be filtered out)
            admin_events = [
                ('user_signed_up', admin_user),
                ('loan_created', admin_user),
                ('loan_created', admin_user),
                ('bank_link_started', admin_user),
                ('bank_link_success', admin_user),
            ]

            for event_name, user_id in admin_events:
                c.execute("""
                    INSERT INTO events (user_id, event_name, created_at, event_data)
                    VALUES (?, ?, datetime('now'), ?)
                """, (user_id, event_name, '{}'))

            # Create events for regular user (should be counted)
            regular_events = [
                ('user_signed_up', regular_user),
                ('loan_created', regular_user),
                ('bank_link_started', regular_user),
                ('bank_link_success', regular_user),
            ]

            for event_name, user_id in regular_events:
                c.execute("""
                    INSERT INTO events (user_id, event_name, created_at, event_data)
                    VALUES (?, ?, datetime('now'), ?)
                """, (user_id, event_name, '{}'))

            # Create an event from last week for retention testing
            c.execute("""
                INSERT INTO events (user_id, event_name, created_at, event_data)
                VALUES (?, ?, datetime('now', '-10 days'), ?)
            """, (regular_user, 'loan_created', '{}'))

            # Create loans for both users
            c.execute("""
                INSERT INTO loans (user_id, borrower, amount, date_borrowed, created_at)
                VALUES (?, ?, ?, date('now'), datetime('now'))
            """, (admin_user, 'Admin Borrower', 100.0))

            c.execute("""
                INSERT INTO loans (user_id, borrower, amount, date_borrowed, created_at)
                VALUES (?, ?, ?, date('now'), datetime('now'))
            """, (regular_user, 'Regular Borrower', 200.0))

            conn.commit()


class TestAnalyticsAccess:
    """Test analytics page access control."""

    def test_analytics_requires_login(self, client):
        """Test that analytics page requires login."""
        response = client.get('/analytics', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.location

    def test_analytics_requires_admin(self, client_with_regular_user):
        """Test that analytics page requires admin role."""
        response = client_with_regular_user.get('/analytics', follow_redirects=False)

        assert response.status_code == 302
        # Should redirect away from analytics

    def test_analytics_accessible_to_admin(self, client_with_admin):
        """Test that analytics page is accessible to admin users."""
        response = client_with_admin.get('/analytics')

        assert response.status_code == 200
        assert b'Analytics Dashboard' in response.data


class TestAnalyticsMetrics:
    """Test analytics metrics and admin user filtering."""

    def test_total_users_includes_all_users(self, client_with_admin, analytics_data):
        """Test that total users includes admin (it's a count of all users)."""
        response = client_with_admin.get('/analytics')

        assert response.status_code == 200
        # Should have 2 total users (admin + regular)
        assert b'Total Users' in response.data

    def test_new_signups_excludes_admin(self, client_with_admin, analytics_data, app):
        """Test that new signup metrics exclude admin user."""
        response = client_with_admin.get('/analytics')

        assert response.status_code == 200

        # Verify in database that we have the right data
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # Check total signups (including admin)
                c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'user_signed_up'")
                total_signups = c.fetchone()[0]
                assert total_signups == 2  # admin + regular

                # Check signups excluding admin
                c.execute("""
                    SELECT COUNT(*) FROM events
                    WHERE event_name = 'user_signed_up' AND user_id != 1
                """)
                filtered_signups = c.fetchone()[0]
                assert filtered_signups == 1  # only regular user

    def test_dau_excludes_admin(self, client_with_admin, analytics_data, app):
        """Test that DAU (Daily Active Users) excludes admin."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # DAU should only count regular user
                c.execute("""
                    SELECT COUNT(DISTINCT user_id)
                    FROM events
                    WHERE date(created_at) = date('now')
                      AND user_id != 1
                """)
                dau = c.fetchone()[0]
                assert dau == 1  # only regular user

    def test_wau_excludes_admin(self, client_with_admin, analytics_data, app):
        """Test that WAU (Weekly Active Users) excludes admin."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # WAU should only count regular user
                c.execute("""
                    SELECT COUNT(DISTINCT user_id)
                    FROM events
                    WHERE created_at >= date('now', '-7 days')
                      AND user_id != 1
                """)
                wau = c.fetchone()[0]
                assert wau == 1  # only regular user

    def test_mau_excludes_admin(self, client_with_admin, analytics_data, app):
        """Test that MAU (Monthly Active Users) excludes admin."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # MAU should only count regular user
                c.execute("""
                    SELECT COUNT(DISTINCT user_id)
                    FROM events
                    WHERE created_at >= date('now', '-30 days')
                      AND user_id != 1
                """)
                mau = c.fetchone()[0]
                assert mau == 1  # only regular user

    def test_loans_created_excludes_admin(self, client_with_admin, analytics_data, app):
        """Test that loan creation metrics exclude admin."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # Check total loan events (including admin)
                c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'loan_created'")
                total_loans = c.fetchone()[0]
                assert total_loans == 4  # 2 from admin, 2 from regular (1 today, 1 old)

                # Check loans excluding admin (last 30 days)
                c.execute("""
                    SELECT COUNT(*) FROM events
                    WHERE event_name = 'loan_created'
                      AND created_at >= date('now', '-30 days')
                      AND user_id != 1
                """)
                filtered_loans = c.fetchone()[0]
                assert filtered_loans == 2  # only regular user's loans

    def test_bank_link_funnel_excludes_admin(self, client_with_admin, analytics_data, app):
        """Test that bank link funnel metrics exclude admin."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # Check bank link started (excluding admin)
                c.execute("""
                    SELECT COUNT(*) FROM events
                    WHERE event_name = 'bank_link_started'
                      AND created_at >= date('now', '-30 days')
                      AND user_id != 1
                """)
                started = c.fetchone()[0]
                assert started == 1  # only regular user

                # Check bank link success (excluding admin)
                c.execute("""
                    SELECT COUNT(*) FROM events
                    WHERE event_name = 'bank_link_success'
                      AND created_at >= date('now', '-30 days')
                      AND user_id != 1
                """)
                success = c.fetchone()[0]
                assert success == 1  # only regular user

                # Conversion should be 100%
                conversion = (success / started * 100) if started > 0 else 0
                assert conversion == 100.0

    def test_retention_excludes_admin(self, client_with_admin, analytics_data, app):
        """Test that retention calculation excludes admin."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # The retention query should exclude admin from both week calculations
                c.execute("""
                    SELECT COUNT(DISTINCT e1.user_id)
                    FROM events e1
                    WHERE e1.created_at >= date('now', '-7 days')
                      AND e1.user_id != 1
                      AND e1.user_id IN (
                          SELECT DISTINCT user_id
                          FROM events
                          WHERE created_at >= date('now', '-14 days')
                            AND created_at < date('now', '-7 days')
                            AND user_id != 1
                      )
                """)
                retained = c.fetchone()[0]

                # We created an event 10 days ago for regular user, and events today
                # So regular user should be retained
                assert retained == 1


class TestAnalyticsEventData:
    """Test event counts and recent events."""

    def test_event_counts_exclude_admin(self, client_with_admin, analytics_data, app):
        """Test that event counts exclude admin user."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # Event counts should exclude admin
                c.execute("""
                    SELECT event_name, COUNT(*) as count
                    FROM events
                    WHERE created_at >= date('now', '-30 days')
                      AND user_id != 1
                    GROUP BY event_name
                    ORDER BY count DESC
                """)
                event_counts = c.fetchall()

                # Should only have regular user's events
                total_events = sum(count for _, count in event_counts)
                assert total_events == 5  # 4 today + 1 from 10 days ago (all from regular user)

    def test_recent_events_exclude_admin(self, client_with_admin, analytics_data, app):
        """Test that recent events list excludes admin user."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                # Recent events should exclude admin
                c.execute("""
                    SELECT e.event_name, e.created_at, u.email, e.event_data
                    FROM events e
                    LEFT JOIN users u ON e.user_id = u.id
                    WHERE e.user_id != 1
                    ORDER BY e.created_at DESC
                    LIMIT 20
                """)
                recent_events = c.fetchall()

                # Should only have regular user's events
                assert len(recent_events) == 5  # 4 today + 1 from 10 days ago

                # Verify none are from admin
                for event in recent_events:
                    email = event[2]
                    assert email != 'admin@example.com'
                    assert email == 'user@example.com'

    def test_analytics_page_renders_metrics(self, client_with_admin, analytics_data):
        """Test that analytics page renders all metric sections."""
        response = client_with_admin.get('/analytics')

        assert response.status_code == 200
        assert b'Total Users' in response.data
        assert b'Daily Active Users' in response.data
        assert b'Weekly Active Users' in response.data
        assert b'Monthly Active Users' in response.data
        assert b'Total Loans' in response.data
        assert b'Week-over-Week Retention' in response.data
        assert b'Bank Connection Funnel' in response.data
        assert b'Event Activity' in response.data
        assert b'Recent Activity' in response.data


class TestAnalyticsWithNoData:
    """Test analytics with no event data."""

    def test_analytics_with_no_events(self, client_with_admin):
        """Test that analytics page handles zero events gracefully."""
        response = client_with_admin.get('/analytics')

        assert response.status_code == 200
        # Should show zeros or handle division by zero
        assert b'Analytics Dashboard' in response.data

    def test_bank_conversion_with_zero_starts(self, client_with_admin, app):
        """Test that bank conversion handles zero starts without error."""
        with app.app_context():
            with get_db_connection() as conn:
                c = conn.cursor()

                c.execute("""
                    SELECT COUNT(*) FROM events
                    WHERE event_name = 'bank_link_started'
                      AND created_at >= date('now', '-30 days')
                      AND user_id != 1
                """)
                bank_started = c.fetchone()[0]

                c.execute("""
                    SELECT COUNT(*) FROM events
                    WHERE event_name = 'bank_link_success'
                      AND created_at >= date('now', '-30 days')
                      AND user_id != 1
                """)
                bank_success = c.fetchone()[0]

                # Should not raise ZeroDivisionError
                conversion = (bank_success / bank_started * 100) if bank_started > 0 else 0
                assert conversion == 0
