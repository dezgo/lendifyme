"""
Tests for subscription lifecycle: tier lookup, loan limits, webhook handling.

Uses app/client fixtures from conftest.py.
"""
import json
import sqlite3
import pytest
from unittest.mock import patch


def _create_user(app, *, email="test@example.com", tier="free", manual_override=False):
    """Create a test user and return their ID."""
    from services.encryption import generate_encryption_salt
    from werkzeug.security import generate_password_hash

    db_path = app.config["DATABASE"]
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    salt = generate_encryption_salt()
    pw_hash = generate_password_hash("testpassword123")

    c.execute("""
        INSERT INTO users (email, name, recovery_codes, created_at,
                           encryption_salt, password_hash, email_verified,
                           onboarding_completed, role, subscription_tier,
                           manual_override)
        VALUES (?, ?, '[]', datetime('now'), ?, ?, 1, 1, 'user', ?, ?)
    """, (email, "Test User", salt, pw_hash, tier, int(manual_override)))
    user_id = c.lastrowid
    conn.commit()
    conn.close()
    return user_id


def _create_subscription(app, user_id, *, tier="basic", status="active",
                          stripe_sub_id="sub_test_123"):
    """Create a user_subscriptions row."""
    db_path = app.config["DATABASE"]
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        INSERT INTO user_subscriptions
        (user_id, stripe_subscription_id, stripe_customer_id, tier, status,
         current_period_start, current_period_end, created_at, updated_at)
        VALUES (?, ?, 'cus_test', ?, ?, '2026-01-01T00:00:00', '2026-02-01T00:00:00',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    """, (user_id, stripe_sub_id, tier, status))
    conn.commit()
    conn.close()


def _login_as(client, user_id):
    """Set session to logged in as user_id."""
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["user_email"] = "test@example.com"
        sess["user_name"] = "Test User"
        sess["user_password"] = "testpassword123"


def _loan_count(app, user_id):
    """Count loans for a user."""
    db_path = app.config["DATABASE"]
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM loans WHERE user_id = ?", (user_id,))
    count = c.fetchone()[0]
    conn.close()
    return count


def _get_user_tier(app, user_id):
    """Read subscription_tier from users table."""
    db_path = app.config["DATABASE"]
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT subscription_tier FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None


# ─── Tier lookup tests ───────────────────────────────────────────────────


class TestGetUserSubscriptionTier:
    """Tests for get_user_subscription_tier()."""

    def test_null_tier_returns_free(self, app):
        """BUG FIX: NULL subscription_tier must return 'free', not None."""
        user_id = _create_user(app, tier="free")

        # Manually set tier to NULL (simulates bug where webhook set it)
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.execute("UPDATE users SET subscription_tier = NULL WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        from services.loans import get_user_subscription_tier

        with app.app_context():
            tier = get_user_subscription_tier(user_id)
            assert tier == "free", f"NULL tier should return 'free', got '{tier}'"

    def test_null_tier_with_active_subscription_returns_paid(self, app):
        """BUG FIX: If tier is NULL but user_subscriptions has active row, return that tier."""
        user_id = _create_user(app, tier="free")

        # Set tier to NULL but create an active subscription record
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.execute("UPDATE users SET subscription_tier = NULL WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        _create_subscription(app, user_id, tier="basic", status="active")

        from services.loans import get_user_subscription_tier

        with app.app_context():
            tier = get_user_subscription_tier(user_id)
            assert tier == "basic", f"Should auto-repair from user_subscriptions, got '{tier}'"

        # Verify it also repaired the users table
        assert _get_user_tier(app, user_id) == "basic"

    def test_free_user_returns_free(self, app):
        user_id = _create_user(app, tier="free")

        from services.loans import get_user_subscription_tier

        with app.app_context():
            assert get_user_subscription_tier(user_id) == "free"

    def test_paid_user_returns_tier(self, app):
        user_id = _create_user(app, tier="pro")

        from services.loans import get_user_subscription_tier

        with app.app_context():
            assert get_user_subscription_tier(user_id) == "pro"

    def test_manual_override_respected(self, app):
        user_id = _create_user(app, tier="pro", manual_override=True)

        from services.loans import get_user_subscription_tier

        with app.app_context():
            assert get_user_subscription_tier(user_id) == "pro"

    def test_nonexistent_user_returns_free(self, app):
        from services.loans import get_user_subscription_tier

        with app.app_context():
            assert get_user_subscription_tier(99999) == "free"


# ─── Loan limit tests ────────────────────────────────────────────────────


class TestLoanLimits:
    """Tests for check_loan_limit() enforcement."""

    def test_free_user_limited_to_3(self, app):
        """Free tier users cannot create more than 3 loans."""
        from services.loans import check_loan_limit

        user_id = _create_user(app, tier="free")

        # Insert 3 loans
        conn = sqlite3.connect(app.config["DATABASE"])
        c = conn.cursor()
        for i in range(3):
            c.execute("""
                INSERT INTO loans (user_id, borrower, amount, date_borrowed, created_at)
                VALUES (?, ?, 100, '2026-01-01', datetime('now'))
            """, (user_id, f"Borrower {i}"))
        conn.commit()
        conn.close()

        with app.app_context():
            current, max_loans, can_create = check_loan_limit(user_id)
            assert current == 3
            assert max_loans == 3
            assert can_create is False

    def test_free_user_under_limit_can_create(self, app):
        """Free tier users with <3 loans can create more."""
        from services.loans import check_loan_limit

        user_id = _create_user(app, tier="free")

        with app.app_context():
            current, max_loans, can_create = check_loan_limit(user_id)
            assert current == 0
            assert max_loans == 3
            assert can_create is True

    def test_basic_user_can_exceed_3(self, app):
        """Basic tier users can have more than 3 loans."""
        from services.loans import check_loan_limit

        user_id = _create_user(app, tier="basic")

        # Insert 4 loans (exceeds free limit)
        conn = sqlite3.connect(app.config["DATABASE"])
        c = conn.cursor()
        for i in range(4):
            c.execute("""
                INSERT INTO loans (user_id, borrower, amount, date_borrowed, created_at)
                VALUES (?, ?, 100, '2026-01-01', datetime('now'))
            """, (user_id, f"Borrower {i}"))
        conn.commit()
        conn.close()

        with app.app_context():
            current, max_loans, can_create = check_loan_limit(user_id)
            assert current == 4
            assert max_loans == 25
            assert can_create is True

    def test_pro_user_unlimited(self, app):
        """Pro tier users have no loan limit (max_loans is None)."""
        from services.loans import check_loan_limit

        user_id = _create_user(app, tier="pro")

        # Insert many loans
        conn = sqlite3.connect(app.config["DATABASE"])
        c = conn.cursor()
        for i in range(10):
            c.execute("""
                INSERT INTO loans (user_id, borrower, amount, date_borrowed, created_at)
                VALUES (?, ?, 100, '2026-01-01', datetime('now'))
            """, (user_id, f"Borrower {i}"))
        conn.commit()
        conn.close()

        with app.app_context():
            current, max_loans, can_create = check_loan_limit(user_id)
            assert current == 10
            assert max_loans is None
            assert can_create is True

    def test_null_tier_falls_back_to_free_limit(self, app):
        """BUG FIX: NULL tier should be treated as free (3 loan limit)."""
        from services.loans import check_loan_limit

        user_id = _create_user(app, tier="free")

        # Set tier to NULL
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.execute("UPDATE users SET subscription_tier = NULL WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        with app.app_context():
            current, max_loans, can_create = check_loan_limit(user_id)
            assert max_loans == 3, f"NULL tier should limit to 3, got {max_loans}"


# ─── Webhook tests ────────────────────────────────────────────────────────


class TestWebhookHandling:
    """Tests for Stripe webhook event processing."""

    def _post_webhook(self, app, event_type, data_object):
        """Post a fake webhook event (bypassing Stripe signature for tests).

        Uses a plain FlaskClient to avoid CSRFClient interference with
        the raw JSON body that Stripe webhooks send.
        """
        from flask.testing import FlaskClient

        event = {
            "id": "evt_test_123",
            "type": event_type,
            "data": {"object": data_object},
        }
        # Temporarily restore plain FlaskClient (conftest sets CSRFClient on the
        # singleton app, which corrupts raw JSON POST bodies).
        saved_cls = app.test_client_class
        app.test_client_class = FlaskClient
        try:
            with app.test_client() as raw_client:
                with patch("stripe.Webhook.construct_event", return_value=event):
                    return raw_client.post(
                        "/webhooks/stripe",
                        data=json.dumps(event),
                        content_type="application/json",
                        headers={"Stripe-Signature": "test_sig"},
                    )
        finally:
            app.test_client_class = saved_cls

    def test_checkout_completed_sets_tier(self, app):
        """checkout.session.completed should set user tier and create subscription row."""
        user_id = _create_user(app, tier="free")

        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": "whsec_test",
                                        "STRIPE_SECRET_KEY": "sk_test"}):
            resp = self._post_webhook(app, "checkout.session.completed", {
                "id": "cs_test_123",
                "customer": "cus_test_456",
                "subscription": "sub_test_789",
                "metadata": {"user_id": str(user_id), "tier": "basic"},
            })

        assert resp.status_code == 200
        assert _get_user_tier(app, user_id) == "basic"

        # Verify subscription record was created
        conn = sqlite3.connect(app.config["DATABASE"])
        c = conn.cursor()
        c.execute("SELECT tier, status FROM user_subscriptions WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "basic"
        assert row[1] == "trialing"

    def test_checkout_completed_idempotent(self, app):
        """Duplicate checkout.session.completed should not fail."""
        user_id = _create_user(app, tier="free")

        webhook_data = {
            "id": "cs_test_123",
            "customer": "cus_test_456",
            "subscription": "sub_test_789",
            "metadata": {"user_id": str(user_id), "tier": "basic"},
        }

        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": "whsec_test",
                                        "STRIPE_SECRET_KEY": "sk_test"}):
            resp1 = self._post_webhook(app, "checkout.session.completed", webhook_data)
            resp2 = self._post_webhook(app, "checkout.session.completed", webhook_data)

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert _get_user_tier(app, user_id) == "basic"

    def test_subscription_updated_active_sets_tier(self, app):
        """customer.subscription.updated with status=active should set tier."""
        user_id = _create_user(app, tier="free")
        _create_subscription(app, user_id, tier="basic", status="trialing",
                              stripe_sub_id="sub_test_active")

        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": "whsec_test",
                                        "STRIPE_SECRET_KEY": "sk_test"}):
            resp = self._post_webhook(app, "customer.subscription.updated", {
                "id": "sub_test_active",
                "status": "active",
                "customer": "cus_test",
                "items": {"data": [{
                    "current_period_start": 1738368000,
                    "current_period_end": 1740960000,
                    "price": {"id": "price_test", "recurring": {"interval": "month", "interval_count": 1}},
                }]},
                "cancel_at_period_end": False,
                "metadata": {"user_id": str(user_id), "tier": "basic"},
            })

        assert resp.status_code == 200
        assert _get_user_tier(app, user_id) == "basic"

    def test_subscription_updated_missing_row_creates_it(self, app):
        """If user_subscriptions row is missing, subscription.updated should create it from metadata."""
        user_id = _create_user(app, tier="free")

        # No subscription row exists — simulates checkout webhook failure
        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": "whsec_test",
                                        "STRIPE_SECRET_KEY": "sk_test"}):
            resp = self._post_webhook(app, "customer.subscription.updated", {
                "id": "sub_missing_row",
                "status": "active",
                "customer": "cus_test",
                "items": {"data": [{
                    "current_period_start": 1738368000,
                    "current_period_end": 1740960000,
                    "price": {"id": "price_test", "recurring": {"interval": "month", "interval_count": 1}},
                }]},
                "cancel_at_period_end": False,
                "metadata": {"user_id": str(user_id), "tier": "basic"},
            })

        assert resp.status_code == 200
        assert _get_user_tier(app, user_id) == "basic"

        # Verify row was created
        conn = sqlite3.connect(app.config["DATABASE"])
        c = conn.cursor()
        c.execute("SELECT tier FROM user_subscriptions WHERE stripe_subscription_id = ?",
                  ("sub_missing_row",))
        row = c.fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "basic"

    def test_subscription_deleted_downgrades_to_free(self, app):
        """customer.subscription.deleted should downgrade user to free tier."""
        user_id = _create_user(app, tier="basic")
        _create_subscription(app, user_id, tier="basic", status="active",
                              stripe_sub_id="sub_to_delete")

        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": "whsec_test",
                                        "STRIPE_SECRET_KEY": "sk_test"}):
            resp = self._post_webhook(app, "customer.subscription.deleted", {
                "id": "sub_to_delete",
                "customer": "cus_test",
            })

        assert resp.status_code == 200
        assert _get_user_tier(app, user_id) == "free"

    def test_subscription_deleted_respects_manual_override(self, app):
        """Deleting subscription should NOT downgrade manual_override users."""
        user_id = _create_user(app, tier="pro", manual_override=True)
        _create_subscription(app, user_id, tier="pro", status="active",
                              stripe_sub_id="sub_override_del")

        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": "whsec_test",
                                        "STRIPE_SECRET_KEY": "sk_test"}):
            resp = self._post_webhook(app, "customer.subscription.deleted", {
                "id": "sub_override_del",
                "customer": "cus_test",
            })

        assert resp.status_code == 200
        # Should still be pro because of manual_override
        assert _get_user_tier(app, user_id) == "pro"

    def test_invoice_payment_succeeded_sets_active(self, app):
        """invoice.payment_succeeded should set subscription to active and update tier."""
        user_id = _create_user(app, tier="free")
        _create_subscription(app, user_id, tier="basic", status="trialing",
                              stripe_sub_id="sub_pay_success")

        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": "whsec_test",
                                        "STRIPE_SECRET_KEY": "sk_test"}):
            resp = self._post_webhook(app, "invoice.payment_succeeded", {
                "id": "in_test_123",
                "subscription": "sub_pay_success",
            })

        assert resp.status_code == 200
        assert _get_user_tier(app, user_id) == "basic"

        # Verify status is now active
        conn = sqlite3.connect(app.config["DATABASE"])
        c = conn.cursor()
        c.execute("SELECT status FROM user_subscriptions WHERE stripe_subscription_id = ?",
                  ("sub_pay_success",))
        row = c.fetchone()
        conn.close()
        assert row[0] == "active"

    def test_invoice_payment_failed_sets_past_due(self, app):
        """invoice.payment_failed should mark subscription as past_due."""
        user_id = _create_user(app, tier="basic")
        _create_subscription(app, user_id, tier="basic", status="active",
                              stripe_sub_id="sub_pay_fail")

        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": "whsec_test",
                                        "STRIPE_SECRET_KEY": "sk_test"}):
            resp = self._post_webhook(app, "invoice.payment_failed", {
                "id": "in_fail_123",
                "subscription": "sub_pay_fail",
            })

        assert resp.status_code == 200

        conn = sqlite3.connect(app.config["DATABASE"])
        c = conn.cursor()
        c.execute("SELECT status FROM user_subscriptions WHERE stripe_subscription_id = ?",
                  ("sub_pay_fail",))
        row = c.fetchone()
        conn.close()
        assert row[0] == "past_due"
