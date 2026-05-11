"""
Stripe webhook event handlers.

Each handler takes (conn, data_object, logger) and mutates the DB. The dispatcher
in `routes/subscription.py:stripe_webhook` wraps the whole flow in a single
connection with rollback-on-error semantics.

Adding a new event type:
    1. Write a handler function with the (conn, data, logger) signature.
    2. Register it in HANDLERS at the bottom of this file.
"""
import os
from datetime import datetime, timedelta


def _tier_from_subscription_items(items):
    """Determine tier from Stripe subscription items by matching price IDs."""
    if not items:
        return 'basic'  # safe default for paid
    price_id = items[0].get('price', {}).get('id', '')
    if price_id in (
        os.getenv('STRIPE_PRICE_ID_PRO_MONTHLY', ''),
        os.getenv('STRIPE_PRICE_ID_PRO_YEARLY', ''),
    ):
        return 'pro'
    return 'basic'


def _compute_billing_period(subscription, items):
    """
    Stripe deprecated current_period_* on subscription in API v2025-03-31 — they
    now live on subscription items. Pulls the dates from there with a chain of
    fallbacks for missing data.

    Returns (period_start_iso, period_end_iso, cancel_at_period_end).
    """
    period_start = None
    period_end = None

    if items and items[0].get('current_period_start'):
        period_start = items[0]['current_period_start']
        period_end = items[0]['current_period_end']

    if not period_start:
        period_start = subscription.get('start_date') or subscription.get('created')

    if not period_end:
        period_end = subscription.get('cancel_at')
        if not period_end and items:
            price = items[0].get('price', {})
            interval = price.get('recurring', {}).get('interval')
            interval_count = price.get('recurring', {}).get('interval_count', 1)
            if interval and period_start:
                start_dt = datetime.fromtimestamp(period_start)
                if interval == 'month':
                    end_dt = start_dt + timedelta(days=30 * interval_count)
                elif interval == 'year':
                    end_dt = start_dt + timedelta(days=365 * interval_count)
                elif interval == 'week':
                    end_dt = start_dt + timedelta(weeks=interval_count)
                elif interval == 'day':
                    end_dt = start_dt + timedelta(days=interval_count)
                else:
                    end_dt = start_dt + timedelta(days=30)
                period_end = int(end_dt.timestamp())
        if not period_end:
            anchor = subscription.get('billing_cycle_anchor')
            if anchor:
                period_end = anchor + (30 * 86400)
            else:
                period_end = period_start + (30 * 86400) if period_start else None

    period_start_iso = datetime.fromtimestamp(period_start).isoformat() if period_start else None
    period_end_iso = datetime.fromtimestamp(period_end).isoformat() if period_end else None
    cancel_at_period_end = subscription.get('cancel_at_period_end', False)

    return period_start_iso, period_end_iso, cancel_at_period_end


def handle_checkout_session_completed(conn, data, logger):
    """Payment successful, subscription created (or re-activated)."""
    session = data
    customer_id = session.get('customer')
    subscription_id = session.get('subscription')
    metadata = session.get('metadata', {})
    user_id = metadata.get('user_id')
    tier = metadata.get('tier')

    logger.info(
        "checkout.session.completed: user_id=%s tier=%s customer=%s sub=%s",
        user_id, tier, customer_id, subscription_id,
    )

    if not user_id or not tier:
        logger.error(
            f"checkout.session.completed missing metadata: user_id={user_id}, "
            f"tier={tier}, session_id={session.get('id')}"
        )
        return

    c = conn.cursor()

    c.execute(
        "UPDATE users SET subscription_tier = ?, stripe_customer_id = ? WHERE id = ?",
        (tier, customer_id, user_id),
    )

    # Idempotent upsert: safe if webhook fires twice
    c.execute("""
        INSERT INTO user_subscriptions
        (user_id, stripe_subscription_id, stripe_customer_id, tier, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'trialing', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(stripe_subscription_id) DO UPDATE SET
            tier = excluded.tier,
            status = CASE WHEN user_subscriptions.status = 'canceled'
                          THEN excluded.status
                          ELSE user_subscriptions.status END,
            updated_at = CURRENT_TIMESTAMP
    """, (user_id, subscription_id, customer_id, tier))

    conn.commit()
    logger.info(f"Subscription created/updated for user {user_id}: {tier}")


def handle_subscription_updated(conn, data, logger):
    """Subscription status / billing period changed."""
    subscription = data
    subscription_id = subscription['id']
    status = subscription['status']

    logger.info(
        "customer.subscription.updated: sub=%s status=%s",
        subscription_id, status,
    )

    items = subscription.get('items', {}).get('data', [])
    period_start_iso, period_end_iso, cancel_at_period_end = _compute_billing_period(subscription, items)

    logger.info(
        "  period: %s to %s, cancel_at_period_end=%s",
        period_start_iso, period_end_iso, cancel_at_period_end,
    )

    metadata = subscription.get('metadata', {})
    meta_user_id = metadata.get('user_id')
    meta_tier = metadata.get('tier')
    customer_id = subscription.get('customer')

    c = conn.cursor()

    # Locate an existing user_subscriptions row, or create one if upstream events were missed
    c.execute(
        "SELECT user_id, tier FROM user_subscriptions WHERE stripe_subscription_id = ?",
        (subscription_id,),
    )
    existing = c.fetchone()

    if existing:
        c.execute("""
            UPDATE user_subscriptions
            SET status = ?,
                current_period_start = ?,
                current_period_end = ?,
                cancel_at_period_end = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE stripe_subscription_id = ?
        """, (status, period_start_iso, period_end_iso, cancel_at_period_end, subscription_id))
        sub_user_id, sub_tier = existing
    elif meta_user_id and meta_tier:
        logger.warning(
            "user_subscriptions row missing for sub %s, creating from metadata",
            subscription_id,
        )
        c.execute("""
            INSERT INTO user_subscriptions
            (user_id, stripe_subscription_id, stripe_customer_id, tier, status,
             current_period_start, current_period_end, cancel_at_period_end,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (meta_user_id, subscription_id, customer_id, meta_tier, status,
              period_start_iso, period_end_iso, cancel_at_period_end))
        sub_user_id, sub_tier = meta_user_id, meta_tier
    else:
        # No row and no metadata — try to find user by Stripe customer ID
        c.execute("SELECT id FROM users WHERE stripe_customer_id = ?", (customer_id,))
        user_row = c.fetchone()
        if user_row:
            logger.warning(
                "Creating user_subscriptions from customer lookup for sub %s",
                subscription_id,
            )
            tier_from_price = _tier_from_subscription_items(items)
            c.execute("""
                INSERT INTO user_subscriptions
                (user_id, stripe_subscription_id, stripe_customer_id, tier, status,
                 current_period_start, current_period_end, cancel_at_period_end,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (user_row[0], subscription_id, customer_id,
                  tier_from_price, status,
                  period_start_iso, period_end_iso, cancel_at_period_end))
            sub_user_id, sub_tier = user_row[0], tier_from_price
        else:
            logger.error(
                "Cannot find user for subscription %s (customer %s), skipping tier update",
                subscription_id, customer_id,
            )
            sub_user_id, sub_tier = None, None

    if status == 'active' and sub_user_id and sub_tier:
        c.execute(
            "UPDATE users SET subscription_tier = ? WHERE id = ?",
            (sub_tier, sub_user_id),
        )

    conn.commit()
    logger.info(f"Subscription {subscription_id} updated: {status}")


def handle_subscription_deleted(conn, data, logger):
    """Subscription cancelled or ended — downgrade unless manual_override is set."""
    subscription = data
    subscription_id = subscription['id']
    customer_id = subscription.get('customer')

    logger.info(
        "customer.subscription.deleted: sub=%s customer=%s",
        subscription_id, customer_id,
    )

    c = conn.cursor()

    c.execute(
        "SELECT user_id FROM user_subscriptions WHERE stripe_subscription_id = ?",
        (subscription_id,),
    )
    result = c.fetchone()

    if not result and customer_id:
        c.execute("SELECT id FROM users WHERE stripe_customer_id = ?", (customer_id,))
        result = c.fetchone()

    if not result:
        logger.warning(
            "customer.subscription.deleted: cannot find user for sub %s",
            subscription_id,
        )
        return

    user_id = result[0]

    c.execute("SELECT manual_override FROM users WHERE id = ?", (user_id,))
    override = c.fetchone()
    if override and override[0]:
        logger.info("Skipping downgrade for user %s — manual_override is set", user_id)
    else:
        c.execute("UPDATE users SET subscription_tier = 'free' WHERE id = ?", (user_id,))
        logger.info(f"User {user_id} downgraded to free")

    c.execute("""
        UPDATE user_subscriptions
        SET status = 'canceled',
            updated_at = CURRENT_TIMESTAMP
        WHERE stripe_subscription_id = ?
    """, (subscription_id,))

    conn.commit()
    logger.info(f"Subscription {subscription_id} cancelled")


def handle_invoice_payment_succeeded(conn, data, logger):
    """Safety net: ensure subscription is 'active' and user tier matches."""
    invoice = data
    subscription_id = invoice.get('subscription')

    logger.info(
        "invoice.payment_succeeded: sub=%s invoice=%s",
        subscription_id, invoice.get('id'),
    )

    if not subscription_id:
        return

    c = conn.cursor()

    c.execute("""
        UPDATE user_subscriptions
        SET status = 'active',
            updated_at = CURRENT_TIMESTAMP
        WHERE stripe_subscription_id = ?
    """, (subscription_id,))

    c.execute(
        "SELECT user_id, tier FROM user_subscriptions WHERE stripe_subscription_id = ?",
        (subscription_id,),
    )
    sub_row = c.fetchone()
    if sub_row and sub_row[0] and sub_row[1]:
        c.execute(
            "UPDATE users SET subscription_tier = ? WHERE id = ?",
            (sub_row[1], sub_row[0]),
        )
        logger.info("Payment succeeded: user %s tier set to %s", sub_row[0], sub_row[1])
    else:
        logger.warning(
            "invoice.payment_succeeded: no user_subscriptions row for sub %s, "
            "cannot update user tier",
            subscription_id,
        )

    conn.commit()


def handle_invoice_payment_failed(conn, data, logger):
    """Mark subscription past_due."""
    invoice = data
    subscription_id = invoice.get('subscription')

    if not subscription_id:
        return

    c = conn.cursor()
    c.execute("""
        UPDATE user_subscriptions
        SET status = 'past_due',
            updated_at = CURRENT_TIMESTAMP
        WHERE stripe_subscription_id = ?
    """, (subscription_id,))
    conn.commit()
    logger.warning(f"Payment failed for subscription {subscription_id}")


HANDLERS = {
    'checkout.session.completed': handle_checkout_session_completed,
    'customer.subscription.updated': handle_subscription_updated,
    'customer.subscription.deleted': handle_subscription_deleted,
    'invoice.payment_succeeded': handle_invoice_payment_succeeded,
    'invoice.payment_failed': handle_invoice_payment_failed,
}


def dispatch(event_type, conn, data, logger):
    """Run the handler for `event_type` against `conn`. No-op for unknown types."""
    handler = HANDLERS.get(event_type)
    if handler:
        handler(conn, data, logger)
    else:
        logger.info(f"Unhandled Stripe webhook event: {event_type}")
