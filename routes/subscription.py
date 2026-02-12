"""
Subscription routes - pricing, billing, Stripe integration, webhooks.
"""
from flask import Blueprint, render_template, request, session, redirect, flash, current_app as app
from helpers.decorators import login_required, get_current_user_id
from helpers.db import get_db_connection
from services.loans import get_user_subscription_tier, check_loan_limit
from datetime import datetime, timedelta
import json
import os


def _tier_from_subscription_items(items):
    """Determine tier from Stripe subscription items by matching price IDs."""
    if not items:
        return 'basic'  # safe default for paid
    price_id = items[0].get('price', {}).get('id', '')
    if price_id in (os.getenv('STRIPE_PRICE_ID_PRO_MONTHLY', ''),
                    os.getenv('STRIPE_PRICE_ID_PRO_YEARLY', '')):
        return 'pro'
    return 'basic'


def log_event(event_name, event_data=None, user_id=None):
    """Log an event to the events table."""
    if user_id is None:
        user_id = get_current_user_id()

    conn = get_db_connection()
    c = conn.cursor()

    event_data_json = json.dumps(event_data) if event_data else '{}'

    c.execute("""
        INSERT INTO events (user_id, event_name, event_data, created_at)
        VALUES (?, ?, ?, datetime('now'))
    """, (user_id, event_name, event_data_json))

    conn.commit()
    conn.close()


# Create blueprint (no prefix - routes are at root level)
subscription_bp = Blueprint('subscription', __name__)


@subscription_bp.route("/pricing")
def pricing():
    """Display pricing tiers and subscription options."""
    conn = get_db_connection()
    c = conn.cursor()

    # Get all subscription plans
    c.execute("""
        SELECT tier, name, price_monthly, price_yearly, max_loans, features_json
        FROM subscription_plans
        WHERE active = 1
        ORDER BY price_monthly ASC
    """)
    plan_rows = c.fetchall()
    conn.close()

    # Convert to dicts
    plans = []
    for row in plan_rows:
        tier, name, price_monthly, price_yearly, max_loans, features_json = row
        features = json.loads(features_json)
        plans.append({
            'tier': tier,
            'name': name,
            'price_monthly': price_monthly / 100 if price_monthly else 0,  # Convert cents to dollars
            'price_yearly': price_yearly / 100 if price_yearly else 0,
            'max_loans': max_loans,
            'features': features
        })

    # Get current user's tier if logged in
    current_tier = None
    current_loans = 0
    manual_override = False
    if 'user_id' in session:
        current_tier = get_user_subscription_tier()
        current_loans, _, _ = check_loan_limit()

        # Check if user has manual override (admin-granted)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT manual_override FROM users WHERE id = ?", (get_current_user_id(),))
        result = c.fetchone()
        manual_override = result[0] if result else False
        conn.close()

    return render_template("pricing.html",
                         plans=plans,
                         current_tier=current_tier,
                         current_loans=current_loans,
                         manual_override=manual_override)


@subscription_bp.route("/subscribe/<tier>")
@login_required
def subscribe(tier):
    """Create Stripe checkout session for subscription."""
    import stripe

    # Validate tier
    if tier not in ['basic', 'pro']:
        flash("Invalid subscription tier", "error")
        return redirect("/pricing")

    # Get billing cycle (monthly or yearly)
    billing_cycle = request.args.get('billing', 'monthly')
    if billing_cycle not in ['monthly', 'yearly']:
        billing_cycle = 'monthly'

    # Check if user already has this tier or higher
    current_tier = get_user_subscription_tier()
    tier_hierarchy = {'free': 0, 'basic': 1, 'pro': 2}
    if tier_hierarchy.get(current_tier, 0) >= tier_hierarchy.get(tier, 0):
        flash(f"You already have {current_tier.title()} plan access", "error")
        return redirect("/pricing")

    # Get or create Stripe customer
    user_id = get_current_user_id()
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT stripe_customer_id, email FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    stripe_customer_id, user_email = result

    # Initialize Stripe
    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

    if not stripe.api_key:
        flash("Stripe is not configured. Please contact support.", "error")
        conn.close()
        return redirect("/pricing")

    try:
        # Create or retrieve Stripe customer
        if not stripe_customer_id:
            customer = stripe.Customer.create(
                email=user_email,
                metadata={'user_id': user_id}
            )
            stripe_customer_id = customer.id

            # Save customer ID
            c.execute("UPDATE users SET stripe_customer_id = ? WHERE id = ?",
                     (stripe_customer_id, user_id))
            conn.commit()

        # Get price ID from environment based on billing cycle
        price_id_key = f'STRIPE_PRICE_ID_{tier.upper()}_{billing_cycle.upper()}'
        price_id = os.getenv(price_id_key)

        if not price_id:
            flash(f"Pricing not configured for {tier.title()} plan ({billing_cycle}). Please contact support.", "error")
            conn.close()
            return redirect("/pricing")

        # Set trial end date (14 days from now)
        trial_end = int((datetime.now() + timedelta(days=14)).timestamp())

        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=stripe_customer_id,
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{app.config['APP_URL']}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{app.config['APP_URL']}/pricing",
            subscription_data={
                'trial_period_days': 14,
                'metadata': {
                    'user_id': user_id,
                    'tier': tier,
                    'billing_cycle': billing_cycle
                }
            },
            metadata={
                'user_id': user_id,
                'tier': tier,
                'billing_cycle': billing_cycle
            }
        )

        # Store trial start in database
        trial_ends_at = (datetime.now() + timedelta(days=14)).isoformat()
        c.execute("UPDATE users SET trial_ends_at = ? WHERE id = ?",
                 (trial_ends_at, user_id))
        conn.commit()
        conn.close()

        # Log analytics event
        log_event('subscription_checkout_started', event_data={'tier': tier, 'billing_cycle': billing_cycle})

        # Redirect to Stripe Checkout
        return redirect(checkout_session.url, code=303)

    except Exception as e:
        app.logger.error(f"Subscription error: {e}")
        flash("An error occurred. Please try again.", "error")
        conn.close()
        return redirect("/pricing")


@subscription_bp.route("/checkout/success")
@login_required
def checkout_success():
    """Handle successful checkout.

    This is the return URL after Stripe Checkout.  The webhook may not have
    fired yet (especially on localhost without a tunnel), so we activate the
    subscription directly from the Checkout Session as a reliable fallback.
    """
    import stripe

    session_id = request.args.get('session_id')
    if not session_id:
        flash("Invalid checkout session", "error")
        return redirect("/")

    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
    user_id = get_current_user_id()

    try:
        cs = stripe.checkout.Session.retrieve(session_id)
        metadata = cs.get('metadata', {})
        tier = metadata.get('tier')
        customer_id = cs.get('customer')
        subscription_id = cs.get('subscription')

        if tier and user_id:
            conn = get_db_connection()
            c = conn.cursor()

            # Set the tier immediately (idempotent with webhook)
            c.execute(
                "UPDATE users SET subscription_tier = ?, stripe_customer_id = ? WHERE id = ?",
                (tier, customer_id, user_id),
            )

            # Upsert subscription record (same as webhook handler)
            c.execute("""
                INSERT INTO user_subscriptions
                (user_id, stripe_subscription_id, stripe_customer_id, tier, status,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, 'trialing', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(stripe_subscription_id) DO UPDATE SET
                    tier = excluded.tier,
                    updated_at = CURRENT_TIMESTAMP
            """, (user_id, subscription_id, customer_id, tier))

            conn.commit()
            conn.close()

            app.logger.info(
                "checkout_success: activated tier=%s for user %s (session %s)",
                tier, user_id, session_id,
            )

            flash(f"Subscription activated! Welcome to the {tier.title()} plan.", "success")
        else:
            app.logger.warning(
                "checkout_success: missing tier/user_id in session %s", session_id,
            )
            flash("Subscription activated! Welcome to your new plan.", "success")

    except Exception as e:
        app.logger.error(f"checkout_success: error retrieving session: {e}")
        flash("Subscription activated! Welcome to your new plan.", "success")

    log_event('subscription_activated', event_data={'tier': tier if 'tier' in dir() else None})

    # If we saved a pending loan form before redirecting to pricing, go back to dashboard
    pending = session.pop('pending_loan_form', None)
    if pending:
        # Store in session so the template can pre-fill the form
        session['prefill_loan'] = pending
    return redirect("/")


@subscription_bp.route("/checkout/cancel")
@login_required
def checkout_cancel():
    """Handle cancelled checkout."""
    flash("Checkout cancelled. You can subscribe anytime from the pricing page.", "error")
    return redirect("/pricing")


@subscription_bp.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events."""
    import stripe

    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

    if not webhook_secret:
        app.logger.error("Stripe webhook secret not configured")
        return ('Webhook secret not configured', 400)

    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        app.logger.error("Invalid webhook payload")
        return ('Invalid payload', 400)
    except stripe.SignatureVerificationError:
        app.logger.error("Invalid webhook signature")
        return ('Invalid signature', 400)

    # Handle the event
    event_type = event['type']
    data_object = event['data']['object']

    app.logger.info(f"Received Stripe webhook: {event_type}")

    conn = get_db_connection()
    c = conn.cursor()

    try:
        if event_type == 'checkout.session.completed':
            # Payment successful, subscription created
            session = data_object
            customer_id = session.get('customer')
            subscription_id = session.get('subscription')
            metadata = session.get('metadata', {})
            user_id = metadata.get('user_id')
            tier = metadata.get('tier')

            app.logger.info(
                "checkout.session.completed: user_id=%s tier=%s customer=%s sub=%s",
                user_id, tier, customer_id, subscription_id,
            )

            if user_id and tier:
                # Update user's subscription tier
                c.execute("""
                    UPDATE users
                    SET subscription_tier = ?, stripe_customer_id = ?
                    WHERE id = ?
                """, (tier, customer_id, user_id))

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
                app.logger.info(f"Subscription created/updated for user {user_id}: {tier}")
            else:
                app.logger.error(f"checkout.session.completed missing metadata: user_id={user_id}, tier={tier}, session_id={session.get('id')}")

        elif event_type == 'customer.subscription.updated':
            # Subscription status changed
            subscription = data_object
            subscription_id = subscription['id']
            status = subscription['status']

            app.logger.info(
                "customer.subscription.updated: sub=%s status=%s",
                subscription_id, status,
            )

            # Get billing period - Stripe deprecated current_period_* on subscription
            # in API v2025-03-31; they now live on subscription items.
            period_start = None
            period_end = None

            items = subscription.get('items', {}).get('data', [])
            if items and items[0].get('current_period_start'):
                period_start = items[0]['current_period_start']
                period_end = items[0]['current_period_end']

            # Fallback: compute period from start_date + interval
            if not period_start:
                period_start = subscription.get('start_date') or subscription.get('created')
            if not period_end:
                # Try cancel_at or trial_end as hints, then compute from interval
                period_end = subscription.get('cancel_at')
                if not period_end and items:
                    # Compute from price interval
                    price = items[0].get('price', {}) if items else {}
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
                    # Last resort: billing_cycle_anchor + 30 days
                    anchor = subscription.get('billing_cycle_anchor')
                    if anchor:
                        period_end = anchor + (30 * 86400)
                    else:
                        period_end = period_start + (30 * 86400) if period_start else None

            current_period_start = datetime.fromtimestamp(period_start).isoformat() if period_start else None
            current_period_end = datetime.fromtimestamp(period_end).isoformat() if period_end else None
            cancel_at_period_end = subscription.get('cancel_at_period_end', False)

            app.logger.info(
                "  period: %s to %s, cancel_at_period_end=%s",
                current_period_start, current_period_end, cancel_at_period_end,
            )

            # Upsert subscription record — creates if checkout webhook was missed
            metadata = subscription.get('metadata', {})
            meta_user_id = metadata.get('user_id')
            meta_tier = metadata.get('tier')
            customer_id = subscription.get('customer')

            # Try to find existing row first
            c.execute(
                "SELECT user_id, tier FROM user_subscriptions WHERE stripe_subscription_id = ?",
                (subscription_id,),
            )
            existing = c.fetchone()

            if existing:
                # Normal path: row exists, update it
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = ?,
                        current_period_start = ?,
                        current_period_end = ?,
                        cancel_at_period_end = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (status, current_period_start, current_period_end, cancel_at_period_end, subscription_id))
                sub_user_id, sub_tier = existing
            elif meta_user_id and meta_tier:
                # Row missing (checkout webhook failed) — create it from metadata
                app.logger.warning(
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
                      current_period_start, current_period_end, cancel_at_period_end))
                sub_user_id, sub_tier = meta_user_id, meta_tier
            else:
                # No row and no metadata — try to find user by stripe customer ID
                c.execute(
                    "SELECT id FROM users WHERE stripe_customer_id = ?",
                    (customer_id,),
                )
                user_row = c.fetchone()
                if user_row:
                    app.logger.warning(
                        "Creating user_subscriptions from customer lookup for sub %s",
                        subscription_id,
                    )
                    # Determine tier from price
                    tier_from_price = _tier_from_subscription_items(items)
                    c.execute("""
                        INSERT INTO user_subscriptions
                        (user_id, stripe_subscription_id, stripe_customer_id, tier, status,
                         current_period_start, current_period_end, cancel_at_period_end,
                         created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """, (user_row[0], subscription_id, customer_id,
                          tier_from_price, status,
                          current_period_start, current_period_end, cancel_at_period_end))
                    sub_user_id, sub_tier = user_row[0], tier_from_price
                else:
                    app.logger.error(
                        "Cannot find user for subscription %s (customer %s), skipping tier update",
                        subscription_id, customer_id,
                    )
                    sub_user_id, sub_tier = None, None

            # If subscription becomes active, update user tier (only if we know who they are)
            if status == 'active' and sub_user_id and sub_tier:
                c.execute(
                    "UPDATE users SET subscription_tier = ? WHERE id = ?",
                    (sub_tier, sub_user_id),
                )

            conn.commit()
            app.logger.info(f"Subscription {subscription_id} updated: {status}")

        elif event_type == 'customer.subscription.deleted':
            # Subscription cancelled or ended
            subscription = data_object
            subscription_id = subscription['id']
            customer_id = subscription.get('customer')

            app.logger.info(
                "customer.subscription.deleted: sub=%s customer=%s",
                subscription_id, customer_id,
            )

            # Get user_id from subscription record
            c.execute("SELECT user_id FROM user_subscriptions WHERE stripe_subscription_id = ?", (subscription_id,))
            result = c.fetchone()

            if not result and customer_id:
                # Fallback: find user by Stripe customer ID
                c.execute("SELECT id FROM users WHERE stripe_customer_id = ?", (customer_id,))
                result = c.fetchone()

            if result:
                user_id = result[0]

                # Only downgrade if user doesn't have manual_override
                c.execute("SELECT manual_override FROM users WHERE id = ?", (user_id,))
                override = c.fetchone()
                if override and override[0]:
                    app.logger.info(
                        "Skipping downgrade for user %s — manual_override is set",
                        user_id,
                    )
                else:
                    # Downgrade user to free tier
                    c.execute("UPDATE users SET subscription_tier = 'free' WHERE id = ?", (user_id,))
                    app.logger.info(f"User {user_id} downgraded to free")

                # Update subscription status
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = 'canceled',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))

                conn.commit()
                app.logger.info(f"Subscription {subscription_id} cancelled")
            else:
                app.logger.warning(
                    "customer.subscription.deleted: cannot find user for sub %s",
                    subscription_id,
                )

        elif event_type == 'invoice.payment_succeeded':
            # Successful payment — safety net for tier activation
            invoice = data_object
            subscription_id = invoice.get('subscription')

            app.logger.info(
                "invoice.payment_succeeded: sub=%s invoice=%s",
                subscription_id, invoice.get('id'),
            )

            if subscription_id:
                # Update subscription status to active
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = 'active',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))

                # Safely update user's tier — only if we have a valid row
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
                    app.logger.info(
                        "Payment succeeded: user %s tier set to %s",
                        sub_row[0], sub_row[1],
                    )
                else:
                    app.logger.warning(
                        "invoice.payment_succeeded: no user_subscriptions row for sub %s, "
                        "cannot update user tier",
                        subscription_id,
                    )

                conn.commit()

        elif event_type == 'invoice.payment_failed':
            # Failed payment
            invoice = data_object
            subscription_id = invoice.get('subscription')

            if subscription_id:
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = 'past_due',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))
                conn.commit()
                app.logger.warning(f"Payment failed for subscription {subscription_id}")

        conn.close()
        return ('Success', 200)

    except Exception as e:
        app.logger.error(f"Error processing webhook: {e}")
        conn.rollback()
        conn.close()
        return ('Error processing webhook', 500)


@subscription_bp.route("/billing")
@login_required
def billing():
    """Manage subscription and billing."""
    import stripe

    user_id = get_current_user_id()
    conn = get_db_connection()
    c = conn.cursor()

    # Get user's subscription info
    c.execute("""
        SELECT u.subscription_tier, u.stripe_customer_id, u.manual_override,
               us.stripe_subscription_id, us.status, us.current_period_end,
               us.cancel_at_period_end, sp.price_monthly, sp.price_yearly, sp.features_json
        FROM users u
        LEFT JOIN user_subscriptions us ON u.id = us.user_id AND us.status IN ('active', 'trialing', 'past_due')
        LEFT JOIN subscription_plans sp ON u.subscription_tier = sp.tier
        WHERE u.id = ?
    """, (user_id,))
    result = c.fetchone()

    if not result:
        conn.close()
        flash("User not found", "error")
        return redirect("/")

    tier, stripe_customer_id, manual_override, subscription_id, status, period_end, cancel_at_period_end, price_monthly, price_yearly, features_json = result

    # Get usage stats
    current_loans, max_loans, can_create = check_loan_limit()

    subscription_data = {
        'tier': tier,
        'tier_name': tier.title(),
        'status': status,
        'price_monthly': price_monthly / 100 if price_monthly else 0,
        'price_yearly': price_yearly / 100 if price_yearly else 0,
        'manual_override': manual_override,
        'subscription_id': subscription_id,
        'cancel_at_period_end': cancel_at_period_end,
        'period_end': period_end,
        'current_loans': current_loans,
        'max_loans': max_loans,
        'features': json.loads(features_json) if features_json else {}
    }

    # Create Stripe portal session for managing subscription
    portal_url = None
    if stripe_customer_id and not manual_override:
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
        try:
            portal_session = stripe.billing_portal.Session.create(
                customer=stripe_customer_id,
                return_url=f"{app.config['APP_URL']}/billing"
            )
            portal_url = portal_session.url
        except Exception as e:
            app.logger.error(f"Error creating portal session: {e}")

    conn.close()

    return render_template("billing.html",
                         subscription=subscription_data,
                         portal_url=portal_url)
