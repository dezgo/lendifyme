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
    """Handle successful checkout."""
    session_id = request.args.get('session_id')

    if not session_id:
        flash("Invalid checkout session", "error")
        return redirect("/")

    flash("Subscription activated! Welcome to your new plan.", "success")
    log_event('subscription_activated')

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

            if user_id and tier:
                # Update user's subscription tier
                c.execute("""
                    UPDATE users
                    SET subscription_tier = ?, stripe_customer_id = ?
                    WHERE id = ?
                """, (tier, customer_id, user_id))

                # Create subscription record
                c.execute("""
                    INSERT INTO user_subscriptions
                    (user_id, stripe_subscription_id, stripe_customer_id, tier, status, created_at)
                    VALUES (?, ?, ?, ?, 'trialing', CURRENT_TIMESTAMP)
                """, (user_id, subscription_id, customer_id, tier))

                conn.commit()
                app.logger.info(f"Subscription created for user {user_id}: {tier}")

        elif event_type == 'customer.subscription.updated':
            # Subscription status changed
            subscription = data_object
            subscription_id = subscription['id']
            status = subscription['status']
            current_period_start = datetime.fromtimestamp(subscription['current_period_start']).isoformat()
            current_period_end = datetime.fromtimestamp(subscription['current_period_end']).isoformat()
            cancel_at_period_end = subscription.get('cancel_at_period_end', False)

            # Update subscription record
            c.execute("""
                UPDATE user_subscriptions
                SET status = ?,
                    current_period_start = ?,
                    current_period_end = ?,
                    cancel_at_period_end = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE stripe_subscription_id = ?
            """, (status, current_period_start, current_period_end, cancel_at_period_end, subscription_id))

            # If subscription becomes active, update user tier
            if status == 'active':
                c.execute("""
                    UPDATE users
                    SET subscription_tier = (
                        SELECT tier FROM user_subscriptions
                        WHERE stripe_subscription_id = ?
                    )
                    WHERE id = (
                        SELECT user_id FROM user_subscriptions
                        WHERE stripe_subscription_id = ?
                    )
                """, (subscription_id, subscription_id))

            conn.commit()
            app.logger.info(f"Subscription {subscription_id} updated: {status}")

        elif event_type == 'customer.subscription.deleted':
            # Subscription cancelled or ended
            subscription = data_object
            subscription_id = subscription['id']

            # Get user_id before deleting
            c.execute("SELECT user_id FROM user_subscriptions WHERE stripe_subscription_id = ?", (subscription_id,))
            result = c.fetchone()

            if result:
                user_id = result[0]

                # Downgrade user to free tier
                c.execute("UPDATE users SET subscription_tier = 'free' WHERE id = ?", (user_id,))

                # Update subscription status
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = 'canceled',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))

                conn.commit()
                app.logger.info(f"Subscription {subscription_id} cancelled, user {user_id} downgraded to free")

        elif event_type == 'invoice.payment_succeeded':
            # Successful payment
            invoice = data_object
            subscription_id = invoice.get('subscription')

            if subscription_id:
                c.execute("""
                    UPDATE user_subscriptions
                    SET status = 'active',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))
                conn.commit()
                app.logger.info(f"Payment succeeded for subscription {subscription_id}")

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
