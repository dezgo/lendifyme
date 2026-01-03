#!/usr/bin/env python3
"""
Repair missing subscription records by fetching data from Stripe.

For users who paid but have no subscription record in the database,
this script fetches their subscription from Stripe and creates the
missing database record.

Usage: python repair_missing_subscription.py <email> [--dry-run]
"""
import sqlite3
import sys
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def repair_subscription(email, dry_run=False):
    """Repair missing subscription for a user."""
    import stripe

    # Load Stripe API key from environment
    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
    if not stripe.api_key:
        print("❌ STRIPE_SECRET_KEY not set in environment!")
        print("   Set it with: export STRIPE_SECRET_KEY='sk_...'")
        return

    conn = sqlite3.connect('lendifyme.db')
    c = conn.cursor()

    print(f"\n{'='*80}")
    print(f"Repairing subscription for: {email}")
    if dry_run:
        print("🔍 DRY RUN MODE - No changes will be made")
    print(f"{'='*80}\n")

    # Get user data
    c.execute("""
        SELECT id, email, subscription_tier, stripe_customer_id
        FROM users
        WHERE email = ?
    """, (email,))
    user = c.fetchone()

    if not user:
        print(f"❌ User not found: {email}")
        conn.close()
        return

    user_id, email, current_tier, stripe_customer_id = user

    print("👤 USER DATA:")
    print(f"   ID: {user_id}")
    print(f"   Email: {email}")
    print(f"   Current Tier: {current_tier}")
    print(f"   Stripe Customer ID: {stripe_customer_id}")
    print()

    if not stripe_customer_id:
        print("❌ User has no Stripe Customer ID - cannot fetch subscription")
        conn.close()
        return

    # Check if subscription record already exists
    c.execute("""
        SELECT COUNT(*) FROM user_subscriptions
        WHERE user_id = ? AND status IN ('active', 'trialing')
    """, (user_id,))
    existing_count = c.fetchone()[0]

    if existing_count > 0:
        print("✅ User already has an active subscription record - nothing to repair")
        conn.close()
        return

    print("🔍 Fetching subscriptions from Stripe...")
    try:
        # Fetch all subscriptions for this customer
        subscriptions = stripe.Subscription.list(
            customer=stripe_customer_id,
            status='all',
            limit=10
        )

        if not subscriptions.data:
            print("❌ No subscriptions found in Stripe for this customer")
            print("   The customer exists but has no subscription. Payment may have failed.")
            conn.close()
            return

        print(f"\n📋 Found {len(subscriptions.data)} subscription(s) in Stripe:\n")

        active_sub = None
        for i, sub in enumerate(subscriptions.data, 1):
            print(f"   Subscription #{i}:")
            print(f"   - ID: {sub['id']}")
            print(f"   - Status: {sub['status']}")
            print(f"   - Created: {datetime.fromtimestamp(sub['created'])}")

            # Access items list
            items = sub.get('items', {}).get('data', [])
            if items:
                item = items[0]
                price = item.get('price', {})
                price_id = price.get('id')
                amount = price.get('unit_amount', 0) / 100
                interval = price.get('recurring', {}).get('interval', 'unknown')
                print(f"   - Price: ${amount}/{interval} (ID: {price_id})")

            metadata = sub.get('metadata', {})
            if metadata:
                print(f"   - Metadata: {dict(metadata)}")

            print()

            # Use the first active or trialing subscription
            if sub['status'] in ['active', 'trialing'] and not active_sub:
                active_sub = sub

        if not active_sub:
            print("⚠️  No active or trialing subscription found")
            print("   All subscriptions are canceled or expired")
            conn.close()
            return

        print(f"✅ Will use subscription: {active_sub['id']} (status: {active_sub['status']})")
        print()

        # Determine tier from metadata or price ID
        metadata = active_sub.get('metadata', {})
        tier = metadata.get('tier') if metadata else None

        if not tier:
            # Try to determine tier from price ID by checking env vars
            items = active_sub.get('items', {}).get('data', [])
            if items:
                price = items[0].get('price', {})
                price_id = price.get('id')
                if price_id == os.getenv('STRIPE_PRICE_ID_BASIC_MONTHLY') or price_id == os.getenv('STRIPE_PRICE_ID_BASIC_YEARLY'):
                    tier = 'basic'
                elif price_id == os.getenv('STRIPE_PRICE_ID_PRO_MONTHLY') or price_id == os.getenv('STRIPE_PRICE_ID_PRO_YEARLY'):
                    tier = 'pro'
                else:
                    print(f"⚠️  Cannot determine tier from price ID: {price_id}")
                    print("   Please specify tier manually or check .env file")
                    conn.close()
                    return
            else:
                print(f"⚠️  Cannot determine tier - no items in subscription")
                conn.close()
                return

        print(f"💾 Creating subscription record:")
        print(f"   - User ID: {user_id}")
        print(f"   - Stripe Subscription ID: {active_sub['id']}")
        print(f"   - Stripe Customer ID: {stripe_customer_id}")
        print(f"   - Tier: {tier}")
        print(f"   - Status: {active_sub['status']}")
        print(f"   - Period: {datetime.fromtimestamp(active_sub['current_period_start'])} to {datetime.fromtimestamp(active_sub['current_period_end'])}")
        print()

        if not dry_run:
            # Create the missing subscription record
            c.execute("""
                INSERT INTO user_subscriptions
                (user_id, stripe_subscription_id, stripe_customer_id, tier, status,
                 current_period_start, current_period_end, cancel_at_period_end,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (
                user_id,
                active_sub['id'],
                stripe_customer_id,
                tier,
                active_sub['status'],
                datetime.fromtimestamp(active_sub['current_period_start']).isoformat(),
                datetime.fromtimestamp(active_sub['current_period_end']).isoformat(),
                active_sub.get('cancel_at_period_end', False)
            ))

            # Update user's tier
            c.execute("""
                UPDATE users
                SET subscription_tier = ?
                WHERE id = ?
            """, (tier, user_id))

            conn.commit()

            print("✅ Subscription record created successfully!")
            print(f"✅ User tier updated from '{current_tier}' to '{tier}'")
            print()
            print("🎉 Repair complete! User should now see the correct tier.")
        else:
            print("🔍 DRY RUN - No changes made. Run without --dry-run to apply.")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

    print(f"\n{'='*80}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python repair_missing_subscription.py <email> [--dry-run]")
        sys.exit(1)

    email = sys.argv[1]
    dry_run = "--dry-run" in sys.argv

    repair_subscription(email, dry_run)
