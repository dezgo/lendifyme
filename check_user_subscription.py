#!/usr/bin/env python3
"""
Check a specific user's subscription data and Stripe status.

Usage: python check_user_subscription.py <email>
"""
import sqlite3
import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def check_user(email):
    """Check user's subscription data."""
    conn = sqlite3.connect('lendifyme.db')
    c = conn.cursor()

    print(f"\n{'='*80}")
    print(f"Checking subscription data for: {email}")
    print(f"{'='*80}\n")

    # Get user data
    c.execute("""
        SELECT id, email, name, subscription_tier, stripe_customer_id,
               manual_override, trial_ends_at, created_at, email_verified
        FROM users
        WHERE email = ?
    """, (email,))
    user = c.fetchone()

    if not user:
        print(f"❌ User not found: {email}")
        conn.close()
        return

    user_id, email, name, tier, stripe_customer_id, manual_override, trial_ends_at, created_at, verified = user

    print("👤 USER DATA:")
    print(f"   ID: {user_id}")
    print(f"   Email: {email}")
    print(f"   Name: {name or 'N/A'}")
    print(f"   Current Tier: {tier}")
    print(f"   Stripe Customer ID: {stripe_customer_id or 'NONE'}")
    print(f"   Manual Override: {manual_override}")
    print(f"   Trial Ends: {trial_ends_at or 'N/A'}")
    print(f"   Email Verified: {verified}")
    print(f"   Created: {created_at}")
    print()

    # Get subscription records
    c.execute("""
        SELECT id, stripe_subscription_id, stripe_customer_id, tier, status,
               current_period_start, current_period_end, cancel_at_period_end,
               created_at, updated_at
        FROM user_subscriptions
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,))
    subs = c.fetchall()

    print(f"💳 SUBSCRIPTION RECORDS: {len(subs)}")
    if subs:
        for i, sub in enumerate(subs, 1):
            print(f"\n   Subscription #{i}:")
            print(f"   - Record ID: {sub[0]}")
            print(f"   - Stripe Subscription ID: {sub[1]}")
            print(f"   - Stripe Customer ID: {sub[2]}")
            print(f"   - Tier: {sub[3]}")
            print(f"   - Status: {sub[4]}")
            print(f"   - Period: {sub[5]} to {sub[6]}")
            print(f"   - Cancel at Period End: {sub[7]}")
            print(f"   - Created: {sub[8]}, Updated: {sub[9]}")
    else:
        print("   ⚠️  NO SUBSCRIPTION RECORDS FOUND!")
        print("   This means checkout.session.completed webhook likely didn't fire or failed.")
    print()

    # Check recent events for this user
    c.execute("""
        SELECT event_name, created_at, event_data
        FROM events
        WHERE user_id = ?
          AND (event_name LIKE '%subscription%' OR event_name LIKE '%checkout%')
        ORDER BY created_at DESC
        LIMIT 5
    """, (user_id,))
    events = c.fetchall()

    print(f"📊 RECENT SUBSCRIPTION EVENTS: {len(events)}")
    if events:
        import json
        for event in events:
            print(f"   - {event[0]} at {event[1]}")
            if event[2]:
                try:
                    data = json.loads(event[2])
                    print(f"     Data: {data}")
                except:
                    pass
    else:
        print("   ℹ️  No subscription events logged for this user")
    print()

    # If they have a Stripe customer ID, suggest checking Stripe
    if stripe_customer_id:
        print("🔍 NEXT STEPS:")
        print(f"   1. Check Stripe dashboard for customer: {stripe_customer_id}")
        print(f"   2. Look for active subscriptions under this customer")
        print(f"   3. Check webhook delivery logs in Stripe for this customer")
        print(f"   4. If subscription exists in Stripe but not in DB, manually create it")
    else:
        print("⚠️  PROBLEM:")
        print("   User has no Stripe Customer ID!")
        print("   This means the checkout flow didn't complete properly.")
        print("   Check if they actually completed payment in Stripe.")

    conn.close()
    print(f"\n{'='*80}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_user_subscription.py <email>")
        sys.exit(1)

    email = sys.argv[1]
    check_user(email)
