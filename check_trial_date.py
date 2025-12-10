#!/usr/bin/env python3
"""Check if trial_ends_at is set for users with subscriptions."""
import sqlite3

conn = sqlite3.connect('lendifyme.db')
c = conn.cursor()

print("=" * 80)
print("USERS WITH SUBSCRIPTIONS:")
print("=" * 80)

c.execute("""
    SELECT
        u.id,
        u.email,
        u.subscription_tier,
        u.trial_ends_at,
        us.status,
        us.tier,
        us.stripe_subscription_id
    FROM users u
    LEFT JOIN user_subscriptions us ON u.id = us.user_id
    WHERE u.subscription_tier != 'free' OR us.id IS NOT NULL
    ORDER BY u.id DESC
""")

users = c.fetchall()

if not users:
    print("No subscribed users found")
else:
    for user_id, email, sub_tier, trial_ends, us_status, us_tier, stripe_id in users:
        print(f"\nUser #{user_id}: {email}")
        print(f"  Subscription Tier: {sub_tier}")
        print(f"  Trial Ends At: {trial_ends if trial_ends else 'NOT SET ❌'}")
        if us_status:
            print(f"  Subscription Status: {us_status}")
            print(f"  Subscription Tier: {us_tier}")
            print(f"  Stripe ID: {stripe_id}")

conn.close()
