#!/usr/bin/env python3
"""Fetch trial end date from Stripe and update database."""
import sqlite3
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Import Stripe
try:
    import stripe
    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
except ImportError:
    print("❌ Stripe library not found. Run: pip install stripe")
    exit(1)

conn = sqlite3.connect('lendifyme.db')
c = conn.cursor()

# Find users with subscriptions but no trial_ends_at
c.execute("""
    SELECT u.id, u.email, us.stripe_subscription_id
    FROM users u
    JOIN user_subscriptions us ON u.id = us.user_id
    WHERE u.trial_ends_at IS NULL
    AND us.status IN ('trialing', 'active')
""")

users = c.fetchall()

if not users:
    print("✅ All users with active subscriptions have trial_ends_at set!")
else:
    print(f"Found {len(users)} user(s) with missing trial_ends_at")

    for user_id, email, subscription_id in users:
        print(f"\n📝 Processing user {user_id} ({email})...")

        try:
            # Fetch subscription from Stripe
            sub = stripe.Subscription.retrieve(subscription_id)

            if sub.get('trial_end'):
                trial_end_timestamp = sub['trial_end']
                trial_end_date = datetime.fromtimestamp(trial_end_timestamp).isoformat()

                # Update database
                c.execute("UPDATE users SET trial_ends_at = ? WHERE id = ?",
                         (trial_end_date, user_id))
                conn.commit()

                print(f"   ✅ Updated trial_ends_at to: {trial_end_date}")
            else:
                print(f"   ⚠️  Subscription has no trial_end (might not be in trial)")

        except Exception as e:
            print(f"   ❌ Error: {e}")

conn.close()
print("\n✅ Done!")
