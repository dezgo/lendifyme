#!/usr/bin/env python3
"""
Fix subscription tiers for users who have active subscriptions but incorrect tier in users table.

This script identifies users where:
- user_subscriptions.status is 'active' or 'trialing'
- user_subscriptions.tier doesn't match users.subscription_tier
- manual_override is not set

It then updates the users table to match the subscription tier.

Usage: python fix_subscription_tiers.py [--dry-run]
"""
import sqlite3
import sys


def fix_subscription_tiers(dry_run=False):
    """Fix mismatched subscription tiers."""
    conn = sqlite3.connect('lendifyme.db')
    c = conn.cursor()

    # Find users with active subscriptions but mismatched tiers
    c.execute("""
        SELECT u.id, u.email, u.subscription_tier as current_tier,
               us.tier as should_be_tier, us.status, us.stripe_subscription_id
        FROM users u
        JOIN user_subscriptions us ON u.id = us.user_id
        WHERE us.status IN ('active', 'trialing')
          AND u.subscription_tier != us.tier
          AND (u.manual_override IS NULL OR u.manual_override = 0)
    """)

    mismatched_users = c.fetchall()

    if not mismatched_users:
        print("✅ No mismatched subscription tiers found. All users are correctly set up!")
        conn.close()
        return

    print(f"Found {len(mismatched_users)} user(s) with mismatched subscription tiers:\n")

    for user_id, email, current_tier, should_be_tier, status, sub_id in mismatched_users:
        print(f"  User ID: {user_id}")
        print(f"  Email: {email}")
        print(f"  Current tier in users table: {current_tier}")
        print(f"  Subscription tier (paid): {should_be_tier}")
        print(f"  Subscription status: {status}")
        print(f"  Stripe subscription ID: {sub_id}")
        print()

        if not dry_run:
            # Update the user's tier to match their active subscription
            c.execute("""
                UPDATE users
                SET subscription_tier = ?
                WHERE id = ?
            """, (should_be_tier, user_id))
            print(f"  ✅ Updated {email} from '{current_tier}' to '{should_be_tier}'")
            print()

    if dry_run:
        print("\n🔍 DRY RUN - No changes were made. Run without --dry-run to apply fixes.")
    else:
        conn.commit()
        print(f"\n✅ Successfully updated {len(mismatched_users)} user(s)!")

    conn.close()


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv
    if dry_run:
        print("🔍 Running in DRY RUN mode (no changes will be made)\n")

    fix_subscription_tiers(dry_run=dry_run)
