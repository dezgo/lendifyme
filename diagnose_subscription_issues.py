#!/usr/bin/env python3
"""
Comprehensive diagnostic script for subscription issues.

This script checks for various subscription problems:
1. Users with paid subscriptions but wrong tier in users table
2. Users with Stripe customer ID but no subscription record
3. Users with 'trialing' status that should be 'active'
4. Recent payment events from Stripe

Usage: python diagnose_subscription_issues.py
"""
import sqlite3
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def diagnose_subscriptions():
    """Run comprehensive subscription diagnostics."""
    conn = sqlite3.connect('lendifyme.db')
    c = conn.cursor()

    print("=" * 80)
    print("SUBSCRIPTION DIAGNOSTICS")
    print("=" * 80)
    print()

    # Check 1: Users with active subscriptions but wrong tier
    print("1️⃣  Checking for mismatched tiers (paid subscription but showing as free)...")
    c.execute("""
        SELECT u.id, u.email, u.subscription_tier, u.stripe_customer_id,
               us.tier, us.status, us.created_at, us.stripe_subscription_id
        FROM users u
        JOIN user_subscriptions us ON u.id = us.user_id
        WHERE us.status IN ('active', 'trialing')
          AND u.subscription_tier != us.tier
          AND (u.manual_override IS NULL OR u.manual_override = 0)
    """)
    mismatched = c.fetchall()

    if mismatched:
        print(f"   ⚠️  Found {len(mismatched)} user(s) with mismatched tiers:\n")
        for row in mismatched:
            print(f"      User ID: {row[0]}, Email: {row[1]}")
            print(f"      Users table tier: '{row[2]}' (WRONG)")
            print(f"      Subscription tier: '{row[4]}' (CORRECT)")
            print(f"      Status: {row[5]}, Created: {row[6]}")
            print(f"      Stripe Sub ID: {row[7]}")
            print()
    else:
        print("   ✅ No mismatched tiers found\n")

    # Check 2: Users with Stripe customer ID but no active subscription record
    print("2️⃣  Checking for users with Stripe customer but no subscription record...")
    c.execute("""
        SELECT u.id, u.email, u.subscription_tier, u.stripe_customer_id,
               COUNT(us.id) as sub_count
        FROM users u
        LEFT JOIN user_subscriptions us ON u.id = us.user_id
            AND us.status IN ('active', 'trialing')
        WHERE u.stripe_customer_id IS NOT NULL
          AND u.subscription_tier != 'free'
        GROUP BY u.id
        HAVING sub_count = 0
    """)
    missing_subs = c.fetchall()

    if missing_subs:
        print(f"   ⚠️  Found {len(missing_subs)} user(s) with Stripe customer but no active subscription:\n")
        for row in missing_subs:
            print(f"      User ID: {row[0]}, Email: {row[1]}")
            print(f"      Tier: {row[2]}, Stripe Customer: {row[3]}")
            print()
    else:
        print("   ✅ No orphaned Stripe customers found\n")

    # Check 3: All users with non-free tiers (to see the full picture)
    print("3️⃣  Checking ALL users with non-free tiers...")
    c.execute("""
        SELECT u.id, u.email, u.subscription_tier, u.manual_override,
               u.stripe_customer_id, u.trial_ends_at, u.created_at
        FROM users u
        WHERE u.subscription_tier != 'free'
        ORDER BY u.created_at DESC
        LIMIT 20
    """)
    paid_users = c.fetchall()

    if paid_users:
        print(f"   Found {len(paid_users)} user(s) with non-free tiers:\n")
        for row in paid_users:
            print(f"      User ID: {row[0]}, Email: {row[1]}")
            print(f"      Tier: {row[2]}, Manual Override: {row[3]}")
            print(f"      Stripe Customer: {row[4] or 'None'}")
            print(f"      Trial Ends: {row[5] or 'N/A'}, Created: {row[6]}")

            # Check their subscription records
            c.execute("""
                SELECT tier, status, created_at, stripe_subscription_id
                FROM user_subscriptions
                WHERE user_id = ?
                ORDER BY created_at DESC
            """, (row[0],))
            subs = c.fetchall()

            if subs:
                print(f"      Subscription records: {len(subs)}")
                for sub in subs:
                    print(f"        - Tier: {sub[0]}, Status: {sub[1]}, Created: {sub[2]}")
                    print(f"          Stripe Sub ID: {sub[3]}")
            else:
                print(f"      ⚠️  NO subscription records found!")
            print()
    else:
        print("   ℹ️  No users with paid tiers found\n")

    # Check 4: Recent subscription events
    print("4️⃣  Checking recent subscription-related events...")
    c.execute("""
        SELECT event_name, created_at, user_id, event_data
        FROM events
        WHERE event_name LIKE '%subscription%'
           OR event_name LIKE '%checkout%'
        ORDER BY created_at DESC
        LIMIT 10
    """)
    events = c.fetchall()

    if events:
        print(f"   Found {len(events)} recent subscription events:\n")
        for row in events:
            print(f"      Event: {row[0]}, Time: {row[1]}, User ID: {row[2]}")
            if row[3]:
                import json
                try:
                    data = json.loads(row[3])
                    print(f"      Data: {data}")
                except:
                    print(f"      Data: {row[3]}")
            print()
    else:
        print("   ℹ️  No recent subscription events found\n")

    # Check 5: All subscription records (to see what we have)
    print("5️⃣  Checking ALL subscription records...")
    c.execute("""
        SELECT user_id, tier, status, created_at, stripe_subscription_id,
               current_period_start, current_period_end
        FROM user_subscriptions
        ORDER BY created_at DESC
        LIMIT 20
    """)
    all_subs = c.fetchall()

    if all_subs:
        print(f"   Found {len(all_subs)} subscription record(s):\n")
        for row in all_subs:
            print(f"      User ID: {row[0]}, Tier: {row[1]}, Status: {row[2]}")
            print(f"      Created: {row[3]}")
            print(f"      Stripe Sub ID: {row[4]}")
            print(f"      Period: {row[5]} to {row[6]}")
            print()
    else:
        print("   ⚠️  NO subscription records found at all!\n")

    conn.close()

    print("=" * 80)
    print("DIAGNOSIS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    diagnose_subscriptions()
