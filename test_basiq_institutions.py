#!/usr/bin/env python3
"""
Test script to fetch available institutions from Basiq API.
This will help us get the correct institution IDs for each bank.
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from services.connectors.basiq import BasiqConnector

def main():
    api_key = os.getenv('BASIQ_API_KEY')

    if not api_key:
        print("ERROR: BASIQ_API_KEY not found in .env file")
        return

    print("Fetching institutions from Basiq API...")
    print("=" * 80)

    try:
        connector = BasiqConnector(api_key)

        # First, let's see the raw API response
        print("\nFetching raw API response...\n")
        import requests
        token = connector._get_access_token()
        response = requests.get(
            f"{connector.BASE_URL}/institutions",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "basiq-version": connector.API_VERSION
            },
            timeout=15
        )
        raw_data = response.json()

        print("RAW API RESPONSE (first institution):")
        print("-" * 80)
        if raw_data.get('data') and len(raw_data['data']) > 0:
            import json
            print(json.dumps(raw_data['data'][0], indent=2))
        print("\n")

        institutions = connector.get_available_institutions()

        print(f"\nFound {len(institutions)} institutions:\n")

        # Filter to major banks (tier 1) first
        major_banks = [i for i in institutions if i['tier'] == 1]
        other_banks = [i for i in institutions if i['tier'] != 1]

        print("MAJOR BANKS (Tier 1):")
        print("-" * 80)
        for inst in major_banks:
            print(f"ID: {inst['id']:15} | {inst['name']:40} | Status: {inst['service_status']}")

        print("\n\nOTHER BANKS:")
        print("-" * 80)
        for inst in other_banks[:20]:  # Show first 20
            print(f"ID: {inst['id']:15} | {inst['name']:40} | Tier: {inst['tier']} | Status: {inst['service_status']}")

        if len(other_banks) > 20:
            print(f"\n... and {len(other_banks) - 20} more banks")

        # Look for specific banks we're using
        print("\n\nBANKS WE'RE USING IN LENDIFYME:")
        print("-" * 80)
        target_banks = [
            "Commonwealth Bank", "NAB", "Westpac", "ANZ", "ING",
            "Macquarie", "Bank of Melbourne", "BankSA", "St.George", "Bendigo Bank"
        ]

        for target in target_banks:
            matches = [i for i in institutions if target.lower() in i['name'].lower()]
            if matches:
                for match in matches:
                    print(f"{target:20} -> ID: {match['id']:15} | Full name: {match['name']}")
            else:
                print(f"{target:20} -> NOT FOUND")

    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
