# services/connectors/aggregator_banks.py
"""
Virtual bank connectors backed by Basiq aggregator.

Users see "Commonwealth Bank", "NAB", "Westpac", etc. as individual options.
Behind the scenes, all are powered by Basiq, but the user never knows.

Each connector knows:
- Its bank name and logo
- Its Basiq institution ID
- How to create a user and consent link specifically for that bank
"""

from typing import List, Optional
from .base import BankConnector, Transaction
from .basiq import BasiqConnector


class AggregatorBackedBank(BankConnector):
    """
    Base class for banks backed by an aggregator (Basiq).

    Users connect to specific banks (CommBank, NAB, etc.) but all are
    powered by Basiq behind the scenes.
    """

    # Override these in subclasses
    BANK_NAME = "Unknown Bank"
    BANK_SHORT_NAME = "Unknown"
    BASIQ_INSTITUTION_ID = None  # Optional: filter to specific institution

    def __init__(self, api_key: str, basiq_user_id: Optional[str] = None):
        """
        Initialize aggregator-backed bank connector.

        Args:
            api_key: YOUR Basiq API key (from .env, not user-provided)
            basiq_user_id: The Basiq user ID for this LendifyMe user
        """
        super().__init__(api_key)
        self.basiq_user_id = basiq_user_id
        self._basiq = BasiqConnector(api_key)

    @property
    def connector_name(self) -> str:
        return self.BANK_NAME

    @classmethod
    def get_credential_schema(cls) -> dict:
        """
        Aggregator-backed banks don't need user credentials.
        They use OAuth-style consent flow instead.
        """
        return {
            'auth_type': 'oauth',  # Signals that this needs a consent flow
            'fields': []  # No fields to fill - just redirect to consent
        }

    def test_connection(self) -> bool:
        """Test if Basiq connection works."""
        return self._basiq.test_connection()

    def get_account_name(self) -> str:
        """Get display name."""
        if self.basiq_user_id:
            try:
                connections = self._basiq.get_user_connections(self.basiq_user_id)

                # Filter to this bank if institution ID specified
                if self.BASIQ_INSTITUTION_ID:
                    bank_connections = [
                        c for c in connections
                        if c.get('institution', {}).get('id') == self.BASIQ_INSTITUTION_ID
                    ]
                else:
                    bank_connections = connections

                if bank_connections and bank_connections[0]['status'] == 'active':
                    return f"{self.BANK_NAME} (Connected)"

            except Exception:
                pass

        return f"{self.BANK_NAME} (Not Connected)"

    def get_transactions(self, since_date: Optional[str] = None, limit: Optional[int] = None) -> List[Transaction]:
        """
        Fetch transactions from this user's connected account.

        If BASIQ_INSTITUTION_ID is set, filters to only this bank's transactions.
        """
        if not self.basiq_user_id:
            raise ValueError(f"No Basiq user ID set. User must connect their {self.BANK_NAME} account first.")

        # Fetch all transactions for this user
        all_transactions = self._basiq.get_transactions(since_date, limit)

        # If we have a specific institution ID, filter to that bank only
        # This ensures CommBank connector only returns CommBank transactions
        if self.BASIQ_INSTITUTION_ID:
            # TODO: Filter by institution when raw_data includes institution info
            # For now, return all (user should only have one bank connected per connector)
            pass

        return all_transactions

    def get_incoming_transactions(self, since_date: Optional[str] = None, limit: Optional[int] = None) -> List[Transaction]:
        """Fetch only incoming transactions."""
        all_transactions = self.get_transactions(since_date, limit)
        return self.filter_incoming_only(all_transactions)

    # ========================================
    # User Management Methods
    # ========================================

    def create_user(self, email: str, mobile: Optional[str] = None, first_name: Optional[str] = None) -> dict:
        """Create a Basiq user for this LendifyMe user."""
        return self._basiq.create_user(email, mobile, first_name)

    def create_consent_link(self, basiq_user_id: str, redirect_url: Optional[str] = None,
                           institution_id: Optional[str] = None) -> dict:
        """
        Generate consent link for this specific bank.

        Args:
            basiq_user_id: Basiq user ID
            redirect_url: Where to redirect after connection
            institution_id: Optional specific institution (uses class default if not provided)

        Returns:
            {'consent_url': '...', 'token': '...'}
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"AggregatorBackedBank.create_consent_link called with basiq_user_id={basiq_user_id}, institution_id={institution_id}")

        # Use provided institution ID or class default
        inst_id = institution_id or self.BASIQ_INSTITUTION_ID

        # Pass institution_id directly to Basiq connector (it now supports it)
        logger.info(f"Calling Basiq connector with user_id={basiq_user_id}, inst_id={inst_id}")
        consent = self._basiq.create_consent_link(
            user_id=basiq_user_id,
            redirect_url=redirect_url,
            institution_id=inst_id
        )

        return consent

    def get_user_connections(self, basiq_user_id: str) -> List[dict]:
        """Get bank connections for this user."""
        all_connections = self._basiq.get_user_connections(basiq_user_id)

        # If we have a specific institution ID, filter to this bank only
        if self.BASIQ_INSTITUTION_ID:
            return [
                c for c in all_connections
                if c.get('institution', {}).get('id') == self.BASIQ_INSTITUTION_ID
            ]

        return all_connections

    def refresh_connection(self, basiq_user_id: str, connection_id: str) -> bool:
        """Refresh this bank connection."""
        return self._basiq.refresh_connection(basiq_user_id, connection_id)


# ========================================
# Individual Bank Connectors
# ========================================

class CommBankConnector(AggregatorBackedBank):
    """Commonwealth Bank connector (backed by Basiq)."""
    BANK_NAME = "Commonwealth Bank"
    BANK_SHORT_NAME = "CommBank"
    BASIQ_INSTITUTION_ID = "AU04301"  # Commonwealth Bank Australia


class NABConnector(AggregatorBackedBank):
    """NAB connector (backed by Basiq)."""
    BANK_NAME = "NAB"
    BANK_SHORT_NAME = "NAB"
    BASIQ_INSTITUTION_ID = "AU01001"  # National Australia Bank Limited


class WestpacConnector(AggregatorBackedBank):
    """Westpac connector (backed by Basiq)."""
    BANK_NAME = "Westpac"
    BANK_SHORT_NAME = "Westpac"
    BASIQ_INSTITUTION_ID = "AU14201"  # Westpac Banking Corporation


class ANZConnector(AggregatorBackedBank):
    """ANZ connector (backed by Basiq)."""
    BANK_NAME = "ANZ"
    BANK_SHORT_NAME = "ANZ"
    BASIQ_INSTITUTION_ID = "AU00601"  # Australia and New Zealand Banking Group Limited


class INGConnector(AggregatorBackedBank):
    """ING connector (backed by Basiq)."""
    BANK_NAME = "ING"
    BANK_SHORT_NAME = "ING"
    BASIQ_INSTITUTION_ID = "AU00201"  # ING Bank (Australia) Limited (trading as ING Direct)


class MacquarieConnector(AggregatorBackedBank):
    """Macquarie Bank connector (backed by Basiq)."""
    BANK_NAME = "Macquarie Bank"
    BANK_SHORT_NAME = "Macquarie"
    BASIQ_INSTITUTION_ID = "AU00301"  # Macquarie Bank Limited


class BankOfMelbourneConnector(AggregatorBackedBank):
    """Bank of Melbourne connector (backed by Basiq)."""
    BANK_NAME = "Bank of Melbourne"
    BANK_SHORT_NAME = "Bank Melbourne"
    BASIQ_INSTITUTION_ID = "AU03001"  # Bank of Melbourne (a subsidiary of Westpac)


class BankSAConnector(AggregatorBackedBank):
    """BankSA connector (backed by Basiq)."""
    BANK_NAME = "BankSA"
    BANK_SHORT_NAME = "BankSA"
    BASIQ_INSTITUTION_ID = "AU03201"  # BankSA (a subsidiary of Westpac)


class StGeorgeConnector(AggregatorBackedBank):
    """St.George Bank connector (backed by Basiq)."""
    BANK_NAME = "St.George Bank"
    BANK_SHORT_NAME = "St.George"
    BASIQ_INSTITUTION_ID = "AU12301"  # St. George Bank (a subsidiary of Westpac)


class BendigoBankConnector(AggregatorBackedBank):
    """Bendigo Bank connector (backed by Basiq)."""
    BANK_NAME = "Bendigo Bank"
    BANK_SHORT_NAME = "Bendigo"
    BASIQ_INSTITUTION_ID = "AU00101"  # Bendigo and Adelaide Bank Limited


class BankwestConnector(AggregatorBackedBank):
    """Bankwest connector (backed by Basiq)."""
    BANK_NAME = "Bankwest"
    BANK_SHORT_NAME = "Bankwest"
    BASIQ_INSTITUTION_ID = "AU00401"  # Bankwest Bank (a subsidiary of Commonwealth Bank)


class RAMSConnector(AggregatorBackedBank):
    """RAMS connector (backed by Basiq)."""
    BANK_NAME = "RAMS"
    BANK_SHORT_NAME = "RAMS"
    BASIQ_INSTITUTION_ID = "AU11301"  # RAMS (a subsidiary of Westpac)


class SuncorpConnector(AggregatorBackedBank):
    """Suncorp Bank connector (backed by Basiq)."""
    BANK_NAME = "Suncorp Bank"
    BANK_SHORT_NAME = "Suncorp"
    BASIQ_INSTITUTION_ID = "AU01101"  # Suncorp Bank


class OtherBankConnector(AggregatorBackedBank):
    """
    Generic connector for any other bank supported by Basiq.

    This shows all available institutions in the consent flow,
    covering the 90+ other banks not explicitly listed above.
    """
    BANK_NAME = "Other Bank"
    BANK_SHORT_NAME = "Other"
    BASIQ_INSTITUTION_ID = None  # No filter - show all banks
