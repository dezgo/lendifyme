# services/connectors/base.py
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from datetime import datetime


class Transaction:
    """Represents a standardized transaction."""

    def __init__(self, date: str, description: str, amount: float, raw_data: Optional[Dict] = None):
        """
        Args:
            date: Transaction date in YYYY-MM-DD format
            description: Transaction description/memo
            amount: Transaction amount (positive for incoming, negative for outgoing)
            raw_data: Original raw transaction data from the bank API
        """
        self.date = date
        self.description = description
        self.amount = amount
        self.raw_data = raw_data or {}

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        return {
            'date': self.date,
            'description': self.description,
            'amount': self.amount,
            'raw_data': self.raw_data
        }


class BankConnector(ABC):
    """Abstract base class for bank API connectors."""

    def __init__(self, api_key: str):
        """
        Initialize connector with API credentials.

        Args:
            api_key: API key/token for authentication
        """
        self.api_key = api_key

    @abstractmethod
    def get_transactions(self, since_date: Optional[str] = None, limit: Optional[int] = None) -> List[Transaction]:
        """
        Fetch transactions from the bank API.

        Args:
            since_date: Optional date to fetch transactions from (YYYY-MM-DD format)
            limit: Optional limit on number of transactions to fetch

        Returns:
            List of Transaction objects

        Raises:
            ConnectionError: If API connection fails
            ValueError: If authentication fails
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test if the API connection is working.

        Returns:
            True if connection successful, False otherwise
        """
        pass

    @abstractmethod
    def get_account_name(self) -> str:
        """
        Get a human-readable account identifier.

        Returns:
            Account name or identifier
        """
        pass

    @property
    @abstractmethod
    def connector_name(self) -> str:
        """
        Get the name of this connector.

        Returns:
            Connector name (e.g., "Up Bank", "Commonwealth Bank")
        """
        pass

    def filter_incoming_only(self, transactions: List[Transaction]) -> List[Transaction]:
        """
        Filter transactions to only include incoming payments (positive amounts).

        Args:
            transactions: List of transactions

        Returns:
            List of transactions with positive amounts only
        """
        return [t for t in transactions if t.amount > 0]
