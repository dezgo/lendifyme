# services/connectors/csv_connector.py
from typing import List, Optional
from .base import BankConnector, Transaction
from ..transaction_matcher import parse_csv_transactions


class CSVConnector(BankConnector):
    """Connector for CSV file uploads (manual transaction import)."""

    def __init__(self, csv_content: str):
        """
        Initialize CSV connector with CSV content.

        Args:
            csv_content: Raw CSV string content
        """
        # CSV doesn't need API key, but parent requires it
        super().__init__(api_key="")
        self.csv_content = csv_content

    @property
    def connector_name(self) -> str:
        return "CSV Upload"

    @classmethod
    def get_credential_schema(cls) -> dict:
        """Get credential schema for CSV (no credentials needed)."""
        return {
            'auth_type': 'none',
            'fields': []
        }

    def test_connection(self) -> bool:
        """CSV always 'connects' successfully if content is provided."""
        return bool(self.csv_content)

    def get_account_name(self) -> str:
        """Return generic name for CSV uploads."""
        return "Manual CSV Import"

    def get_transactions(self, since_date: Optional[str] = None, limit: Optional[int] = None) -> List[Transaction]:
        """
        Parse transactions from CSV content.

        Args:
            since_date: Optional date filter (applied after parsing)
            limit: Optional limit on number of transactions

        Returns:
            List of Transaction objects
        """
        # Parse CSV using existing parser
        parsed_transactions = parse_csv_transactions(self.csv_content)

        # Convert to Transaction objects
        transactions = []
        for t in parsed_transactions:
            transaction = Transaction(
                date=t['date'],
                description=t['description'],
                amount=t['amount'],
                raw_data=t
            )
            transactions.append(transaction)

        # Apply date filter if specified
        if since_date:
            transactions = [t for t in transactions if t.date >= since_date]

        # Apply limit if specified
        if limit:
            transactions = transactions[:limit]

        return transactions
