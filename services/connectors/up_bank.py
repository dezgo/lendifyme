# services/connectors/up_bank.py
import requests
import logging
from typing import List, Optional
from datetime import datetime, timedelta
from .base import BankConnector, Transaction

logger = logging.getLogger(__name__)


class UpBankConnector(BankConnector):
    """Connector for Up Bank API."""

    BASE_URL = "https://api.up.com.au/api/v1"

    @property
    def connector_name(self) -> str:
        return "Up Bank"

    def _get_headers(self) -> dict:
        """Get authorization headers for API requests."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def test_connection(self) -> bool:
        """Test connection by pinging the API."""
        try:
            response = requests.get(
                f"{self.BASE_URL}/util/ping",
                headers=self._get_headers(),
                timeout=10
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    def get_account_name(self) -> str:
        """Get account display name from Up Bank."""
        try:
            response = requests.get(
                f"{self.BASE_URL}/accounts",
                headers=self._get_headers(),
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data.get("data") and len(data["data"]) > 0:
                # Return first account name
                account = data["data"][0]
                return account.get("attributes", {}).get("displayName", "Up Bank Account")

            return "Up Bank Account"
        except requests.RequestException:
            return "Up Bank Account"

    def _fetch_transactions_for_range(self, since_date: str, until_date: Optional[str] = None, page_limit: int = 100) -> List[Transaction]:
        """
        Fetch transactions for a specific date range with pagination.

        Args:
            since_date: Start date in YYYY-MM-DD format
            until_date: Optional end date in YYYY-MM-DD format
            page_limit: Number of results per page

        Returns:
            List of Transaction objects for this date range
        """
        transactions = []
        url = f"{self.BASE_URL}/transactions"

        # Build query parameters
        params = {
            "filter[since]": f"{since_date}T00:00:00Z",
            "page[size]": page_limit
        }

        if until_date:
            params["filter[until]"] = f"{until_date}T23:59:59Z"

        try:
            while url:
                response = requests.get(
                    url,
                    headers=self._get_headers(),
                    params=params if url == f"{self.BASE_URL}/transactions" else None,
                    timeout=15
                )

                if response.status_code == 401:
                    raise ValueError("Authentication failed. Check your Up Bank API key.")

                response.raise_for_status()
                data = response.json()

                # Parse transactions from response
                for item in data.get("data", []):
                    attributes = item.get("attributes", {})

                    # Extract transaction details
                    description = attributes.get("description", "")
                    amount_data = attributes.get("amount", {})
                    amount = float(amount_data.get("valueInBaseUnits", 0)) / 100  # Convert cents to dollars

                    # Parse date (ISO 8601 to YYYY-MM-DD)
                    created_at = attributes.get("createdAt", "")
                    transaction_date = created_at.split("T")[0] if created_at else ""

                    # Create transaction object
                    transaction = Transaction(
                        date=transaction_date,
                        description=description,
                        amount=amount,
                        raw_data=item
                    )
                    transactions.append(transaction)

                # Check for next page
                url = data.get("links", {}).get("next")
                params = None  # Don't pass params for paginated URLs

            return transactions

        except requests.exceptions.Timeout:
            raise ConnectionError("Request to Up Bank API timed out")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to connect to Up Bank API: {str(e)}")

    def get_transactions(self, since_date: Optional[str] = None, limit: Optional[int] = None) -> List[Transaction]:
        """
        Fetch transactions from Up Bank API.

        To work around API pagination limits, this fetches transactions in 3-month chunks
        and combines the results.

        Args:
            since_date: Optional date in YYYY-MM-DD format to fetch transactions from
            limit: Optional limit on number of transactions

        Returns:
            List of Transaction objects

        Raises:
            ConnectionError: If API connection fails
            ValueError: If authentication fails
        """
        # Determine start date
        if since_date:
            start_date = datetime.strptime(since_date, "%Y-%m-%d")
        else:
            # Default to last 30 days if no date specified
            start_date = datetime.now() - timedelta(days=30)

        # End date is always now
        end_date = datetime.now()

        # Break into 3-month chunks to work around API limits
        all_transactions = []
        chunk_start = start_date

        while chunk_start < end_date:
            # Calculate chunk end (3 months from start)
            chunk_end = chunk_start + timedelta(days=90)
            if chunk_end > end_date:
                chunk_end = end_date

            # Fetch transactions for this chunk
            chunk_start_str = chunk_start.strftime("%Y-%m-%d")
            chunk_end_str = chunk_end.strftime("%Y-%m-%d")

            chunk_transactions = self._fetch_transactions_for_range(
                since_date=chunk_start_str,
                until_date=chunk_end_str
            )

            all_transactions.extend(chunk_transactions)

            # Move to next chunk
            chunk_start = chunk_end + timedelta(days=1)

            # If we have a limit and reached it, stop
            if limit and len(all_transactions) >= limit:
                all_transactions = all_transactions[:limit]
                break

        # Sort by date (newest first)
        all_transactions.sort(key=lambda t: t.date, reverse=True)

        return all_transactions

    def get_incoming_transactions(self, since_date: Optional[str] = None, limit: Optional[int] = None) -> List[Transaction]:
        """
        Fetch only incoming transactions (positive amounts).

        Args:
            since_date: Optional date in YYYY-MM-DD format
            limit: Optional limit on number of transactions

        Returns:
            List of incoming Transaction objects
        """
        all_transactions = self.get_transactions(since_date, limit)
        return self.filter_incoming_only(all_transactions)
