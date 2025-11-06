# services/connectors/basiq.py
import requests
import logging
from typing import List, Optional
from datetime import datetime, timedelta
from .base import BankConnector, Transaction
import base64

logger = logging.getLogger(__name__)


class BasiqConnector(BankConnector):
    """
    Connector for Basiq API.

    Basiq is a bank aggregation platform that connects to 100+ Australian financial institutions.
    Unlike direct bank APIs, Basiq works with a "user" model where users connect their bank accounts,
    and you fetch transactions for those users.

    This connector will:
    1. Authenticate with your Basiq API key to get an access token
    2. Fetch all users that have connected their banks
    3. Retrieve transactions from all connected users
    """

    BASE_URL = "https://au-api.basiq.io"
    API_VERSION = "3.0"

    def __init__(self, api_key: str):
        """
        Initialize Basiq connector.

        Args:
            api_key: Basiq API key (get from https://dashboard.basiq.io)
        """
        super().__init__(api_key)
        self._access_token = None
        self._token_expiry = None

    @property
    def connector_name(self) -> str:
        return "Basiq (Multi-Bank)"

    @classmethod
    def get_credential_schema(cls) -> dict:
        """Get credential schema for Basiq."""
        return {
            'auth_type': 'api_key',
            'fields': [
                {
                    'name': 'api_key',
                    'type': 'password',
                    'label': 'API Key',
                    'placeholder': 'Your Basiq API key',
                    'required': True,
                    'help_text': 'Get your API key from https://dashboard.basiq.io'
                }
            ]
        }

    def _get_access_token(self) -> str:
        """
        Authenticate and get access token.

        Basiq uses OAuth 2.0 with client credentials flow.
        Tokens expire after 60 minutes, so we cache and reuse.

        Returns:
            Access token string

        Raises:
            ValueError: If authentication fails
        """
        # Return cached token if still valid
        if self._access_token and self._token_expiry:
            if datetime.now() < self._token_expiry:
                return self._access_token

        # Encode API key as Basic auth
        # Basiq expects: "Basic {base64(api_key:)}"
        auth_string = f"{self.api_key}:"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()

        headers = {
            "Authorization": f"Basic {encoded_auth}",
            "Content-Type": "application/json",
            "basiq-version": self.API_VERSION
        }

        try:
            response = requests.post(
                f"{self.BASE_URL}/token",
                headers=headers,
                json={"scope": "SERVER_ACCESS"},
                timeout=15
            )

            if response.status_code == 401:
                raise ValueError("Authentication failed. Check your Basiq API key.")

            response.raise_for_status()
            data = response.json()

            self._access_token = data.get("access_token")

            # Tokens expire in 60 minutes, cache for 55 to be safe
            self._token_expiry = datetime.now() + timedelta(minutes=55)

            logger.info("Successfully authenticated with Basiq API")
            return self._access_token

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to authenticate with Basiq: {str(e)}")

    def _get_headers(self) -> dict:
        """Get authorization headers for API requests."""
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "basiq-version": self.API_VERSION
        }

    def test_connection(self) -> bool:
        """Test connection by attempting to authenticate."""
        try:
            self._get_access_token()
            return True
        except (ConnectionError, ValueError):
            return False

    def get_account_name(self) -> str:
        """Get account display name."""
        try:
            # Try to get user count for a meaningful name
            users = self._get_users()
            user_count = len(users)

            if user_count == 0:
                return "Basiq (No users connected)"
            elif user_count == 1:
                return "Basiq (1 user connected)"
            else:
                return f"Basiq ({user_count} users connected)"

        except Exception:
            return "Basiq Multi-Bank"

    def _get_users(self) -> List[dict]:
        """
        Fetch all users that have connected their banks.

        Returns:
            List of user dictionaries with id and other metadata
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/users",
                headers=self._get_headers(),
                timeout=15
            )
            response.raise_for_status()
            data = response.json()

            users = data.get("data", [])
            logger.info(f"Found {len(users)} users in Basiq account")
            return users

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch users: {str(e)}")
            raise ConnectionError(f"Failed to fetch Basiq users: {str(e)}")

    def _get_user_transactions(self, user_id: str, since_date: Optional[str] = None) -> List[Transaction]:
        """
        Fetch transactions for a specific user.

        Args:
            user_id: Basiq user ID
            since_date: Optional date filter in YYYY-MM-DD format

        Returns:
            List of Transaction objects for this user
        """
        transactions = []
        url = f"{self.BASE_URL}/users/{user_id}/transactions"

        # Build query parameters
        params = {}
        if since_date:
            # Basiq uses filter[postDate.from] for date filtering
            params["filter[postDate.from]"] = since_date

        try:
            while url:
                response = requests.get(
                    url,
                    headers=self._get_headers(),
                    params=params if params else None,
                    timeout=15
                )

                if response.status_code == 404:
                    # User might not have any transactions or accounts
                    logger.warning(f"No transactions found for user {user_id}")
                    break

                response.raise_for_status()
                data = response.json()

                # Parse transactions from response
                for item in data.get("data", []):
                    attributes = item.get("attributes", {})

                    # Extract transaction details
                    description = attributes.get("description", "")
                    amount = float(attributes.get("amount", 0))

                    # Parse date (use postDate, fallback to transactionDate)
                    transaction_date = attributes.get("postDate") or attributes.get("transactionDate", "")

                    # Ensure date is in YYYY-MM-DD format
                    if "T" in transaction_date:
                        transaction_date = transaction_date.split("T")[0]

                    # Create transaction object with full raw data
                    transaction = Transaction(
                        date=transaction_date,
                        description=description,
                        amount=amount,
                        raw_data=item
                    )
                    transactions.append(transaction)

                # Check for next page
                links = data.get("links", {})
                next_link = links.get("next")

                if next_link:
                    # Basiq returns full URL in next link
                    url = next_link
                    params = None  # Don't pass params for paginated URLs
                else:
                    url = None

            return transactions

        except requests.exceptions.Timeout:
            raise ConnectionError("Request to Basiq API timed out")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch transactions for user {user_id}: {str(e)}")
            raise ConnectionError(f"Failed to fetch transactions: {str(e)}")

    def get_transactions(self, since_date: Optional[str] = None, limit: Optional[int] = None) -> List[Transaction]:
        """
        Fetch transactions from all connected users in Basiq.

        Args:
            since_date: Optional date in YYYY-MM-DD format to fetch transactions from
            limit: Optional limit on total number of transactions (applied after fetching all)

        Returns:
            List of Transaction objects from all users

        Raises:
            ConnectionError: If API connection fails
            ValueError: If authentication fails
        """
        # Determine start date
        if not since_date:
            # Default to last 30 days if no date specified
            since_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        # Get all users
        users = self._get_users()

        if not users:
            logger.warning("No users found in Basiq account. Users must connect their banks first.")
            return []

        # Fetch transactions from all users
        all_transactions = []

        for user in users:
            user_id = user.get("id")
            if not user_id:
                continue

            try:
                user_transactions = self._get_user_transactions(user_id, since_date)
                all_transactions.extend(user_transactions)
                logger.info(f"Fetched {len(user_transactions)} transactions from user {user_id}")
            except Exception as e:
                # Log error but continue with other users
                logger.error(f"Error fetching transactions for user {user_id}: {str(e)}")
                continue

        # Sort by date (newest first)
        all_transactions.sort(key=lambda t: t.date, reverse=True)

        # Apply limit if specified
        if limit:
            all_transactions = all_transactions[:limit]

        logger.info(f"Total transactions fetched: {len(all_transactions)}")
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
