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

    This connector provides:
    1. User management (create users programmatically for your LendifyMe users)
    2. Consent link generation (for embedded bank connection flow)
    3. Transaction fetching from all connected banks
    4. Connection status monitoring
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

            if response.status_code == 400:
                # Log the actual error from Basiq
                try:
                    error_detail = response.json()
                    logger.error(f"Basiq 400 error: {error_detail}")
                    raise ValueError(f"Bad request to Basiq API. Response: {error_detail}")
                except:
                    raise ValueError(f"Bad request to Basiq API. Status: {response.status_code}, Response: {response.text}")

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

    # ========================================
    # User Management Methods (for seamless UX)
    # ========================================

    def create_user(self, email: str, mobile: Optional[str] = None, first_name: Optional[str] = None) -> dict:
        """
        Create a new user in Basiq programmatically.

        This should be called when a LendifyMe user wants to connect their bank.
        The user is created in Basiq but never sees the Basiq branding.

        Args:
            email: User's email address (required by Basiq)
            mobile: User's mobile number (optional, format: +61412345678)
            first_name: User's first name (optional)

        Returns:
            Dict with user info including:
            {
                'id': 'user-id',
                'email': 'user@example.com',
                'created_at': '2024-01-01T00:00:00Z'
            }

        Raises:
            ConnectionError: If API request fails
        """
        payload = {"email": email}

        if mobile:
            payload["mobile"] = mobile
        if first_name:
            payload["firstName"] = first_name

        try:
            response = requests.post(
                f"{self.BASE_URL}/users",
                headers=self._get_headers(),
                json=payload,
                timeout=15
            )

            if response.status_code == 400:
                # User might already exist with this email
                error_data = response.json()
                raise ValueError(f"Failed to create user: {error_data}")

            response.raise_for_status()
            data = response.json()

            user_data = data.get("data", {})
            logger.info(f"Created Basiq user: {user_data.get('id')}")

            return {
                'id': user_data.get('id'),
                'email': user_data.get('email'),
                'created_at': user_data.get('createdAt')
            }

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to create Basiq user: {str(e)}")

    def get_user_by_id(self, user_id: str) -> dict:
        """
        Get user details by Basiq user ID.

        Args:
            user_id: Basiq user ID

        Returns:
            Dict with user information

        Raises:
            ConnectionError: If API request fails
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/users/{user_id}",
                headers=self._get_headers(),
                timeout=15
            )
            response.raise_for_status()
            data = response.json()
            return data.get("data", {})

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to fetch user: {str(e)}")

    def create_consent_link(self, user_id: str, redirect_url: Optional[str] = None) -> dict:
        """
        Generate a consent link for a user to connect their bank.

        This is the key method for seamless UX! After creating a user,
        generate this link and either:
        1. Redirect user to it (opens Basiq Connect UI)
        2. Use Basiq Connect JS widget to embed it in your app

        Args:
            user_id: Basiq user ID (from create_user)
            redirect_url: Optional URL to redirect back to after connection
                         (e.g., 'https://lendifyme.com/bank-connected')

        Returns:
            Dict with:
            {
                'consent_url': 'https://consent.basiq.io/...',
                'token': 'consent-token'
            }

        Raises:
            ConnectionError: If API request fails
        """
        payload = {
            "scope": "TRANSACTION_DETAILS",  # Permission to read transactions
            "userId": user_id
        }

        if redirect_url:
            payload["redirectUrl"] = redirect_url

        try:
            response = requests.post(
                f"{self.BASE_URL}/consents",
                headers=self._get_headers(),
                json=payload,
                timeout=15
            )

            if response.status_code == 400:
                error_data = response.json()
                raise ValueError(f"Failed to create consent: {error_data}")

            response.raise_for_status()
            data = response.json()

            # Extract consent URL from response
            consent_data = data.get("data", {})
            consent_url = consent_data.get("url")
            consent_token = consent_data.get("id")

            logger.info(f"Created consent link for user {user_id}")

            return {
                'consent_url': consent_url,
                'token': consent_token
            }

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to create consent link: {str(e)}")

    def get_user_connections(self, user_id: str) -> List[dict]:
        """
        Get all bank connections for a user.

        Use this to check if user has successfully connected their bank
        and what the connection status is.

        Args:
            user_id: Basiq user ID

        Returns:
            List of connection dicts with:
            {
                'id': 'connection-id',
                'institution': {'name': 'Commonwealth Bank'},
                'status': 'active' | 'inactive' | 'credentials-invalid',
                'lastUsed': '2024-01-01T00:00:00Z'
            }

        Raises:
            ConnectionError: If API request fails
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/users/{user_id}/connections",
                headers=self._get_headers(),
                timeout=15
            )

            if response.status_code == 404:
                # User has no connections yet
                return []

            response.raise_for_status()
            data = response.json()

            connections = []
            for item in data.get("data", []):
                attributes = item.get("attributes", {})
                institution = attributes.get("institution", {})

                connections.append({
                    'id': item.get('id'),
                    'institution': {
                        'name': institution.get('name', 'Unknown'),
                        'short_name': institution.get('shortName', ''),
                        'logo': institution.get('logo', '')
                    },
                    'status': attributes.get('status'),
                    'last_used': attributes.get('lastUsed'),
                    'created_at': attributes.get('createdAt')
                })

            return connections

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to fetch connections: {str(e)}")

    def get_available_institutions(self, search: Optional[str] = None) -> List[dict]:
        """
        Get list of available banks/institutions that users can connect.

        Use this to show a nice bank selection UI to your users.

        Args:
            search: Optional search term to filter institutions

        Returns:
            List of institution dicts with:
            {
                'id': 'AU00000',
                'name': 'Commonwealth Bank',
                'short_name': 'CommBank',
                'logo': 'https://...',
                'tier': 1  # 1 = major bank, 2 = regional, 3 = other
            }

        Raises:
            ConnectionError: If API request fails
        """
        try:
            params = {}
            if search:
                params["filter"] = search

            response = requests.get(
                f"{self.BASE_URL}/institutions",
                headers=self._get_headers(),
                params=params if params else None,
                timeout=15
            )

            response.raise_for_status()
            data = response.json()

            institutions = []
            for item in data.get("data", []):
                attributes = item.get("attributes", {})

                institutions.append({
                    'id': item.get('id'),
                    'name': attributes.get('name', 'Unknown'),
                    'short_name': attributes.get('shortName', ''),
                    'logo': attributes.get('logo', ''),
                    'tier': attributes.get('tier', 3),
                    'service_status': attributes.get('serviceStatus', 'up')
                })

            # Sort by tier (major banks first)
            institutions.sort(key=lambda x: (x['tier'], x['name']))

            return institutions

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to fetch institutions: {str(e)}")

    def refresh_connection(self, user_id: str, connection_id: str) -> bool:
        """
        Refresh a bank connection to fetch latest data.

        Call this periodically or when user manually requests a refresh.

        Args:
            user_id: Basiq user ID
            connection_id: Connection ID to refresh

        Returns:
            True if refresh initiated successfully

        Raises:
            ConnectionError: If API request fails
        """
        try:
            response = requests.post(
                f"{self.BASE_URL}/users/{user_id}/connections/{connection_id}/refresh",
                headers=self._get_headers(),
                timeout=15
            )

            response.raise_for_status()
            logger.info(f"Refreshed connection {connection_id} for user {user_id}")
            return True

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to refresh connection: {str(e)}")
            raise ConnectionError(f"Failed to refresh connection: {str(e)}")
