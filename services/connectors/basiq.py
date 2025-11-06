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
                    Can be raw UUID or already base64-encoded
        """
        super().__init__(api_key)
        self._access_token = None
        self._token_expiry = None
        # Store whether the key is already base64 encoded
        self._key_is_encoded = api_key.endswith('==') or api_key.endswith('=')

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

    def _get_access_token(self, scope: str = "SERVER_ACCESS", user_id: Optional[str] = None) -> str:
        """
        Authenticate and get access token.

        Basiq uses OAuth 2.0 with client credentials flow.
        Tokens expire after 60 minutes, so we cache and reuse.

        Args:
            scope: Either "SERVER_ACCESS" (for backend API calls) or "CLIENT_ACCESS" (for consent UI)
            user_id: Required when scope is "CLIENT_ACCESS" to bind token to specific user

        Returns:
            Access token string

        Raises:
            ValueError: If authentication fails
        """
        # For CLIENT_ACCESS tokens, don't cache (they're user-specific)
        if scope == "CLIENT_ACCESS":
            if not user_id:
                raise ValueError("user_id is required for CLIENT_ACCESS tokens")
        else:
            # Return cached SERVER_ACCESS token if still valid
            if self._access_token and self._token_expiry:
                if datetime.now() < self._token_expiry:
                    return self._access_token

        # Encode API key as Basic auth
        # Basiq expects: "Basic {base64(api_key:)}"
        # If the key is already base64 encoded (ends with = or ==), use it directly
        if self._key_is_encoded:
            # Key from dashboard is already base64 encoded, use as-is
            encoded_auth = self.api_key
            logger.info("Using pre-encoded Basiq API key")
        else:
            # Raw key (UUID format), encode it
            auth_string = f"{self.api_key}:"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            logger.info("Encoded raw Basiq API key")

        headers = {
            "Authorization": f"Basic {encoded_auth}",
            "Content-Type": "application/x-www-form-urlencoded",
            "basiq-version": self.API_VERSION
        }

        # Build form data
        payload = {"scope": scope}
        if user_id:
            payload["userId"] = user_id

        try:
            response = requests.post(
                f"{self.BASE_URL}/token",
                headers=headers,
                data=payload,  # Use form data, not JSON
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

            token = data.get("access_token")

            # Only cache SERVER_ACCESS tokens
            if scope == "SERVER_ACCESS":
                self._access_token = token
                # Tokens expire in 60 minutes, cache for 55 to be safe
                self._token_expiry = datetime.now() + timedelta(minutes=55)

            logger.info(f"Successfully authenticated with Basiq API (scope: {scope})")
            return token

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

            logger.info(f"Basiq create_user response: {data}")

            user_data = data.get("data", {})
            logger.info(f"Extracted user_data: {user_data}")

            # Try different possible response structures
            user_id = user_data.get('id') or data.get('id')
            user_email = user_data.get('email') or data.get('email')
            created_at = user_data.get('createdAt') or data.get('createdAt')

            logger.info(f"Created Basiq user with ID: {user_id}")

            return {
                'id': user_id,
                'email': user_email,
                'created_at': created_at
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

    def create_consent_link(self, user_id: str, redirect_url: Optional[str] = None,
                           institution_id: Optional[str] = None) -> dict:
        """
        Generate a consent link for a user to connect their bank.

        This is the key method for seamless UX! After creating a user,
        generate this link and redirect the user to it to connect their bank.

        Basiq API v3.0 uses a CLIENT_ACCESS token bound to the user ID
        to access the Consent UI at https://consent.basiq.io/home

        Args:
            user_id: Basiq user ID (from create_user)
            redirect_url: Optional URL to redirect back to after connection
                         (e.g., 'https://lendifyme.com/bank-connected')
            institution_id: Optional institution ID to pre-select a specific bank

        Returns:
            Dict with:
            {
                'consent_url': 'https://consent.basiq.io/home?token=...',
                'token': 'client-access-token'
            }

        Raises:
            ConnectionError: If API request fails
        """
        logger.info(f"Creating consent link for user {user_id}")

        try:
            # Get CLIENT_ACCESS token bound to this user
            client_token = self._get_access_token(scope="CLIENT_ACCESS", user_id=user_id)

            # Build consent UI URL
            consent_url = f"https://consent.basiq.io/home?token={client_token}"

            # Add optional parameters
            if institution_id:
                consent_url += f"&institution={institution_id}"
                logger.info(f"Pre-selecting institution: {institution_id}")

            if redirect_url:
                # URL-encode the redirect URL
                from urllib.parse import quote
                consent_url += f"&redirect_uri={quote(redirect_url)}"
                logger.info(f"Setting redirect URL: {redirect_url}")

            logger.info(f"Created consent link for user {user_id}: {consent_url}")

            return {
                'consent_url': consent_url,
                'token': client_token
            }

        except Exception as e:
            logger.error(f"Failed to create consent link: {str(e)}")
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
                # In API v3.0, data is directly on item, not nested in "attributes"
                # Get logo URL from nested structure
                logo_url = ''
                logo_obj = item.get('logo', {})
                if isinstance(logo_obj, dict):
                    links = logo_obj.get('links', {})
                    logo_url = links.get('square', '') or links.get('full', '')

                # Tier is returned as string "1", "2", "3" - convert to int
                tier_str = item.get('tier', '3')
                tier = int(tier_str) if tier_str else 3

                institutions.append({
                    'id': item.get('id'),
                    'name': item.get('name', 'Unknown'),
                    'short_name': item.get('shortName', ''),
                    'logo': logo_url,
                    'tier': tier,
                    'service_status': item.get('status', 'up')
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
