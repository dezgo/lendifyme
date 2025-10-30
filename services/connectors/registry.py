# services/connectors/registry.py
import os
import sqlite3
from typing import Dict, Type, Optional, List
from .base import BankConnector
from .up_bank import UpBankConnector
from .csv_connector import CSVConnector
from ..encryption import encrypt_credentials, decrypt_credentials, decrypt_credentials_with_password


class ConnectorRegistry:
    """Registry for managing bank connectors."""

    _connectors: Dict[str, Type[BankConnector]] = {
        'up_bank': UpBankConnector,
        'csv': CSVConnector,
    }

    @classmethod
    def register_connector(cls, connector_id: str, connector_class: Type[BankConnector]):
        """
        Register a new bank connector.

        Args:
            connector_id: Unique identifier for the connector (e.g., 'commonwealth_bank')
            connector_class: Connector class implementing BankConnector
        """
        cls._connectors[connector_id] = connector_class

    @classmethod
    def get_connector_class(cls, connector_id: str) -> Optional[Type[BankConnector]]:
        """
        Get connector class by ID.

        Args:
            connector_id: Connector identifier

        Returns:
            Connector class or None if not found
        """
        return cls._connectors.get(connector_id)

    @classmethod
    def get_available_connectors(cls) -> Dict[str, str]:
        """
        Get list of available connectors with their display names.

        Returns:
            Dict mapping connector_id to display name
        """
        available = {}
        for connector_id, connector_class in cls._connectors.items():
            # Skip CSV from "bank" connectors (it's always available)
            if connector_id == 'csv':
                continue

            # Instantiate to get name (with dummy API key)
            try:
                instance = connector_class(api_key="dummy")
                available[connector_id] = instance.connector_name
            except Exception:
                pass

        return available

    @classmethod
    def create_connector(cls, connector_id: str, **kwargs) -> Optional[BankConnector]:
        """
        Create a connector instance.

        Args:
            connector_id: Connector identifier
            **kwargs: Arguments to pass to connector constructor

        Returns:
            Connector instance or None if not found
        """
        connector_class = cls.get_connector_class(connector_id)
        if not connector_class:
            return None

        return connector_class(**kwargs)

    @classmethod
    def create_from_env(cls, connector_id: str) -> Optional[BankConnector]:
        """
        Create a connector using environment variables for credentials.

        Expected environment variables:
        - UP_BANK_API_KEY for Up Bank
        - Add more as needed for other banks

        Args:
            connector_id: Connector identifier

        Returns:
            Connector instance or None if credentials not found
        """
        if connector_id == 'up_bank':
            api_key = os.getenv('UP_BANK_API_KEY')
            if not api_key:
                return None
            return UpBankConnector(api_key=api_key)

        # Add more connectors here as they're implemented
        # elif connector_id == 'commonwealth_bank':
        #     api_key = os.getenv('CBA_API_KEY')
        #     ...

        return None

    @classmethod
    def get_all_connector_info(cls) -> Dict[str, dict]:
        """
        Get information about all available connectors for UI display.

        Returns:
            Dict mapping connector_id to info dict with:
            {
                'name': 'Up Bank',
                'auth_type': 'api_key',
                'fields': [...]
            }
        """
        info = {}
        for connector_id, connector_class in cls._connectors.items():
            # Skip CSV as it's not a "bank connection"
            if connector_id == 'csv':
                continue

            try:
                instance = connector_class(api_key="dummy")
                schema = connector_class.get_credential_schema()
                info[connector_id] = {
                    'name': instance.connector_name,
                    'auth_type': schema['auth_type'],
                    'fields': schema['fields']
                }
            except Exception:
                pass

        return info

    @classmethod
    def create_from_connection(cls, db_path: str, connection_id: int, user_id: int,
                              user_password: Optional[str] = None) -> Optional[BankConnector]:
        """
        Create a connector instance from a stored bank connection.

        Args:
            db_path: Path to database
            connection_id: Bank connection ID
            user_id: User ID (for security check)
            user_password: User's password for zero-knowledge decryption (required)

        Returns:
            Connector instance or None if not found/unauthorized
        """
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        # Get connection and user's encryption salt
        c.execute("""
            SELECT bc.connector_type, bc.credentials_encrypted, bc.is_active, u.encryption_salt
            FROM bank_connections bc
            JOIN users u ON u.id = bc.user_id
            WHERE bc.id = ? AND bc.user_id = ?
        """, (connection_id, user_id))

        result = c.fetchone()
        conn.close()

        if not result or not result[2]:  # Check exists and is_active
            return None

        connector_type, encrypted_creds, _, encryption_salt = result

        if not user_password or not encryption_salt:
            # Cannot decrypt without password
            return None

        try:
            # Decrypt credentials using password-based zero-knowledge encryption
            credentials = decrypt_credentials_with_password(encrypted_creds, user_password, encryption_salt)

            # Create connector instance
            if connector_type == 'up_bank':
                return UpBankConnector(api_key=credentials['api_key'])
            # Add more connector types here
            # elif connector_type == 'plaid':
            #     return PlaidConnector(access_token=credentials['access_token'])

        except Exception:
            return None

        return None

    @classmethod
    def get_user_connections(cls, db_path: str, user_id: int) -> List[dict]:
        """
        Get all active bank connections for a user.

        Args:
            db_path: Path to database
            user_id: User ID

        Returns:
            List of connection dicts with id, display_name, connector_type, etc.
        """
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        c.execute("""
            SELECT id, connector_type, display_name, last_synced_at, created_at
            FROM bank_connections
            WHERE user_id = ? AND is_active = 1
            ORDER BY created_at DESC
        """, (user_id,))

        rows = c.fetchall()
        conn.close()

        connections = []
        for row in rows:
            # Get connector display name
            connector_class = cls.get_connector_class(row[1])
            if connector_class:
                try:
                    instance = connector_class(api_key="dummy")
                    connector_display_name = instance.connector_name
                except:
                    connector_display_name = row[1]
            else:
                connector_display_name = row[1]

            connections.append({
                'id': row[0],
                'connector_type': row[1],
                'display_name': row[2],
                'connector_name': connector_display_name,
                'last_synced_at': row[3],
                'created_at': row[4]
            })

        return connections
