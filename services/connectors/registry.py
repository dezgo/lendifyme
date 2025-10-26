# services/connectors/registry.py
import os
from typing import Dict, Type, Optional
from .base import BankConnector
from .up_bank import UpBankConnector
from .csv_connector import CSVConnector


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
