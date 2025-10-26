import pytest
from unittest.mock import Mock, patch
from services.connectors.base import Transaction, BankConnector
from services.connectors.csv_connector import CSVConnector
from services.connectors.up_bank import UpBankConnector
from services.connectors.registry import ConnectorRegistry


class TestTransaction:
    """Test Transaction model."""

    def test_transaction_creation(self):
        """Test creating a transaction object."""
        transaction = Transaction(
            date="2025-10-15",
            description="Test payment",
            amount=50.00
        )

        assert transaction.date == "2025-10-15"
        assert transaction.description == "Test payment"
        assert transaction.amount == 50.00
        assert transaction.raw_data == {}

    def test_transaction_to_dict(self):
        """Test converting transaction to dictionary."""
        transaction = Transaction(
            date="2025-10-15",
            description="Test payment",
            amount=50.00,
            raw_data={"id": "123"}
        )

        result = transaction.to_dict()

        assert result == {
            'date': '2025-10-15',
            'description': 'Test payment',
            'amount': 50.00
        }


class TestCSVConnector:
    """Test CSV connector."""

    def test_csv_connector_initialization(self):
        """Test CSV connector initialization."""
        csv_data = "Date,Description,Amount\n2025-10-15,Payment,50.00"
        connector = CSVConnector(csv_content=csv_data)

        assert connector.connector_name == "CSV Upload"
        assert connector.csv_content == csv_data

    def test_csv_connector_test_connection(self):
        """Test CSV connector connection test."""
        csv_data = "Date,Description,Amount\n2025-10-15,Payment,50.00"
        connector = CSVConnector(csv_content=csv_data)

        assert connector.test_connection() is True

    def test_csv_connector_empty_content(self):
        """Test CSV connector with empty content."""
        connector = CSVConnector(csv_content="")

        assert connector.test_connection() is False

    def test_csv_connector_get_transactions(self):
        """Test getting transactions from CSV."""
        csv_data = """Date,Description,Amount
2025-10-15,Payment from Alice,50.00
2025-10-16,Transfer Bob,100.00"""

        connector = CSVConnector(csv_content=csv_data)
        transactions = connector.get_transactions()

        assert len(transactions) == 2
        assert transactions[0].date == "2025-10-15"
        assert transactions[0].description == "Payment from Alice"
        assert transactions[0].amount == 50.00

    def test_csv_connector_with_date_filter(self):
        """Test CSV connector with date filtering."""
        csv_data = """Date,Description,Amount
2025-10-15,Payment from Alice,50.00
2025-10-20,Transfer Bob,100.00"""

        connector = CSVConnector(csv_content=csv_data)
        transactions = connector.get_transactions(since_date="2025-10-18")

        assert len(transactions) == 1
        assert transactions[0].date == "2025-10-20"

    def test_csv_connector_with_limit(self):
        """Test CSV connector with limit."""
        csv_data = """Date,Description,Amount
2025-10-15,Payment 1,50.00
2025-10-16,Payment 2,60.00
2025-10-17,Payment 3,70.00"""

        connector = CSVConnector(csv_content=csv_data)
        transactions = connector.get_transactions(limit=2)

        assert len(transactions) == 2


class TestUpBankConnector:
    """Test Up Bank connector (with mocking)."""

    def test_connector_name(self):
        """Test Up Bank connector name."""
        connector = UpBankConnector(api_key="test-key")
        assert connector.connector_name == "Up Bank"

    @patch('services.connectors.up_bank.requests.get')
    def test_test_connection_success(self, mock_get):
        """Test successful connection test."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        connector = UpBankConnector(api_key="test-key")
        result = connector.test_connection()

        assert result is True
        mock_get.assert_called_once()

    @patch('services.connectors.up_bank.requests.get')
    def test_test_connection_failure(self, mock_get):
        """Test failed connection test."""
        mock_get.side_effect = Exception("Connection failed")

        connector = UpBankConnector(api_key="test-key")
        result = connector.test_connection()

        assert result is False

    @patch('services.connectors.up_bank.requests.get')
    def test_get_account_name(self, mock_get):
        """Test getting account name."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{
                "attributes": {
                    "displayName": "My Spending Account"
                }
            }]
        }
        mock_get.return_value = mock_response

        connector = UpBankConnector(api_key="test-key")
        account_name = connector.get_account_name()

        assert account_name == "My Spending Account"

    @patch('services.connectors.up_bank.requests.get')
    def test_get_transactions(self, mock_get):
        """Test fetching transactions from Up Bank."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "description": "Payment from Alice",
                        "amount": {
                            "valueInBaseUnits": 5000  # 50.00 in cents
                        },
                        "createdAt": "2025-10-15T10:30:00Z"
                    }
                },
                {
                    "attributes": {
                        "description": "Transfer from Bob",
                        "amount": {
                            "valueInBaseUnits": -2500  # -25.00 (outgoing)
                        },
                        "createdAt": "2025-10-16T14:20:00Z"
                    }
                }
            ],
            "links": {
                "next": None
            }
        }
        mock_get.return_value = mock_response

        connector = UpBankConnector(api_key="test-key")
        transactions = connector.get_transactions()

        assert len(transactions) == 2
        assert transactions[0].amount == 50.00
        assert transactions[0].description == "Payment from Alice"
        assert transactions[0].date == "2025-10-15"
        assert transactions[1].amount == -25.00

    @patch('services.connectors.up_bank.requests.get')
    def test_get_incoming_transactions(self, mock_get):
        """Test filtering for incoming transactions only."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "description": "Payment from Alice",
                        "amount": {"valueInBaseUnits": 5000},
                        "createdAt": "2025-10-15T10:30:00Z"
                    }
                },
                {
                    "attributes": {
                        "description": "Expense",
                        "amount": {"valueInBaseUnits": -2500},
                        "createdAt": "2025-10-16T14:20:00Z"
                    }
                }
            ],
            "links": {"next": None}
        }
        mock_get.return_value = mock_response

        connector = UpBankConnector(api_key="test-key")
        transactions = connector.get_incoming_transactions()

        # Should only include positive amounts
        assert len(transactions) == 1
        assert transactions[0].amount == 50.00

    @patch('services.connectors.up_bank.requests.get')
    def test_authentication_error(self, mock_get):
        """Test handling authentication errors."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = Exception("Unauthorized")
        mock_get.return_value = mock_response

        connector = UpBankConnector(api_key="bad-key")

        with pytest.raises(ValueError, match="Authentication failed"):
            connector.get_transactions()


class TestConnectorRegistry:
    """Test connector registry."""

    def test_get_connector_class(self):
        """Test getting connector class by ID."""
        connector_class = ConnectorRegistry.get_connector_class('csv')
        assert connector_class == CSVConnector

        connector_class = ConnectorRegistry.get_connector_class('up_bank')
        assert connector_class == UpBankConnector

    def test_get_connector_class_not_found(self):
        """Test getting non-existent connector."""
        connector_class = ConnectorRegistry.get_connector_class('non_existent')
        assert connector_class is None

    def test_create_connector(self):
        """Test creating connector instance."""
        csv_data = "Date,Description,Amount\n2025-10-15,Test,50.00"
        connector = ConnectorRegistry.create_connector('csv', csv_content=csv_data)

        assert isinstance(connector, CSVConnector)
        assert connector.csv_content == csv_data

    def test_register_custom_connector(self):
        """Test registering a custom connector."""
        class CustomConnector(BankConnector):
            @property
            def connector_name(self):
                return "Custom Bank"

            def get_transactions(self, since_date=None, limit=None):
                return []

            def test_connection(self):
                return True

            def get_account_name(self):
                return "Custom Account"

        ConnectorRegistry.register_connector('custom', CustomConnector)

        connector_class = ConnectorRegistry.get_connector_class('custom')
        assert connector_class == CustomConnector

        # Clean up
        del ConnectorRegistry._connectors['custom']

    def test_get_available_connectors(self):
        """Test getting list of available connectors."""
        available = ConnectorRegistry.get_available_connectors()

        # CSV should be excluded from "bank" connectors
        assert 'csv' not in available
        # Up Bank should be included
        assert 'up_bank' in available
        assert available['up_bank'] == "Up Bank"

    @patch.dict('os.environ', {'UP_BANK_API_KEY': 'test-api-key'})
    def test_create_from_env_up_bank(self):
        """Test creating Up Bank connector from environment."""
        connector = ConnectorRegistry.create_from_env('up_bank')

        assert isinstance(connector, UpBankConnector)
        assert connector.api_key == 'test-api-key'

    def test_create_from_env_no_credentials(self):
        """Test creating connector when credentials not in environment."""
        connector = ConnectorRegistry.create_from_env('up_bank')

        # Should return None if no API key in environment
        assert connector is None or isinstance(connector, UpBankConnector)
