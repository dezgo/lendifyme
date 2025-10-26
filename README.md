# LendifyMe

A simple loan tracking web application that helps you keep track of money you've lent to others and automatically match bank transactions to loan repayments.

## Features

- **Track loans**: Record loans with borrower name, amount, date, and notes
- **Manual repayments**: Add repayments manually as they come in
- **Automatic transaction matching**: Import bank transactions and automatically match them to loans
- **Multiple bank support**: Connect to Up Bank or upload CSV from any bank
- **Smart matching algorithm**: Uses name similarity, amount matching, and date validation to suggest repayments
- **Mobile-responsive**: Works great on phones and tablets

## Quick Start

### Prerequisites

- Python 3.7+
- pip

### Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env and add your configuration
   ```

4. Run the application:
   ```bash
   python app.py
   ```

5. Open http://localhost:5000 in your browser

## Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

**Required:**
- `SECRET_KEY` - Flask session secret (set to a random string)

**Optional (for bank API access):**
- `UP_BANK_API_KEY` - Your Up Bank API token (get from https://api.up.com.au/getting_started)

### Up Bank Setup

1. Log into your Up Bank app
2. Go to Settings → Up API
3. Create a new Personal Access Token
4. Copy the token to your `.env` file as `UP_BANK_API_KEY`

## Usage

### Adding a Loan

1. Fill in the loan form on the home page
2. Enter borrower name, amount, date, and optional note
3. Click "Add Loan"

### Manual Repayments

1. Find the loan in the loans table
2. Enter the repayment amount in the "Add Repayment" column
3. Click "Pay"

### Automatic Transaction Matching

1. Click "Match Bank Transactions" button
2. Choose your import method:
   - **Up Bank**: Automatically fetch transactions from your Up Bank account
     - Select date range (7, 30, 60, or 90 days)
     - Or choose a custom start date
   - **CSV Upload**: Paste CSV data from any bank export
3. Review suggested matches (sorted by confidence)
4. Apply matches to update loans

## Architecture

### Bank Connectors

The app uses a plugin-based connector architecture that makes it easy to add support for new banks:

- **Base connector** (`services/connectors/base.py`): Abstract interface all connectors implement
- **Up Bank** (`services/connectors/up_bank.py`): API integration for Up Bank
- **CSV** (`services/connectors/csv_connector.py`): Manual CSV upload for any bank

### Adding New Banks

1. Create a new connector class inheriting from `BankConnector`
2. Implement required methods: `get_transactions()`, `test_connection()`, etc.
3. Register in `ConnectorRegistry` (`services/connectors/registry.py`)
4. Add environment variable for API credentials

See `CLAUDE.md` for detailed architecture documentation.

## Testing

Run the test suite:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

Run specific test file:

```bash
pytest tests/test_connectors.py
```

## Development

### Project Structure

```
lendifyme/
├── app.py                          # Main Flask application
├── services/
│   ├── migrations.py               # Database migrations
│   ├── transaction_matcher.py     # Matching algorithm
│   └── connectors/                 # Bank connector plugins
│       ├── base.py                 # Connector interface
│       ├── up_bank.py             # Up Bank implementation
│       ├── csv_connector.py       # CSV upload
│       └── registry.py            # Connector registry
├── templates/                      # HTML templates
├── tests/                          # Test suite
└── lendifyme.db                   # SQLite database (created on first run)
```

### Database Migrations

The app uses a custom migration system. Migrations run automatically on startup.

To add a new migration:
1. Create a migration function in `services/migrations.py`
2. Add version check in `run_migrations()`
3. Increment version number

## License

This project is open source and available for personal use.

## Contributing

Contributions welcome! Please feel free to submit issues or pull requests.
