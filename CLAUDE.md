# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LendifyMe is a simple loan tracking Flask web application that allows users to record and view loans they've made to others. The application uses SQLite for data persistence and includes a custom migration system.

## Development Commands

### Running the Application
```bash
# Development server
python app.py

# Production server (using gunicorn with eventlet worker for Socket.IO support)
gunicorn --worker-class eventlet -w 1 app:app

# IMPORTANT: Socket.IO requires eventlet worker class for production
# Standard gunicorn workers will NOT work with WebSocket connections
# Use -w 1 for single worker (Socket.IO rooms require sticky sessions)
# Note: eventlet works on Ubuntu/Linux servers; for Windows development use python app.py
```

### Testing
```bash
# Run all tests
pytest

# Run a single test file
pytest tests/test_routes.py

# Run a specific test
pytest tests/test_routes.py::test_form_submission

# Run with verbose output
pytest -v
```

### Dependencies
```bash
# Install dependencies
pip install -r requirements.txt
```

## Architecture

### Database Management
- **Database File**: `lendifyme.db` (SQLite)
- **Migration System**: Custom version-based migrations in `services/migrations.py`
  - Uses SQLite's `PRAGMA user_version` to track migration state
  - Migrations run automatically on app startup via `init_db()` in app.py:24-27
  - Each migration function is idempotent and version-gated
  - To add a new migration: create a `migrate_vX_description` function and add version check in `run_migrations()`

### Application Structure
- **Main app**: `app.py` - Flask application with single route handler
- **Services**: `services/` directory contains database migrations
- **Templates**: `templates/` directory contains Jinja2 HTML templates
- **Tests**: `tests/` directory with pytest-based tests
  - `conftest.py` provides test fixtures with temporary database setup
  - Tests use Flask test client with isolated database per test

### Request Flow
1. App startup calls `init_db()` which runs migrations (app.py:30)
2. All requests go through `redirect_www()` middleware to strip www subdomain (app.py:17-21)
3. Index route handles both GET (display loans) and POST (add loan) (app.py:33-63)
4. Database connections are opened/closed per request (no connection pooling)

### Loan Management Routes
- `/` (GET, POST) - List loans and create new loans
- `/edit/<loan_id>` (GET, POST) - Edit existing loan details (borrower, amount, schedule, etc.)
- `/delete/<loan_id>` (POST) - Delete a loan (with confirmation)
- `/repay/<loan_id>` (POST) - Add a manual repayment to a loan

### Borrower Self-Service Portal Routes
- `/borrower/<token>` (GET) - Read-only borrower portal showing loan status and payment history
- `/loan/<loan_id>/send-invite` (GET, POST) - Send email invitation to borrower with portal access link

**Borrower Portal Features:**
- Each loan has a unique, secure access token (generated automatically on creation)
- Borrowers can view their loan balance, payment history, and schedule via `/borrower/<token>`
- No authentication required - security through unguessable URL token
- Lender can copy portal link or send email invitation from loan management interface
- Email notifications sent automatically when payments are applied (if borrower email is configured)

### Transaction Matching Routes
- `/match` (GET, POST) - Upload CSV or select API connector, fetch transactions
- `/match/review` (GET) - Review pending matches from session
- `/apply-match` (POST) - Apply a match (update loan, record in applied_transactions)
- `/reject-match` (POST) - Reject a match (record in rejected_matches for this loan)

**Edit vs Repay:**
- Edit: Changes loan details (borrower name, amount, repayment schedule). Does NOT affect `amount_repaid`.
- Repay: Adds to `amount_repaid` without changing loan details.

**Repayment Schedule:**
Optional fields that help with automatic transaction matching:
- `repayment_amount`: Expected repayment amount (e.g., 50.00)
- `repayment_frequency`: 'weekly', 'fortnightly', 'monthly', or NULL
- Displayed in table as "$50.00/weekly"
- Used by matching algorithm to boost confidence when transactions match the scheduled amount

### Database Schema
The `loans` table schema is defined across migrations in `services/migrations.py`:
- `id`: Primary key
- `borrower`: Name of person who borrowed
- `amount`: Loan amount (REAL/float)
- `date_borrowed`: When loan was made
- `date_due`: Optional due date
- `date_repaid`: Optional repayment date
- `note`: Optional note
- `created_at`: Timestamp (auto-generated)
- `amount_repaid`: Running total of repayments received (added in v2)
- `repayment_amount`: Expected repayment amount per schedule (added in v3)
- `repayment_frequency`: Frequency of repayments - 'weekly', 'fortnightly', 'monthly', or NULL (added in v3)
- `borrower_access_token`: Unique secure token for borrower portal access (added in v12)
- `borrower_email`: Email address for sending invitations and notifications (added in v12)
- `bank_name`: Name as it appears in bank statements (optional, added in v5) - used for transaction matching when different from borrower's actual name

**Applied Transactions Table** (`applied_transactions` - added in v4):
Tracks which transactions have been applied to prevent duplicates:
- `id`: Primary key
- `date`: Transaction date
- `description`: Transaction description
- `amount`: Transaction amount
- `loan_id`: Foreign key to loans table
- `applied_at`: Timestamp when applied
- Indexed on (date, description, amount) for fast duplicate checking

**Rejected Matches Table** (`rejected_matches` - added in v6):
Tracks which transaction/loan combinations were explicitly rejected to prevent re-suggesting:
- `id`: Primary key
- `date`: Transaction date
- `description`: Transaction description
- `amount`: Transaction amount
- `loan_id`: Foreign key to loans table (specific loan this was rejected for)
- `rejected_at`: Timestamp when rejected
- Indexed on (date, description, amount, loan_id) for fast duplicate checking
- Note: A transaction can be rejected for one loan but still suggested for another

### Testing Strategy
Tests use temporary databases created via `tempfile.mkstemp()` to ensure isolation. The test client fixture in `tests/conftest.py:8-22` sets up a fresh database with migrations for each test.

Test files:
- `tests/test_routes.py` - Tests for main routes and repayment functionality
- `tests/test_transaction_matcher.py` - Unit tests for CSV parsing and matching algorithms
- `tests/test_match_routes.py` - Integration tests for transaction matching workflow

### Environment Configuration
The application uses `python-dotenv` to load environment variables from `.env` file. The `.env` file is gitignored and should contain local configuration.

Required environment variables:
- `SECRET_KEY` - Flask session secret (defaults to 'dev-secret-key-change-in-production' if not set)

Optional bank API credentials (required only if using respective connector):
- `UP_BANK_API_KEY` - Up Bank API token (get from https://api.up.com.au/getting_started)
- Additional banks can be added by extending the connector registry

Optional email configuration:
- `MAILGUN_API_KEY` - Mailgun API key (recommended for production)
- `MAILGUN_DOMAIN` - Mailgun domain
- `MAIL_DEFAULT_SENDER` - Sender email address
- `MAIL_SENDER_NAME` - Sender name (defaults to 'LendifyMe')
- `APP_URL` - Base application URL (e.g., https://lendifyme.com)
- `ADMIN_EMAIL` - Admin email for support notifications

**Setup:**
1. Copy `.env.example` to `.env`
2. Set `SECRET_KEY` to a random value
3. Add bank API keys for any connectors you want to use
4. Add email credentials (Mailgun recommended)
5. Run `pip install -r requirements.txt`
6. Run `python app.py`

### Email Service
The application uses a centralized email service (`services/email_service.py`) that abstracts all email complexity.

**Usage Pattern:**
```python
from services.email_service import email_service

# Send support request notification
email_service.send_support_request(user_id, user_email)

# Send magic link
email_service.send_magic_link(email, name, token)

# Send borrower invite
email_service.send_borrower_invite(borrower_email, borrower_name, portal_token, lender_name)

# Send payment notification
email_service.send_payment_notification(
    borrower_email, borrower_name, portal_token, lender_name,
    payment_amount, payment_date, payment_description, new_balance, original_amount
)
```

**How It Works:**
- Email service handles environment variables internally (APP_URL, ADMIN_EMAIL, etc.)
- Tries Mailgun API first, falls back to SMTP automatically
- All logging and error handling is centralized
- Callers don't need to know about email infrastructure

**Email Providers:**
1. **Mailgun API** (recommended for production) - Set `MAILGUN_API_KEY` and `MAILGUN_DOMAIN`
2. **SMTP** (fallback) - Set `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_SERVER`, `MAIL_PORT`
3. **Development mode** - Prints links to console if no provider configured

## Bank Connector Architecture

### Overview
The application uses a plugin-based connector architecture (`services/connectors/`) to support multiple banks and import methods. This makes it easy to add new bank integrations.

### Connector Interface
All connectors implement the `BankConnector` abstract base class (`services/connectors/base.py`):

**Key Methods:**
- `get_transactions(since_date, limit)` - Fetch transactions from the source
- `test_connection()` - Verify API credentials/connectivity
- `get_account_name()` - Return human-readable account identifier
- `connector_name` - Property returning connector display name

**Transaction Model:**
Connectors return standardized `Transaction` objects with:
- `date` (YYYY-MM-DD format)
- `description` (transaction memo/description)
- `amount` (float, positive for incoming, negative for outgoing)
- `raw_data` (dict with full original API response - preserved for detailed matching UI)

The `raw_data` field stores the complete API response, which varies by connector:
- **Up Bank**: Includes message, rawText, settledAt, transactionType, status, category, tags, roundUp, cashback, etc.
- **CSV**: Stores the original CSV row data
- This data is displayed in the match review UI to help users make informed decisions

### Available Connectors

**Up Bank Connector** (`services/connectors/up_bank.py`):
- Uses Up Bank API v1 (https://api.up.com.au/api/v1)
- Requires `UP_BANK_API_KEY` in .env file
- Supports pagination and date filtering
- Automatically converts amounts from cents to dollars
- Default fetch: last 30 days, max 100 transactions per page

**CSV Connector** (`services/connectors/csv_connector.py`):
- Manual upload fallback for any bank
- Reuses existing CSV parser from `transaction_matcher.py`
- No API key required

### Adding New Connectors

1. Create new connector class in `services/connectors/your_bank.py`
2. Inherit from `BankConnector`
3. Implement required methods
4. Register in `ConnectorRegistry` (`services/connectors/registry.py`)
5. Add environment variable handling in `create_from_env()`

Example:
```python
class YourBankConnector(BankConnector):
    @property
    def connector_name(self) -> str:
        return "Your Bank"

    def get_transactions(self, since_date, limit):
        # Fetch from API
        # Return List[Transaction]
        pass
```

### Connector Registry
`ConnectorRegistry` manages all available connectors:
- `get_available_connectors()` - Returns dict of {connector_id: display_name}
- `create_from_env(connector_id)` - Instantiates connector with credentials from .env
- `register_connector()` - Register custom connectors at runtime

## Transaction Matching Feature

### Overview
The transaction matching system (`services/transaction_matcher.py`) helps users import existing bank transactions and automatically match them to loan repayments. Works with any connector source.

### Matching Algorithm
The matcher uses a confidence-based scoring system (0-100%) that considers:

1. **Name Similarity** (up to 40 points): Uses `difflib.SequenceMatcher` to find names in transaction descriptions
   - Uses `bank_name` if provided, otherwise falls back to `borrower` name
   - This allows matching against how names appear in bank statements (e.g., "Alice S" instead of "Alice Smith")
2. **Amount Matching** (up to 45 points):
   - Exact match to remaining balance: 40 points
   - Exact match to original loan amount: 35 points
   - **Exact match to scheduled repayment amount: 45 points** (highest priority)
   - Round number partial payment (divisible by 5 or 10): 20 points
   - Other partial payment: 10 points
3. **Date Validation** (up to 10 points): Transaction must occur after loan was created
   - Invalid dates (before loan) subtract 50 points

Matches below 30% confidence are automatically filtered out.

**Repayment Schedule Boost:**
If a loan has a repayment schedule configured (e.g., $50/weekly), transactions matching that exact amount receive the highest confidence boost (45 points). This helps automatically identify regular scheduled payments.

### CSV Format Support
The parser handles multiple CSV formats by checking for common column name variations:
- Date columns: `Date`, `date`, `DATE`
- Description columns: `Description`, `description`, `DESC`, `Memo`
- Amount columns: `Amount`, `amount`, `AMOUNT`

Amounts are cleaned of currency symbols ($) and thousand separators (,) before parsing.

### Workflow

**CSV Import:**
1. User visits `/match` route
2. User selects "Manual CSV Upload" option
3. User pastes CSV bank transaction data
4. System parses transactions and queries all unpaid/partially-paid loans
5. Matching algorithm generates suggested matches stored in session
6. User reviews matches on `/match` review page
7. User applies matches via `/apply-match` route, which updates `amount_repaid` in database

**API Import (e.g., Up Bank):**
1. User visits `/match` route
2. User selects bank connector (e.g., "Up Bank")
3. User selects date range (7/30/60/90 days, or custom date)
4. System fetches transactions from bank API since specified date
5. System filters to incoming transactions only (positive amounts)
6. Matching algorithm generates suggested matches
7. System filters out:
   - Transactions already applied (any loan)
   - Transactions rejected for this specific loan
8. Matches stored in session, redirects to `/match/review`
9. User reviews matches on review page
10. For each match, user can:
    - **Apply**: Records in `applied_transactions`, updates `amount_repaid`, removes from list
    - **Not a Match**: Records in `rejected_matches` for this loan, removes from list
11. Page stays on review with remaining matches after each action
12. Re-importing same transactions won't show applied or rejected ones

**Date Range Options:**
- Preset ranges: 7, 30, 60, or 90 days
- Custom date: User can select any start date
- Default: 30 days (if not specified)

### Session Storage
Pending matches are stored in Flask session to allow multi-step review process without database persistence until confirmation.
