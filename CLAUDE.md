# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LendifyMe is a simple loan tracking Flask web application that allows users to record and view loans they've made to others. The application uses SQLite for data persistence and includes a custom migration system.

## Development Commands

### Running the Application
```bash
# Development server
python app.py

# Production server (using gunicorn)
gunicorn app:app
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

### Database Schema
The `loans` table schema is defined in `services/migrations.py:21-32`:
- `id`: Primary key
- `borrower`: Name of person who borrowed
- `amount`: Loan amount (REAL/float)
- `date_borrowed`: When loan was made
- `date_due`: Optional due date
- `date_repaid`: Optional repayment date
- `note`: Optional note
- `created_at`: Timestamp (auto-generated)

### Testing Strategy
Tests use temporary databases created via `tempfile.mkstemp()` to ensure isolation. The test client fixture in `tests/conftest.py:8-22` sets up a fresh database with migrations for each test.

### Environment Configuration
The application uses `python-dotenv` to load environment variables from `.env` file. The `.env` file is gitignored and should contain local configuration.
