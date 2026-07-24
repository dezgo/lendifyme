#!/bin/bash
set -euo pipefail

APP_DIR="/var/www/lendifyme"
VENV_DIR="$APP_DIR/.venv"
SERVICE_NAME="gunicorn-lendifyme"

echo "Switching ownership to derek..."
sudo chown -R derek:derek "$APP_DIR"

echo "Pulling latest changes from GitHub..."
cd "$APP_DIR"
git pull origin main

echo "Activating virtual environment and installing requirements..."
"$VENV_DIR/bin/pip" install -r requirements.txt

# Make sure instance dir exists for SQLite file
mkdir -p "$APP_DIR/instance"

echo "Running database migrations (flask init-db)..."
# Run as derek while the tree is derek-owned (the chown near the top); the
# chown back to www-data below hands the updated DB to the service account.
# Runs without sudo so the automated (non-interactive) deploy never needs a
# password. Env vars (ENCRYPTION_KEY, STRIPE_SECRET_KEY, etc.) are loaded by
# python-dotenv from /var/www/lendifyme/.env at app startup.
PYTHONPATH="$APP_DIR" FLASK_APP=app "$VENV_DIR/bin/flask" init-db

echo "Switching ownership back to www-data..."
sudo chown -R www-data:www-data "$APP_DIR"

echo "Restarting Gunicorn service: $SERVICE_NAME..."
sudo systemctl restart "$SERVICE_NAME"

echo "✅ Deployment complete."
