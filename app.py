"""
Flask app entry point: bootstraps config, logging, Sentry, Socket.IO, CSRF,
registers blueprints, and exposes a handful of app-level routes (favicon,
health, the analytics shim, the back-compat match handlers).

All business-route logic lives in routes/*.py blueprints.
"""
import logging
import os
import platform
import sys
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

import click
import sentry_sdk
from dotenv import load_dotenv
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    send_from_directory,
)
from flask_mail import Mail
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
from werkzeug.middleware.proxy_fix import ProxyFix

from helpers.db import get_db_connection, get_db_path
from helpers.decorators import admin_required, login_required


# ----------------------------------------------------------------------------
# App setup
# ----------------------------------------------------------------------------

load_dotenv()

ENV = os.environ.get("FLASK_ENV") or "production"

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    environment=ENV,
    integrations=[
        FlaskIntegration(),
        LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
    ],
    send_default_pii=True,
)

app = Flask(__name__)

# Socket.IO needs to be initialized before CSRF to avoid conflicts.
# Windows dev: auto-detect (threading). Linux prod: eventlet for WebSockets.
if platform.system() == 'Windows':
    socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False, engineio_logger=False)
else:
    socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False, engineio_logger=False, async_mode='eventlet')

csrf = CSRFProtect(app)

if os.getenv("FLASK_ENV") == "production":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config.update(
    SESSION_COOKIE_SECURE=(ENV == 'production'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PREFERRED_URL_SCHEME="https",
)

app.config['DATABASE'] = 'lendifyme.db'
app.secret_key = os.getenv('SECRET_KEY')

if not app.secret_key:
    sys.stderr.write(
        "\nERROR: SECRET_KEY is not set in environment.\n"
        "Generate one with:\n"
        "    python -c \"import secrets; print(secrets.token_hex(32))\"\n\n"
    )
    sys.exit(1)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Email config for magic links
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['APP_URL'] = os.getenv('APP_URL', 'http://localhost:5000')

mail = Mail(app)


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, 'lendifyme.log')

file_handler = RotatingFileHandler(log_file, maxBytes=10240000, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
app.logger.addHandler(console_handler)

app.logger.setLevel(logging.INFO)
app.logger.info(f'LendifyMe startup - Debug mode: {app.debug}')
app.logger.info(f'Log file location: {log_file}')

mailgun_configured = bool(os.getenv('MAILGUN_API_KEY') and os.getenv('MAILGUN_DOMAIN'))
smtp_configured = bool(os.getenv('MAIL_USERNAME') and os.getenv('MAIL_DEFAULT_SENDER'))
app.logger.info(f'Email config - Mailgun: {mailgun_configured}, SMTP: {smtp_configured}')
if mailgun_configured:
    app.logger.info(f'Mailgun domain: {os.getenv("MAILGUN_DOMAIN")}')

print(f"🚀 LendifyMe starting...")
print(f"📝 Logging to: {log_file}")
print(f"🐛 Debug mode: {app.debug}")
print(f"📧 Mailgun configured: {mailgun_configured}")
print(f"📧 SMTP configured: {smtp_configured}")
if mailgun_configured:
    print(f"📧 Mailgun domain: {os.getenv('MAILGUN_DOMAIN')}")


# ----------------------------------------------------------------------------
# Blueprints
# ----------------------------------------------------------------------------

from routes.auth import auth_bp, init_mail
app.register_blueprint(auth_bp)
init_mail(mail)
app.logger.info("Registered auth blueprint")
print("✅ Registered auth blueprint")

from routes.dashboard import dashboard_bp
app.register_blueprint(dashboard_bp)
app.logger.info("Registered dashboard blueprint")
print("✅ Registered dashboard blueprint")

from routes.loan_routes import loan_bp
app.register_blueprint(loan_bp)
app.logger.info("Registered loan blueprint")
print("✅ Registered loan blueprint")

from routes.borrower import borrower_bp
app.register_blueprint(borrower_bp)
app.logger.info("Registered borrower blueprint")
print("✅ Registered borrower blueprint")

from routes.admin import admin_bp, analytics_view
app.register_blueprint(admin_bp)
app.logger.info("Registered admin blueprint")
print("✅ Registered admin blueprint")

from routes.matching import (
    matching_bp,
    apply_match_handler,
    reject_match_handler,
)
app.register_blueprint(matching_bp)
app.logger.info("Registered matching blueprint")
print("✅ Registered matching blueprint")

from routes.settings import settings_bp
app.register_blueprint(settings_bp)
app.logger.info("Registered settings blueprint")
print("✅ Registered settings blueprint")

from routes.subscription import subscription_bp
app.register_blueprint(subscription_bp)
app.logger.info("Registered subscription blueprint")
print("✅ Registered subscription blueprint")

from routes.support import support_bp, register_socketio_handlers
app.register_blueprint(support_bp)
register_socketio_handlers(socketio)
app.logger.info("Registered support blueprint with Socket.IO handlers")
print("✅ Registered support blueprint")


# /analytics lives at the root (not under /admin)
@app.route("/analytics")
@admin_required
def analytics():
    return analytics_view()


# Match apply/reject handlers stay at the root for URL compatibility
@app.route("/apply-match", methods=["POST"])
@login_required
def apply_match():
    return apply_match_handler()


@app.route("/reject-match", methods=["POST"])
@login_required
def reject_match():
    return reject_match_handler()


# ----------------------------------------------------------------------------
# Jinja filters
# ----------------------------------------------------------------------------

@app.template_filter('format_date')
def format_date_filter(date_string):
    """Convert ISO date string (YYYY-MM-DD) to e.g. '1 Oct 2024'. Returns '—' for None."""
    if not date_string:
        return '—'
    try:
        if isinstance(date_string, str):
            if 'T' in date_string:
                date_obj = datetime.fromisoformat(date_string.split('.')[0])
            else:
                date_obj = datetime.strptime(date_string, '%Y-%m-%d')
        else:
            date_obj = date_string

        day = str(date_obj.day)
        month = date_obj.strftime('%b')
        year = date_obj.strftime('%Y')
        return f"{day} {month} {year}"
    except (ValueError, AttributeError):
        return date_string


# ----------------------------------------------------------------------------
# Hooks and error handlers
# ----------------------------------------------------------------------------

@app.before_request
def redirect_www():
    if request.host.startswith("www."):
        new_url = request.url.replace("://www.", "://", 1)
        return redirect(new_url, code=301)


@app.errorhandler(400)
def bad_request(e):
    """Handle 400 Bad Request errors (primarily CSRF failures)."""
    error_description = str(e.description) if hasattr(e, 'description') else ""
    is_csrf_error = "CSRF" in error_description or "csrf" in error_description.lower()
    return render_template("400.html", is_csrf_error=is_csrf_error), 400


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# ----------------------------------------------------------------------------
# DB init / health / favicon
# ----------------------------------------------------------------------------

def init_db():
    from services import migrations

    get_db_path()  # uses current_app when context is active
    conn = get_db_connection()
    try:
        migrations.run_migrations(conn)
    finally:
        conn.close()


@app.cli.command("init-db")
def init_db_command():
    """Initialize DB / run migrations (use in deploy)."""
    with app.app_context():
        init_db()
    click.echo("✅ Database initialized (migrations applied).")


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )


@app.route("/health")
def health():
    if ENV != 'development':
        return "status: ok", 200, {'Content-Type': 'text/plain; charset=utf-8'}

    """Health check endpoint with diagnostics (development only)."""
    app.logger.info("Health check endpoint accessed")

    diagnostics = {
        "status": "ok",
        "app_root": os.path.dirname(os.path.abspath(__file__)),
        "log_file": log_file,
        "log_file_exists": os.path.exists(log_file),
        "log_dir_exists": os.path.exists(log_dir),
        "debug_mode": app.debug,
        "python_version": sys.version,
        "working_directory": os.getcwd(),
        "email_config": {
            "mailgun_configured": bool(os.getenv('MAILGUN_API_KEY') and os.getenv('MAILGUN_DOMAIN')),
            "mailgun_domain": os.getenv('MAILGUN_DOMAIN', 'Not set'),
            "smtp_configured": bool(os.getenv('MAIL_USERNAME')),
        },
        "log_dir_writable": os.access(log_dir, os.W_OK) if os.path.exists(log_dir) else "Dir doesn't exist"
    }

    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                log_preview = f.readlines()[-10:]
        except Exception as e:
            log_preview = [f"Error reading log: {str(e)}"]
    else:
        log_preview = ["Log file doesn't exist yet"]

    diagnostics["log_preview"] = log_preview

    output = "=== LendifyMe Health Check ===\n\n"
    for key, value in diagnostics.items():
        if key == "log_preview":
            output += f"\n{key}:\n"
            for line in value:
                output += f"  {line}"
        else:
            output += f"{key}: {value}\n"

    return output, 200, {'Content-Type': 'text/plain; charset=utf-8'}


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------

if __name__ == "__main__":
    # Avoid double-run in Flask's reloader child
    if os.getenv("WERKZEUG_RUN_MAIN") != "true":
        with app.app_context():
            init_db()
    socketio.run(app, debug=True, host="127.0.0.1", port=5000)
