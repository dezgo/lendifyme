"""
Bank connection routes - Connect banks for automatic transaction fetching.
"""
from flask import Blueprint, render_template, request, session, redirect, flash, url_for, jsonify, current_app
from helpers.decorators import login_required, get_current_user_id
from helpers.db import get_db_connection
from helpers.utils import get_db_path
from services.connectors.registry import ConnectorRegistry
from services.encryption import encrypt_credentials, decrypt_credentials
import json
import os

bp = Blueprint('bank_connection', __name__)


def log_event(event_name, event_data=None, user_id=None):
    """Log an event to the events table."""
    if user_id is None:
        user_id = get_current_user_id()

    conn = get_db_connection()
    c = conn.cursor()

    event_data_json = json.dumps(event_data) if event_data else '{}'

    c.execute("""
        INSERT INTO events (user_id, event_name, event_data, created_at)
        VALUES (?, ?, ?, datetime('now'))
    """, (user_id, event_name, event_data_json))

    conn.commit()
    conn.close()


def get_user_info(user_id):
    """Get user information including bank connection status."""
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        SELECT email, name, basiq_user_id, connected_bank, bank_credentials_encrypted
        FROM users
        WHERE id = ?
    """, (user_id,))

    result = c.fetchone()
    conn.close()

    if result:
        return {
            'email': result[0],
            'name': result[1],
            'basiq_user_id': result[2],
            'connected_bank': result[3],
            'bank_credentials_encrypted': result[4]
        }
    return None


@bp.route('/connect-bank')
@login_required
def connect_bank():
    """
    Show bank selection page.

    Users see individual banks (Up Bank, CommBank, NAB, etc.)
    not "Basiq" - that's behind the scenes.
    """
    user_id = get_current_user_id()
    user = get_user_info(user_id)

    # Get all available banks for selection
    banks = ConnectorRegistry.get_banks_for_selection()

    # Group by auth type for better UI
    api_key_banks = [b for b in banks if b['auth_type'] == 'api_key']
    oauth_banks = [b for b in banks if b['auth_type'] == 'oauth']

    # Check if user already has a bank connected
    current_connection = None
    if user and user['connected_bank']:
        try:
            connector_class = ConnectorRegistry.get_connector_class(user['connected_bank'])
            if connector_class:
                # Get credential schema to determine if it needs special instantiation
                schema = connector_class.get_credential_schema()
                if schema.get('auth_type') == 'oauth':
                    # OAuth banks (aggregator-backed) need api_key and optionally basiq_user_id
                    instance = connector_class(api_key="dummy", basiq_user_id=None)
                else:
                    # API key banks just need api_key
                    instance = connector_class(api_key="dummy")

                current_connection = {
                    'id': user['connected_bank'],
                    'name': instance.connector_name
                }
        except Exception as e:
            # Silently fail - just won't show current connection
            current_app.logger.error(f"Failed to get connector name: {e}")
            pass

    log_event('bank_connection_page_viewed')

    return render_template('connect_bank.html',
                         api_key_banks=api_key_banks,
                         oauth_banks=oauth_banks,
                         current_connection=current_connection)


@bp.route('/connect-bank/api-key', methods=['POST'])
@login_required
def connect_bank_api_key():
    """
    Handle API key connection (for Up Bank).

    User provides their API key, we validate and store it encrypted.
    """
    user_id = get_current_user_id()
    data = request.get_json()

    bank_id = data.get('bank_id')
    api_key = data.get('api_key')

    if not bank_id or not api_key:
        return jsonify({'error': 'Missing bank_id or api_key'}), 400

    # Create connector with user's API key
    connector = ConnectorRegistry.create_connector(bank_id, api_key=api_key)

    if not connector:
        return jsonify({'error': 'Invalid bank connector'}), 400

    # Test connection
    try:
        if not connector.test_connection():
            return jsonify({'error': 'Invalid API key or connection failed'}), 400
    except Exception as e:
        return jsonify({'error': f'Connection test failed: {str(e)}'}), 400

    # Encrypt and store credentials
    conn = get_db_connection()
    c = conn.cursor()

    # Get encryption key from env
    encryption_key = os.getenv('ENCRYPTION_KEY')
    if not encryption_key:
        return jsonify({'error': 'Server encryption not configured'}), 500

    encrypted_creds = encrypt_credentials({'api_key': api_key}, encryption_key)

    c.execute("""
        UPDATE users
        SET connected_bank = ?,
            bank_credentials_encrypted = ?
        WHERE id = ?
    """, (bank_id, encrypted_creds, user_id))

    conn.commit()
    conn.close()

    log_event('bank_connected', {'bank': bank_id, 'auth_type': 'api_key'})

    return jsonify({'success': True, 'bank_name': connector.connector_name})


@bp.route('/connect-bank/<bank_id>/oauth')
@login_required
def connect_bank_oauth(bank_id):
    """
    Handle OAuth connection flow (for all banks except Up Bank).

    This creates a Basiq user (if needed) and redirects to bank login.
    User never sees "Basiq" - it's completely white-labeled.
    """
    user_id = get_current_user_id()
    user = get_user_info(user_id)

    if not user:
        flash('User not found')
        return redirect(url_for('bank_connection.connect_bank'))

    # Get connector instance (using YOUR Basiq API key from .env)
    connector = ConnectorRegistry.create_from_env(bank_id)

    if not connector:
        flash('Bank not available. Check BASIQ_API_KEY in .env', 'error')
        return redirect(url_for('bank_connection.connect_bank'))

    # Create or get Basiq user for this LendifyMe user
    basiq_user_id = user.get('basiq_user_id')

    current_app.logger.info(f"OAuth flow for bank {bank_id}, existing basiq_user_id: {basiq_user_id}")

    if not basiq_user_id:
        try:
            current_app.logger.info(f"Creating new Basiq user for email: {user['email']}")
            basiq_user = connector.create_user(
                email=user['email'],
                first_name=user['name']
            )
            basiq_user_id = basiq_user['id']

            current_app.logger.info(f"Created Basiq user with ID: {basiq_user_id}")

            # Store Basiq user ID
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""
                UPDATE users
                SET basiq_user_id = ?
                WHERE id = ?
            """, (basiq_user_id, user_id))
            conn.commit()
            conn.close()

            log_event('basiq_user_created', {'basiq_user_id': basiq_user_id})

        except Exception as e:
            current_app.logger.error(f"Failed to create Basiq user: {str(e)}")
            flash(f'Failed to create bank connection: {str(e)}', 'error')
            return redirect(url_for('bank_connection.connect_bank'))

    # Validate we have a basiq_user_id
    if not basiq_user_id:
        current_app.logger.error("basiq_user_id is still None after creation attempt")
        flash('Failed to get or create Basiq user ID', 'error')
        return redirect(url_for('bank_connection.connect_bank'))

    # Generate consent link for this specific bank
    try:
        current_app.logger.info(f"Creating consent link for basiq_user_id: {basiq_user_id}")
        consent = connector.create_consent_link(
            basiq_user_id=basiq_user_id,
            redirect_url=url_for('bank_connection.bank_connected',
                                bank_id=bank_id,
                                _external=True)
        )

        log_event('oauth_consent_initiated', {'bank': bank_id})

        # Redirect user to bank login page (Basiq handles this, but it's white-labeled)
        return redirect(consent['consent_url'])

    except Exception as e:
        flash(f'Failed to initiate connection: {str(e)}', 'error')
        return redirect(url_for('bank_connection.connect_bank'))


@bp.route('/check-connection-status/<bank_id>')
@login_required
def check_connection_status(bank_id):
    """
    AJAX endpoint to check if user has successfully connected a bank.
    Called when popup closes to verify connection without relying on Basiq redirect.
    """
    user_id = get_current_user_id()
    user = get_user_info(user_id)

    if not user or not user['basiq_user_id']:
        return jsonify({'connected': False, 'error': 'User not found'})

    try:
        connector = ConnectorRegistry.create_from_env(bank_id, basiq_user_id=user['basiq_user_id'])
        if not connector:
            return jsonify({'connected': False, 'error': 'Connector not available'})

        connections = connector.get_user_connections(user['basiq_user_id'])
        current_app.logger.info(f"Check connection status for {bank_id}: found {len(connections)} connections")

        # Check if there's an active connection for this bank
        has_active = any(c['status'] == 'active' for c in connections)

        if has_active:
            # Store the connection
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE users SET connected_bank = ? WHERE id = ?", (bank_id, user_id))
            conn.commit()
            conn.close()

            log_event('bank_connected', {'bank': bank_id, 'auth_type': 'oauth'})

            return jsonify({
                'connected': True,
                'bank_name': connector.connector_name,
                'institution': connections[0]['institution']['name'] if connections else None
            })
        else:
            # Check if connection is pending
            has_pending = any(c['status'] in ['pending', 'credentials-invalid'] for c in connections)
            if has_pending:
                return jsonify({
                    'connected': False,
                    'pending': True,
                    'message': 'Connection is pending or credentials are invalid'
                })

            return jsonify({'connected': False, 'message': 'No active connection found'})

    except Exception as e:
        current_app.logger.error(f"Error checking connection status: {str(e)}")
        return jsonify({'connected': False, 'error': str(e)})


@bp.route('/bank-connected/<bank_id>')
@login_required
def bank_connected(bank_id):
    """
    Handle OAuth callback after user connects their bank.

    User is redirected here after successfully logging into their bank.
    """
    current_app.logger.info(f"bank_connected callback hit for bank_id: {bank_id}")

    user_id = get_current_user_id()
    user = get_user_info(user_id)

    current_app.logger.info(f"User info: id={user_id}, basiq_user_id={user.get('basiq_user_id') if user else 'None'}")

    if not user or not user['basiq_user_id']:
        current_app.logger.error("Bank connection failed - user not found or no basiq_user_id")
        flash('Bank connection failed - user not found', 'error')
        return redirect(url_for('bank_connection.connect_bank'))

    # Get connector
    connector = ConnectorRegistry.create_from_env(
        bank_id,
        basiq_user_id=user['basiq_user_id']
    )

    if not connector:
        current_app.logger.error(f"Bank connector not available for {bank_id}")
        flash('Bank connector not available', 'error')
        return redirect(url_for('bank_connection.connect_bank'))

    # Check if they successfully connected
    try:
        current_app.logger.info(f"Fetching connections for basiq_user_id: {user['basiq_user_id']}")
        connections = connector.get_user_connections(user['basiq_user_id'])
        current_app.logger.info(f"Found {len(connections)} connections: {connections}")

        if connections and any(c['status'] == 'active' for c in connections):
            # Store which bank they connected
            conn = get_db_connection()
            c = conn.cursor()

            c.execute("""
                UPDATE users
                SET connected_bank = ?
                WHERE id = ?
            """, (bank_id, user_id))

            conn.commit()
            conn.close()

            log_event('bank_connected', {
                'bank': bank_id,
                'auth_type': 'oauth',
                'institution': connections[0]['institution']['name'] if connections else None
            })

            flash(f"Successfully connected {connector.connector_name}!", 'success')

            # Check if opened in popup (for OAuth flow)
            if request.args.get('popup') or 'popup' in request.referrer if request.referrer else False:
                # Return HTML that closes the popup
                return render_template('bank_connected_popup.html', success=True)

            return redirect(url_for('match'))
        else:
            flash("Connection failed or was cancelled. Please try again.", 'error')

            # Check if opened in popup
            if request.args.get('popup') or ('popup' in request.referrer if request.referrer else False):
                return render_template('bank_connected_popup.html', success=False, error='Connection failed or was cancelled')

            return redirect(url_for('bank_connection.connect_bank'))

    except Exception as e:
        flash(f"Failed to verify connection: {str(e)}", 'error')

        # Check if opened in popup
        if request.args.get('popup') or ('popup' in request.referrer if request.referrer else False):
            return render_template('bank_connected_popup.html', success=False, error=str(e))

        return redirect(url_for('bank_connection.connect_bank'))


@bp.route('/disconnect-bank', methods=['POST'])
@login_required
def disconnect_bank():
    """
    Disconnect user's bank.
    """
    user_id = get_current_user_id()

    conn = get_db_connection()
    c = conn.cursor()

    # Get current bank before disconnecting
    c.execute("SELECT connected_bank FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    old_bank = result[0] if result else None

    # Clear connection
    c.execute("""
        UPDATE users
        SET connected_bank = NULL,
            bank_credentials_encrypted = NULL
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

    log_event('bank_disconnected', {'bank': old_bank})

    flash('Bank disconnected successfully', 'success')
    return redirect(url_for('bank_connection.connect_bank'))


@bp.route('/bank-status')
@login_required
def bank_status():
    """
    Get current bank connection status (for AJAX polling if needed).
    """
    user_id = get_current_user_id()
    user = get_user_info(user_id)

    if not user or not user['connected_bank']:
        return jsonify({'connected': False})

    connector_class = ConnectorRegistry.get_connector_class(user['connected_bank'])
    if not connector_class:
        return jsonify({'connected': False})

    try:
        instance = connector_class(api_key="dummy")
        return jsonify({
            'connected': True,
            'bank_id': user['connected_bank'],
            'bank_name': instance.connector_name
        })
    except:
        return jsonify({'connected': False})
