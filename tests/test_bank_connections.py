"""
Tests for bank connections feature - encryption, storage, and management.
"""
import os
import pytest
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock
from services.encryption import encrypt_credentials, decrypt_credentials
from services.connectors.registry import ConnectorRegistry
from services.connectors.base import Transaction


class TestEncryption:
    """Test encryption and decryption of credentials."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encrypted data can be decrypted back to original."""
        original = {
            'api_key': 'up:yeah:test123456789',
            'account_id': '12345'
        }

        with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
            encrypted = encrypt_credentials(original)
            decrypted = decrypt_credentials(encrypted)

        assert decrypted == original

    def test_encrypted_string_is_different(self):
        """Test that encrypted string doesn't contain plaintext."""
        credentials = {'api_key': 'super-secret-key'}

        with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
            encrypted = encrypt_credentials(credentials)

        assert 'super-secret-key' not in encrypted
        assert isinstance(encrypted, str)

    def test_encryption_requires_key(self):
        """Test that encryption fails without ENCRYPTION_KEY set."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="ENCRYPTION_KEY not set"):
                encrypt_credentials({'api_key': 'test'})

    def test_different_encryptions_of_same_data(self):
        """Test that same data produces different encrypted strings (due to IV)."""
        credentials = {'api_key': 'test-key'}

        with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
            encrypted1 = encrypt_credentials(credentials)
            encrypted2 = encrypt_credentials(credentials)

        # Should be different due to random initialization vector
        assert encrypted1 != encrypted2

        # But both should decrypt to same value
        with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
            assert decrypt_credentials(encrypted1) == credentials
            assert decrypt_credentials(encrypted2) == credentials


class TestBankConnectionsMigration:
    """Test the bank_connections table migration."""

    def test_migration_creates_table(self, app, client):
        """Test that v15 migration creates bank_connections table."""
        with app.app_context():
            db_path = app.config['DATABASE']
            conn = sqlite3.connect(db_path)
            c = conn.cursor()

            # Check table exists
            c.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='bank_connections'
            """)
            assert c.fetchone() is not None

            # Check schema
            c.execute("PRAGMA table_info(bank_connections)")
            columns = {row[1]: row[2] for row in c.fetchall()}

            assert 'id' in columns
            assert 'user_id' in columns
            assert 'connector_type' in columns
            assert 'display_name' in columns
            assert 'credentials_encrypted' in columns
            assert 'is_active' in columns
            assert 'last_synced_at' in columns
            assert 'created_at' in columns

            conn.close()

    def test_migration_creates_indexes(self, app, client):
        """Test that migration creates required indexes."""
        with app.app_context():
            db_path = app.config['DATABASE']
            conn = sqlite3.connect(db_path)
            c = conn.cursor()

            c.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index' AND tbl_name='bank_connections'
            """)
            indexes = [row[0] for row in c.fetchall()]

            assert 'idx_bank_connections_user' in indexes
            assert 'idx_bank_connections_active' in indexes

            conn.close()


class TestConnectorRegistryUserConnections:
    """Test ConnectorRegistry methods for user connections."""

    def test_get_all_connector_info(self):
        """Test getting connector information for UI."""
        info = ConnectorRegistry.get_all_connector_info()

        # Should include Up Bank but not CSV
        assert 'up_bank' in info
        assert 'csv' not in info

        # Check Up Bank info structure
        up_info = info['up_bank']
        assert up_info['name'] == 'Up Bank'
        assert up_info['auth_type'] == 'api_key'
        assert len(up_info['fields']) > 0
        assert up_info['fields'][0]['name'] == 'api_key'

    def test_get_user_connections_empty(self, app, client):
        """Test getting connections for user with no connections."""
        with app.app_context():
            db_path = app.config['DATABASE']

            # Create a test user
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("INSERT INTO users (email, name, recovery_codes) VALUES (?, ?, ?)",
                     ('test@example.com', 'Test User', '[]'))
            user_id = c.lastrowid
            conn.commit()
            conn.close()

            connections = ConnectorRegistry.get_user_connections(db_path, user_id)
            assert connections == []

    def test_get_user_connections_with_data(self, app, client):
        """Test getting connections for user with saved connections."""
        with app.app_context():
            db_path = app.config['DATABASE']

            # Create test user
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("INSERT INTO users (email, name, recovery_codes) VALUES (?, ?, ?)",
                     ('test@example.com', 'Test User', '[]'))
            user_id = c.lastrowid

            # Add bank connection
            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                encrypted_creds = encrypt_credentials({'api_key': 'test-key'})

            c.execute("""
                INSERT INTO bank_connections
                (user_id, connector_type, display_name, credentials_encrypted, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, 'up_bank', 'My Up Bank', encrypted_creds, 1))
            conn.commit()
            conn.close()

            # Get connections
            connections = ConnectorRegistry.get_user_connections(db_path, user_id)

            assert len(connections) == 1
            assert connections[0]['connector_type'] == 'up_bank'
            assert connections[0]['display_name'] == 'My Up Bank'
            assert connections[0]['connector_name'] == 'Up Bank'

    def test_get_user_connections_filters_inactive(self, app, client):
        """Test that inactive connections are not returned."""
        with app.app_context():
            db_path = app.config['DATABASE']

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("INSERT INTO users (email, name, recovery_codes) VALUES (?, ?, ?)",
                     ('test@example.com', 'Test User', '[]'))
            user_id = c.lastrowid

            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                encrypted_creds = encrypt_credentials({'api_key': 'test-key'})

            # Add active connection
            c.execute("""
                INSERT INTO bank_connections
                (user_id, connector_type, display_name, credentials_encrypted, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, 'up_bank', 'Active Connection', encrypted_creds, 1))

            # Add inactive connection
            c.execute("""
                INSERT INTO bank_connections
                (user_id, connector_type, display_name, credentials_encrypted, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, 'up_bank', 'Inactive Connection', encrypted_creds, 0))

            conn.commit()
            conn.close()

            connections = ConnectorRegistry.get_user_connections(db_path, user_id)

            assert len(connections) == 1
            assert connections[0]['display_name'] == 'Active Connection'

    def test_create_from_connection_success(self, app, client):
        """Test creating connector instance from stored connection."""
        from services.encryption import generate_encryption_salt, encrypt_credentials_with_password

        with app.app_context():
            db_path = app.config['DATABASE']

            conn = sqlite3.connect(db_path)
            c = conn.cursor()

            # Generate encryption salt for password-based encryption
            encryption_salt = generate_encryption_salt()

            c.execute("INSERT INTO users (email, name, recovery_codes, encryption_salt) VALUES (?, ?, ?, ?)",
                      ('test@example.com', 'Test User', '[]', encryption_salt))
            user_id = c.lastrowid

            # ✅ ensure flags
            c.execute("UPDATE users SET email_verified=1, onboarding_completed=1 WHERE id=?", (user_id,))

            # Use password-based encryption for credentials
            user_password = 'testpassword123'
            encrypted_creds = encrypt_credentials_with_password(
                {'api_key': 'up:yeah:test123'},
                user_password,
                encryption_salt
            )

            c.execute("""
                INSERT INTO bank_connections
                (user_id, connector_type, display_name, credentials_encrypted, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, 'up_bank', 'Test Connection', encrypted_creds, 1))
            connection_id = c.lastrowid
            conn.commit()
            conn.close()

            # Create connector from connection with password
            connector = ConnectorRegistry.create_from_connection(
                db_path, connection_id, user_id, user_password
            )

            assert connector is not None
            assert connector.connector_name == 'Up Bank'

    def test_create_from_connection_wrong_user(self, app, client):
        """Test that users can't access other users' connections."""
        with app.app_context():
            db_path = app.config['DATABASE']

            conn = sqlite3.connect(db_path)
            c = conn.cursor()

            # Create two users
            c.execute("INSERT INTO users (email, name, recovery_codes) VALUES (?, ?, ?)",
                     ('user1@example.com', 'User 1', '[]'))
            user1_id = c.lastrowid
            c.execute("INSERT INTO users (email, name, recovery_codes) VALUES (?, ?, ?)",
                     ('user2@example.com', 'User 2', '[]'))
            user2_id = c.lastrowid

            # User 1 creates connection
            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                encrypted_creds = encrypt_credentials({'api_key': 'secret-key'})

            c.execute("""
                INSERT INTO bank_connections
                (user_id, connector_type, display_name, credentials_encrypted, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user1_id, 'up_bank', 'User 1 Connection', encrypted_creds, 1))
            connection_id = c.lastrowid
            conn.commit()
            conn.close()

            # User 2 tries to access User 1's connection
            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                connector = ConnectorRegistry.create_from_connection(
                    db_path, connection_id, user2_id
                )

            # Should return None (access denied)
            assert connector is None

    def test_create_from_connection_inactive(self, app, client):
        """Test that inactive connections can't be used."""
        with app.app_context():
            db_path = app.config['DATABASE']

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("INSERT INTO users (email, name, recovery_codes) VALUES (?, ?, ?)",
                     ('test@example.com', 'Test User', '[]'))
            user_id = c.lastrowid

            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                encrypted_creds = encrypt_credentials({'api_key': 'test-key'})

            c.execute("""
                INSERT INTO bank_connections
                (user_id, connector_type, display_name, credentials_encrypted, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, 'up_bank', 'Deleted Connection', encrypted_creds, 0))
            connection_id = c.lastrowid
            conn.commit()
            conn.close()

            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                connector = ConnectorRegistry.create_from_connection(
                    db_path, connection_id, user_id
                )

            assert connector is None


class TestBankConnectionsRoutes:
    """Test the /settings/banks routes."""

    def test_settings_banks_list_requires_login(self, client):
        """Test that /settings/banks requires authentication."""
        response = client.get('/settings/banks', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.location

    def test_settings_banks_list_empty(self, logged_in_client, app):
        """Test viewing bank connections page with no connections."""
        with app.app_context():
            response = logged_in_client.get('/settings/banks')
            assert response.status_code == 200
            assert b'No Bank Connections' in response.data
            assert b'Add Your First Bank' in response.data

    def test_settings_banks_add_shows_connectors(self, logged_in_client, app):
        """Test /settings/banks/add shows available connectors."""
        with app.app_context():
            response = logged_in_client.get('/settings/banks/add')
            assert response.status_code == 200
            assert b'Up Bank' in response.data
            assert b'Select your bank to get started' in response.data

    def test_settings_banks_configure_shows_form(self, logged_in_client, app):
        """Test /settings/banks/add/<connector> shows credential form."""
        with app.app_context():
            response = logged_in_client.get('/settings/banks/add/up_bank')
            assert response.status_code == 200
            assert b'Connect Up Bank' in response.data
            assert b'API Key' in response.data
            assert b'Test & Save Connection' in response.data

    def test_settings_banks_configure_invalid_connector(self, logged_in_client, app):
        """Test /settings/banks/add/<connector> with invalid connector."""
        with app.app_context():
            response = logged_in_client.get('/settings/banks/add/invalid_bank', follow_redirects=True)
            assert response.status_code == 200
            assert b'Invalid bank connector' in response.data

    @patch('services.connectors.up_bank.UpBankConnector.test_connection')
    def test_settings_banks_save_connection_success(self, mock_test, logged_in_client, app):
        """Test saving a bank connection successfully."""
        mock_test.return_value = True

        with app.app_context():
            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                response = logged_in_client.post('/settings/banks/add/up_bank', data={
                    'display_name': 'My Up Account',
                    'api_key': 'up:yeah:test123456'
                }, follow_redirects=True)

                assert response.status_code == 200
                assert b'Successfully connected to Up Bank!' in response.data
                assert b'My Up Account' in response.data

    @patch('services.connectors.up_bank.UpBankConnector.test_connection')
    def test_settings_banks_save_connection_test_fails(self, mock_test, logged_in_client, app):
        """Test that connection isn't saved if test fails."""
        mock_test.side_effect = ValueError("Invalid API key")

        with app.app_context():
            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                response = logged_in_client.post('/settings/banks/add/up_bank', data={
                    'display_name': 'My Up Account',
                    'api_key': 'invalid-key'
                }, follow_redirects=False)

                assert b'Connection test failed' in response.data
                assert b'Invalid API key' in response.data

    def test_settings_banks_delete_connection(self, logged_in_client, app, tmpdir):
        """Test deleting a bank connection."""
        with app.app_context():
            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                db_path = app.config['DATABASE']

                # Get user_id from session
                with logged_in_client.session_transaction() as sess:
                    user_id = sess['user_id']

                # Manually create a connection
                conn = sqlite3.connect(db_path)
                c = conn.cursor()

                encrypted_creds = encrypt_credentials({'api_key': 'test-key'})
                c.execute("""
                    INSERT INTO bank_connections
                    (user_id, connector_type, display_name, credentials_encrypted, is_active)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_id, 'up_bank', 'Test Connection', encrypted_creds, 1))
                connection_id = c.lastrowid
                conn.commit()
                conn.close()

                # Delete the connection
                response = logged_in_client.post(f'/settings/banks/{connection_id}/delete',
                                                follow_redirects=True)

                assert response.status_code == 200
                assert b'Bank connection removed' in response.data

                # Verify it's soft-deleted
                conn = sqlite3.connect(db_path)
                c = conn.cursor()
                c.execute("SELECT is_active FROM bank_connections WHERE id = ?",
                         (connection_id,))
                is_active = c.fetchone()[0]
                conn.close()

                assert is_active == 0

    def test_settings_banks_delete_wrong_user(self, logged_in_client, app, tmpdir):
        """Test that users can't delete other users' connections."""
        with app.app_context():
            with patch.dict(os.environ, {'ENCRYPTION_KEY': 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='}):
                db_path = app.config['DATABASE']

                # Create user 1 (different from logged_in_client's user)
                conn = sqlite3.connect(db_path)
                c = conn.cursor()
                c.execute("INSERT INTO users (email, name, recovery_codes) VALUES (?, ?, ?)",
                          ('user1@example.com', 'User 1', '[]'))
                user1_id = c.lastrowid
                c.execute("UPDATE users SET email_verified=1, onboarding_completed=1 WHERE id=?", (user1_id,))

                # User 1 creates connection
                encrypted_creds = encrypt_credentials({'api_key': 'test-key'})
                c.execute("""
                    INSERT INTO bank_connections
                    (user_id, connector_type, display_name, credentials_encrypted, is_active)
                    VALUES (?, ?, ?, ?, ?)
                """, (user1_id, 'up_bank', 'User 1 Connection', encrypted_creds, 1))
                connection_id = c.lastrowid
                conn.commit()
                conn.close()

                # logged_in_client is already user 2 (different from user1)
                # User 2 tries to delete User 1's connection
                response = logged_in_client.post(f'/settings/banks/{connection_id}/delete',
                                                follow_redirects=True)

                assert b'Connection not found' in response.data

                # Verify connection is still active
                conn = sqlite3.connect(db_path)
                c = conn.cursor()
                c.execute("SELECT is_active FROM bank_connections WHERE id = ?",
                         (connection_id,))
                is_active = c.fetchone()[0]
                conn.close()

                assert is_active == 1


class TestMatchRouteWithConnections:
    """Test the updated /match route with user connections."""

    def test_match_page_shows_user_connections(self, logged_in_client, app, tmpdir):
        """Test that /match shows user's saved connections."""
        from services.encryption import encrypt_credentials_with_password

        with app.app_context():
            db_path = app.config['DATABASE']

            # Get user_id and password from session
            with logged_in_client.session_transaction() as sess:
                user_id = sess['user_id']
                user_password = sess['user_password']

            # Get user's encryption_salt
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
            encryption_salt = c.fetchone()[0]

            # Add a connection with password-based encryption
            encrypted_creds = encrypt_credentials_with_password(
                {'api_key': 'test-key'},
                user_password,
                encryption_salt
            )
            c.execute("""
                INSERT INTO bank_connections
                (user_id, connector_type, display_name, credentials_encrypted, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, 'up_bank', 'My Up Bank', encrypted_creds, 1))
            conn.commit()
            conn.close()

            # Visit match page
            response = logged_in_client.get('/match')
            assert response.status_code == 200
            assert b'My Up Bank' in response.data
            assert b'Up Bank' in response.data

    def test_match_page_no_connections_shows_message(self, logged_in_client, app):
        """Test that /match shows helpful message when no connections."""
        with app.app_context():
            response = logged_in_client.get('/match')
            assert response.status_code == 200
            assert b'No bank connections configured' in response.data
            assert b'Add a bank connection' in response.data

    @patch('services.connectors.up_bank.UpBankConnector.get_transactions')
    def test_match_with_user_connection(self, mock_get_trans, logged_in_client, app, tmpdir):
        """Test importing transactions using a user's saved connection."""
        from services.encryption import encrypt_credentials_with_password

        # Mock transaction response
        mock_get_trans.return_value = [
            Transaction(
                date='2025-10-20',
                description='Transfer from Alice',
                amount=50.00,
                raw_data={}
            )
        ]

        with app.app_context():
            db_path = app.config['DATABASE']

            # Get user_id and password from session
            with logged_in_client.session_transaction() as sess:
                user_id = sess['user_id']
                user_password = sess['user_password']

            # Create loan
            logged_in_client.post('/', data={
                'borrower': 'Alice',
                'amount': '50',
                'date_borrowed': '2025-10-01'
            })

            # Get user's encryption_salt and add bank connection
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
            encryption_salt = c.fetchone()[0]

            # Add bank connection with password-based encryption
            encrypted_creds = encrypt_credentials_with_password(
                {'api_key': 'up:yeah:validkey'},
                user_password,
                encryption_salt
            )
            c.execute("""
                INSERT INTO bank_connections
                (user_id, connector_type, display_name, credentials_encrypted, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, 'up_bank', 'My Up Bank', encrypted_creds, 1))
            connection_id = c.lastrowid
            conn.commit()
            conn.close()

            # Import transactions using the connection
            response = logged_in_client.post('/match', data={
                'import_source': str(connection_id),
                'date_range': '30'
            }, follow_redirects=True)

            assert response.status_code == 200
            assert b'Alice' in response.data  # Should see the match
