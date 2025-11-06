# Bank Selection UX Guide

## The Perfect User Experience

Your users now see individual banks, not "Basiq". Here's the flow:

### 1. Bank Selection Page

Users see a grid of banks with logos:

```
┌─────────────────────────────────────────────────┐
│           Connect Your Bank                     │
├─────────────────────────────────────────────────┤
│                                                 │
│  [🏦 Up Bank]              [🏦 Commonwealth]   │
│  Enter your API key         Secure login        │
│                                                 │
│  [🏦 NAB]                  [🏦 Westpac]        │
│  Secure login               Secure login        │
│                                                 │
│  [🏦 ANZ]                  [🏦 ING]            │
│  Secure login               Secure login        │
│                                                 │
│  [+ View all banks]                            │
└─────────────────────────────────────────────────┘
```

### 2. Two Different Flows

**Up Bank (API Key):**
```
User clicks "Up Bank"
  → Shows form: "Enter your Up Bank API key"
  → User pastes key
  → Validates immediately
  → ✅ Connected!
```

**Other Banks (OAuth via Basiq):**
```
User clicks "Commonwealth Bank"
  → Redirects to CommBank login page
  → User enters bank username/password
  → User grants permission
  → Redirects back to LendifyMe
  → ✅ Connected!
```

**User never sees "Basiq" mentioned anywhere!**

## Implementation Example

### Step 1: Display Bank Selection

```python
from services.connectors.registry import ConnectorRegistry

@app.route('/connect-bank')
@login_required
def connect_bank():
    # Get all available banks
    banks = ConnectorRegistry.get_banks_for_selection()

    # Group by auth type for better UI
    api_key_banks = [b for b in banks if b['auth_type'] == 'api_key']
    oauth_banks = [b for b in banks if b['auth_type'] == 'oauth']

    return render_template('connect_bank.html',
        api_key_banks=api_key_banks,
        oauth_banks=oauth_banks
    )
```

Template (`connect_bank.html`):
```html
<h1>Connect Your Bank</h1>

<div class="bank-grid">
    <!-- API Key Banks (Up Bank) -->
    {% for bank in api_key_banks %}
    <div class="bank-card" data-bank="{{ bank.id }}" data-auth="{{ bank.auth_type }}">
        <h3>{{ bank.name }}</h3>
        <p class="help-text">{{ bank.description }}</p>
        <button onclick="connectBank('{{ bank.id }}', 'api_key')">
            Connect
        </button>
    </div>
    {% endfor %}

    <!-- OAuth Banks (all others) -->
    {% for bank in oauth_banks %}
    <div class="bank-card" data-bank="{{ bank.id }}" data-auth="{{ bank.auth_type }}">
        <h3>{{ bank.name }}</h3>
        <p class="help-text">{{ bank.description }}</p>
        <button onclick="connectBank('{{ bank.id }}', 'oauth')">
            Connect
        </button>
    </div>
    {% endfor %}
</div>

<script>
function connectBank(bankId, authType) {
    if (authType === 'api_key') {
        // Show modal to enter API key
        showApiKeyModal(bankId);
    } else {
        // Redirect to OAuth flow
        window.location.href = `/connect-bank/${bankId}/oauth`;
    }
}

function showApiKeyModal(bankId) {
    // Show a modal with an input field
    const apiKey = prompt('Enter your ' + bankId + ' API key:');
    if (apiKey) {
        // Submit to backend
        fetch('/connect-bank/api-key', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                bank_id: bankId,
                api_key: apiKey
            })
        }).then(response => {
            if (response.ok) {
                alert('Connected successfully!');
                window.location.href = '/dashboard';
            } else {
                alert('Failed to connect. Check your API key.');
            }
        });
    }
}
</script>
```

### Step 2: Handle API Key Connection (Up Bank)

```python
@app.route('/connect-bank/api-key', methods=['POST'])
@login_required
def connect_bank_api_key():
    data = request.get_json()
    bank_id = data.get('bank_id')
    api_key = data.get('api_key')

    # Create connector with user's API key
    connector = ConnectorRegistry.create_connector(bank_id, api_key=api_key)

    # Test connection
    if not connector or not connector.test_connection():
        return jsonify({'error': 'Invalid API key'}), 400

    # Store encrypted credentials in database
    # (Add your credential storage logic here)
    current_user.connected_bank = bank_id
    current_user.bank_credentials_encrypted = encrypt(api_key)
    db.session.commit()

    return jsonify({'success': True})
```

### Step 3: Handle OAuth Connection (All Other Banks)

```python
from services.connectors.registry import ConnectorRegistry

@app.route('/connect-bank/<bank_id>/oauth')
@login_required
def connect_bank_oauth(bank_id):
    # Get connector instance (using YOUR Basiq API key from .env)
    connector = ConnectorRegistry.create_from_env(bank_id)

    if not connector:
        flash('Bank not available. Check BASIQ_API_KEY in .env')
        return redirect('/connect-bank')

    # Create or get Basiq user for this LendifyMe user
    if not current_user.basiq_user_id:
        basiq_user = connector.create_user(
            email=current_user.email,
            first_name=current_user.name
        )
        current_user.basiq_user_id = basiq_user['id']
        db.session.commit()

    # Generate consent link for this specific bank
    consent = connector.create_consent_link(
        basiq_user_id=current_user.basiq_user_id,
        redirect_url=url_for('bank_connected', bank_id=bank_id, _external=True)
    )

    # Redirect user to bank login page (Basiq handles this)
    return redirect(consent['consent_url'])
```

### Step 4: Handle OAuth Callback

```python
@app.route('/bank-connected/<bank_id>')
@login_required
def bank_connected(bank_id):
    connector = ConnectorRegistry.create_from_env(
        bank_id,
        basiq_user_id=current_user.basiq_user_id
    )

    # Check if they successfully connected
    connections = connector.get_user_connections(current_user.basiq_user_id)

    if connections and connections[0]['status'] == 'active':
        # Store which bank they connected
        current_user.connected_bank = bank_id
        db.session.commit()

        flash(f"Successfully connected {connector.connector_name}!")
        return redirect('/dashboard')
    else:
        flash("Connection failed or was cancelled")
        return redirect('/connect-bank')
```

### Step 5: Fetch Transactions (Works for Both Types)

```python
@app.route('/match')
@login_required
def match_transactions():
    if not current_user.connected_bank:
        flash("Please connect your bank first")
        return redirect('/connect-bank')

    # Get connector (works for both API key and OAuth banks)
    if current_user.connected_bank == 'up_bank':
        # API key bank - use stored credentials
        api_key = decrypt(current_user.bank_credentials_encrypted)
        connector = ConnectorRegistry.create_connector(
            current_user.connected_bank,
            api_key=api_key
        )
    else:
        # OAuth bank - use Basiq user ID
        connector = ConnectorRegistry.create_from_env(
            current_user.connected_bank,
            basiq_user_id=current_user.basiq_user_id
        )

    # Fetch transactions (same interface for all banks!)
    transactions = connector.get_incoming_transactions(
        since_date=request.args.get('since_date', '2024-01-01')
    )

    # Run your matching algorithm
    # ... (your existing code)
```

## Database Schema

Add these columns to your users table:

```sql
ALTER TABLE users ADD COLUMN connected_bank VARCHAR(50);
ALTER TABLE users ADD COLUMN basiq_user_id VARCHAR(255);
ALTER TABLE users ADD COLUMN bank_credentials_encrypted TEXT;
```

Or in migration:

```python
def migrate_vX_add_bank_connection(conn):
    """Add bank connection fields to users table."""
    c = conn.cursor()
    c.execute("ALTER TABLE users ADD COLUMN connected_bank TEXT")
    c.execute("ALTER TABLE users ADD COLUMN basiq_user_id TEXT")
    c.execute("ALTER TABLE users ADD COLUMN bank_credentials_encrypted TEXT")
    conn.commit()
```

## What Users See

### Connection Flow:

1. **User clicks "Connect Bank"**
   - Sees: Up Bank, Commonwealth Bank, NAB, Westpac, ANZ, ING, etc.
   - **Never sees**: "Basiq"

2. **Clicks "Commonwealth Bank"**
   - Sees: CommBank login page
   - **Never sees**: "Basiq" branding (it's white-labeled)

3. **Logs in with bank credentials**
   - Sees: Permission screen
   - **Never sees**: "Basiq" mentioned

4. **Returns to LendifyMe**
   - Sees: "Successfully connected Commonwealth Bank!"
   - **Never sees**: Any mention of the aggregator

### Transaction Matching:

1. **User goes to /match page**
   - Sees: "Fetch transactions from Commonwealth Bank"
   - Clicks button
   - Transactions appear automatically

2. **Behind the scenes**:
   - LendifyMe uses Basiq API
   - Fetches from user's connected CommBank account
   - Runs matching algorithm
   - User has no idea Basiq exists!

## Summary

✅ **Users see**: Individual bank names (CommBank, NAB, Westpac, etc.)
✅ **Users never see**: "Basiq" anywhere
✅ **Up Bank**: Simple API key entry
✅ **All other banks**: OAuth login flow
✅ **Your code**: Same interface for all banks
✅ **100+ banks**: All available through one platform

The perfect UX!
