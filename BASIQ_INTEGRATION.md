# Basiq Integration Guide

This guide explains how to implement a seamless bank connection experience for your LendifyMe users using Basiq.

## The User Experience Flow

Your users will **never know they're using Basiq** - it's completely white-labeled:

1. User clicks "Connect Bank" in LendifyMe
2. User sees a nice UI showing bank logos (CBA, NAB, Westpac, etc.)
3. User selects their bank
4. User logs in with their bank credentials (in Basiq's secure iframe)
5. User grants permission
6. User is redirected back to LendifyMe
7. Transactions automatically flow into the matching system

## Implementation Example

Here's how to implement this in your app:

### Step 1: Create a Basiq User (Backend)

When a LendifyMe user wants to connect their bank, create a Basiq user for them:

```python
from services.connectors.registry import ConnectorRegistry

# Initialize Basiq connector
basiq = ConnectorRegistry.create_from_env('basiq')

# Create a user in Basiq (user never sees this happen)
basiq_user = basiq.create_user(
    email=lendifyme_user.email,
    first_name=lendifyme_user.name
)

# Store the Basiq user ID in your database
# (add a 'basiq_user_id' column to your users table)
lendifyme_user.basiq_user_id = basiq_user['id']
db.commit()
```

### Step 2: Generate Consent Link (Backend)

When user clicks "Connect Bank", generate a consent link:

```python
@app.route('/connect-bank')
@login_required
def connect_bank():
    basiq = ConnectorRegistry.create_from_env('basiq')

    # Generate consent link for this user
    consent = basiq.create_consent_link(
        user_id=current_user.basiq_user_id,
        redirect_url=url_for('bank_connected', _external=True)
    )

    # Redirect user to Basiq Connect UI
    return redirect(consent['consent_url'])
```

### Step 3: Handle Callback (Backend)

When user completes bank connection, they're redirected back:

```python
@app.route('/bank-connected')
@login_required
def bank_connected():
    basiq = ConnectorRegistry.create_from_env('basiq')

    # Check what banks they connected
    connections = basiq.get_user_connections(current_user.basiq_user_id)

    if connections:
        flash(f"Successfully connected {connections[0]['institution']['name']}!")
    else:
        flash("Connection cancelled or failed")

    return redirect('/dashboard')
```

### Step 4: Fetch Transactions (Backend)

Now you can fetch transactions from their connected banks:

```python
@app.route('/match', methods=['GET', 'POST'])
@login_required
def match_transactions():
    if request.form.get('connector') == 'basiq':
        basiq = ConnectorRegistry.create_from_env('basiq')

        # Fetch transactions from all connected banks
        transactions = basiq.get_incoming_transactions(
            since_date=request.form.get('since_date')
        )

        # Now run your matching algorithm
        # (your existing code already handles this)
```

## Advanced: Embedded UI Option

Instead of redirecting, you can embed Basiq Connect in a modal using their JS widget:

### Frontend (template):

```html
<button id="connect-bank-btn">Connect Bank</button>

<script src="https://consent.basiq.io/public/basiq-connect-v1.min.js"></script>
<script>
document.getElementById('connect-bank-btn').addEventListener('click', async () => {
    // Get consent token from your backend
    const response = await fetch('/api/basiq-consent-token');
    const data = await response.json();

    // Launch Basiq Connect widget
    const basiqConnect = new BasiqConnect({
        token: data.consent_token,
        onSuccess: function() {
            window.location.href = '/bank-connected';
        },
        onCancel: function() {
            alert('Connection cancelled');
        }
    });

    basiqConnect.open();
});
</script>
```

### Backend API endpoint:

```python
@app.route('/api/basiq-consent-token')
@login_required
def get_basiq_consent_token():
    basiq = ConnectorRegistry.create_from_env('basiq')

    consent = basiq.create_consent_link(
        user_id=current_user.basiq_user_id,
        redirect_url=url_for('bank_connected', _external=True)
    )

    return jsonify({
        'consent_token': consent['token'],
        'consent_url': consent['consent_url']
    })
```

## Showing Available Banks

You can show users a nice selection of banks before they connect:

```python
@app.route('/banks')
@login_required
def show_banks():
    basiq = ConnectorRegistry.create_from_env('basiq')

    # Get all available banks
    institutions = basiq.get_available_institutions()

    # Filter to major banks (tier 1)
    major_banks = [i for i in institutions if i['tier'] == 1]

    return render_template('banks.html', banks=major_banks)
```

Template (`banks.html`):
```html
<h2>Connect Your Bank</h2>
<div class="bank-grid">
    {% for bank in banks %}
    <div class="bank-card">
        <img src="{{ bank.logo }}" alt="{{ bank.name }}">
        <h3>{{ bank.name }}</h3>
        {% if bank.service_status == 'up' %}
            <span class="status-badge green">Available</span>
        {% else %}
            <span class="status-badge red">Temporarily Unavailable</span>
        {% endif %}
    </div>
    {% endfor %}
</div>
<button onclick="window.location.href='/connect-bank'">
    Continue to Connect
</button>
```

## Database Schema Changes

Add a column to store the Basiq user ID:

```sql
ALTER TABLE users ADD COLUMN basiq_user_id VARCHAR(255);
```

Or if using migrations:

```python
def migrate_vX_add_basiq_user_id(conn):
    """Add basiq_user_id to users table."""
    c = conn.cursor()
    c.execute("ALTER TABLE users ADD COLUMN basiq_user_id TEXT")
    conn.commit()
```

## Checking Connection Status

Periodically check if connections are still active:

```python
def check_basiq_connections():
    """Background job to check all user connections."""
    basiq = ConnectorRegistry.create_from_env('basiq')

    users = User.query.filter(User.basiq_user_id.isnot(None)).all()

    for user in users:
        connections = basiq.get_user_connections(user.basiq_user_id)

        for conn in connections:
            if conn['status'] == 'credentials-invalid':
                # Send email to user to reconnect
                send_email(user.email,
                    "Please reconnect your bank",
                    f"Your {conn['institution']['name']} connection needs to be updated."
                )
```

## Refreshing Transactions

Refresh bank connections to get latest transactions:

```python
def refresh_all_basiq_connections():
    """Refresh all active bank connections."""
    basiq = ConnectorRegistry.create_from_env('basiq')

    users = User.query.filter(User.basiq_user_id.isnot(None)).all()

    for user in users:
        connections = basiq.get_user_connections(user.basiq_user_id)

        for conn in connections:
            if conn['status'] == 'active':
                try:
                    basiq.refresh_connection(user.basiq_user_id, conn['id'])
                    print(f"Refreshed {conn['institution']['name']} for {user.email}")
                except Exception as e:
                    print(f"Failed to refresh: {e}")
```

## Testing Without Real Banks

During development, you can test with Basiq's sandbox institution:

1. Go to https://dashboard.basiq.io
2. Use the test institution "Basiq Bank"
3. Use test credentials provided in the dashboard

## Summary

With these methods, you get:
- ✅ Seamless UX (users never leave your app)
- ✅ Access to 100+ Australian banks
- ✅ White-labeled experience
- ✅ Transaction auto-refresh
- ✅ Connection status monitoring
- ✅ Bank logo display

All your existing transaction matching code continues to work - just the data source changes!
