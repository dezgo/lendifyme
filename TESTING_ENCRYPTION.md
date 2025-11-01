# Testing Encryption Implementation

## Quick Start Test

### 1. Run the Migration

```bash
python app.py
```

This will automatically run migration v25 and encrypt existing data.

You should see output like:
```
📊 Current database version: 24
  Starting envelope encryption migration...
    Added encrypted_dek column to loans table.
    Added borrower_encrypted column to loans table.
    ...
    Found X loans to encrypt...
    Encrypted X loans.
    ⚠️  Note: DEKs stored with temporary placeholder - will be encrypted with user password on next login
  ✅ Envelope encryption migration complete!
✅ Migration v25 applied.
```

### 2. Verify Database Schema

```bash
sqlite3 lendifyme.db "PRAGMA table_info(loans);"
```

You should see new columns:
- `encrypted_dek`
- `borrower_encrypted`
- `amount_encrypted`
- `note_encrypted`
- `bank_name_encrypted`
- `borrower_email_encrypted`
- `repayment_amount_encrypted`
- `repayment_frequency_encrypted`

### 3. Check Encrypted Data

```bash
sqlite3 lendifyme.db "SELECT id, borrower_encrypted, amount_encrypted, encrypted_dek FROM loans LIMIT 1;"
```

You should see:
- `borrower_encrypted`: `gAAAAABm...` (encrypted gibberish)
- `amount_encrypted`: `gAAAAABm...` (encrypted gibberish)
- `encrypted_dek`: `MIGRATION_PENDING:xxxxxxxxxxx` (temporary placeholder)

### 4. Test the Application

**A. Create a New Loan**
1. Log in with your password
2. Create a test loan:
   - Borrower: "Test Person"
   - Amount: 100.00
   - Note: "Secret note"

**B. Verify Encryption in Database**
```bash
sqlite3 lendifyme.db "SELECT borrower, borrower_encrypted, encrypted_dek FROM loans WHERE borrower_encrypted IS NOT NULL ORDER BY id DESC LIMIT 1;"
```

Expected output:
- `borrower`: Empty or NULL (plaintext column not used)
- `borrower_encrypted`: `gAAAAABm...` (Fernet-encrypted data)
- `encrypted_dek`: `gAAAAABm...` (properly encrypted, no MIGRATION_PENDING)

**C. Verify You Can See Decrypted Data**
1. Go to the home page
2. You should see "Test Person" and "$100.00" displayed
3. This proves decryption works!

**D. Test Borrower Portal**
1. Copy the borrower portal link from your loan
2. Open in incognito/private window (to simulate borrower)
3. You should see loan details (proves token-based decryption works)

### 5. Verify Server Admin Cannot Read Data

**Simulate a database administrator:**

```bash
# Try to read loan data directly from database
sqlite3 lendifyme.db "SELECT borrower, borrower_encrypted FROM loans;"
```

You should see:
- `borrower`: Empty/NULL (old plaintext column)
- `borrower_encrypted`: `gAAAAABm...` (gibberish - cannot be read!)

**This proves zero-knowledge encryption is working!** 🎉

## Detailed Testing Scenarios

### Test 1: Migration of Existing Data

**Before migration:**
```sql
SELECT id, borrower, amount, borrower_encrypted FROM loans;
-- borrower: "Alice"
-- amount: 500.0
-- borrower_encrypted: NULL
```

**After migration:**
```sql
SELECT id, borrower, borrower_encrypted, encrypted_dek FROM loans;
-- borrower: NULL or "Alice" (kept temporarily for backwards compatibility)
-- borrower_encrypted: "gAAAAABm..." (encrypted)
-- encrypted_dek: "MIGRATION_PENDING:..." (temporary, will be finalized on login)
```

**After first login:**
```sql
SELECT id, encrypted_dek FROM loans;
-- encrypted_dek: "gAAAAABm..." (properly encrypted with user's password)
```

### Test 2: Create New Loan (Full Encryption)

**Expected database state:**
```sql
SELECT
    borrower,  -- Should be NULL
    borrower_encrypted,  -- Should be encrypted
    amount,  -- Should be NULL
    amount_encrypted,  -- Should be encrypted
    encrypted_dek,  -- Should be encrypted (no MIGRATION_PENDING)
    borrower_access_token  -- Should be the DEK in base64
FROM loans
WHERE id = <new_loan_id>;
```

All encrypted fields should start with `gAAAAAB` (Fernet signature).

### Test 3: Borrower Portal Access

**Test token extraction:**
```python
from services.encryption import extract_dek_from_token, decrypt_field

# Get token from database
token = "..." # from borrower_access_token column

# Extract DEK
dek = extract_dek_from_token(token)

# Should be 44 bytes (32-byte key, base64 encoded)
print(len(dek))  # 44
```

**Verify token can decrypt data:**
```python
# Get encrypted borrower name from database
borrower_encrypted = "gAAAAABm..."

# Decrypt using DEK from token
borrower_name = decrypt_field(borrower_encrypted, dek)
print(borrower_name)  # "Alice" (decrypted!)
```

### Test 4: Password-Based Decryption (Lender)

**Test DEK decryption:**
```python
from services.encryption import decrypt_dek_with_password

# Get from database
encrypted_dek = "gAAAAABm..."
user_password = "mypassword"  # from session
encryption_salt = "rH8F2vP..."  # from users.encryption_salt

# Decrypt DEK
dek = decrypt_dek_with_password(encrypted_dek, user_password, encryption_salt)
print(len(dek))  # 44 bytes
```

### Test 5: Verify Zero-Knowledge

**Things a database admin CANNOT do:**
1. ❌ Read borrower names without password
2. ❌ Read loan amounts without password
3. ❌ Read notes without password
4. ❌ Decrypt DEK without user's password
5. ❌ Search for loans by borrower name

**Things a database admin CAN see:**
1. ✅ User IDs (who owns which loan)
2. ✅ Dates (when loans were created/due)
3. ✅ Loan IDs, transaction IDs
4. ✅ Encrypted blobs (but cannot decrypt them)
5. ✅ Borrower access tokens (but if they don't know which loan it belongs to, can't use it)

**Test this:**
```sql
-- Admin tries to find all loans for user "Alice"
SELECT * FROM loans WHERE borrower LIKE '%Alice%';
-- Returns 0 rows! (borrower is encrypted)

-- Admin tries to find loans over $1000
SELECT * FROM loans WHERE amount > 1000;
-- Returns 0 rows! (amount is encrypted)

-- Admin can only see encrypted data
SELECT borrower_encrypted, amount_encrypted FROM loans;
-- gAAAAABmXY..., gAAAAABmXZ...
-- Meaningless without the decryption keys!
```

## Troubleshooting

### Issue: "Please log in with your password to view your loans"

**Cause:** User password not in session (session expired or magic link login)

**Fix:**
1. Log out
2. Log in using password (not magic link)
3. Password will be stored in session for decryption

### Issue: "Failed to decrypt DEK for loan X"

**Causes:**
1. Wrong password in session
2. Corrupted encrypted_dek in database
3. User changed password (DEK encrypted with old password)

**Debug:**
```python
# Check if encrypted_dek exists
SELECT id, encrypted_dek FROM loans WHERE id = X;

# Check if it's still using migration placeholder
SELECT encrypted_dek FROM loans WHERE encrypted_dek LIKE 'MIGRATION_PENDING:%';
```

### Issue: Borrower portal shows "Unable to decrypt loan data"

**Causes:**
1. Invalid token format
2. Token doesn't match a valid loan
3. Corrupted borrower_access_token

**Debug:**
```sql
-- Check token in database
SELECT id, borrower_access_token FROM loans WHERE id = X;

-- Token should be exactly 44 characters (base64-encoded 32 bytes)
SELECT LENGTH(borrower_access_token) FROM loans WHERE id = X;
-- Should return: 44
```

### Issue: All encrypted fields are NULL

**Cause:** Migration didn't run or failed

**Fix:**
```bash
# Check database version
sqlite3 lendifyme.db "PRAGMA user_version;"
# Should be 25 or higher

# If it's less than 25, migration didn't run
# Check app.py startup logs for migration errors
```

## Verification Checklist

- [ ] Migration v25 completed successfully
- [ ] New encrypted columns exist in loans table
- [ ] Existing loans have encrypted data populated
- [ ] New loans created with encrypted data
- [ ] Can view loan list (decryption works)
- [ ] Can access borrower portal (token decryption works)
- [ ] Database admin cannot read loan data in plaintext
- [ ] MIGRATION_PENDING placeholders replaced after login
- [ ] No plaintext sensitive data in database

## Security Audit Queries

**Check for any plaintext loan data:**
```sql
-- These should all return 0 or NULL
SELECT COUNT(*) FROM loans WHERE borrower IS NOT NULL;
SELECT COUNT(*) FROM loans WHERE amount IS NOT NULL;
SELECT COUNT(*) FROM loans WHERE note IS NOT NULL;
SELECT COUNT(*) FROM loans WHERE bank_name IS NOT NULL;
```

**Check encryption coverage:**
```sql
-- All loans should have encrypted fields
SELECT COUNT(*) FROM loans WHERE borrower_encrypted IS NULL;
-- Should be 0

SELECT COUNT(*) FROM loans WHERE amount_encrypted IS NULL;
-- Should be 0
```

**Check DEK encryption status:**
```sql
-- Check for migration placeholders (should be 0 after users login)
SELECT COUNT(*) FROM loans WHERE encrypted_dek LIKE 'MIGRATION_PENDING:%';

-- All loans should have encrypted DEKs
SELECT COUNT(*) FROM loans WHERE encrypted_dek IS NULL;
-- Should be 0
```

**Verify no sensitive data in logs:**
```bash
# Check application logs for accidental plaintext logging
grep -i "alice\|bob\|charlie" logs/lendifyme.log
# Should not find borrower names in logs
```

## Performance Testing

**Test decryption performance:**
```python
import time
from app import app, get_db_path, get_loan_dek
import sqlite3

with app.app_context():
    # Simulate loading 100 loans
    start = time.time()

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT id FROM loans LIMIT 100")
    loan_ids = [row[0] for row in c.fetchall()]

    for loan_id in loan_ids:
        dek = get_loan_dek(loan_id, user_password="test")
        # Decrypt loan fields here...

    elapsed = time.time() - start
    print(f"Decrypted 100 loans in {elapsed:.2f}s")
    # Should be under 1 second for 100 loans
    conn.close()
```

## Success Criteria

✅ Migration completes without errors
✅ All loans have encrypted fields populated
✅ Can create new encrypted loans
✅ Can view decrypted loan list
✅ Borrower portal works with token
✅ Database admin cannot read sensitive data
✅ No plaintext sensitive data remains in database
✅ Decryption performance acceptable (<100ms per loan)
