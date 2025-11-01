# Test Fixes for Encryption Implementation

## What Was Fixed

### 1. NOT NULL Constraint Issue ✅
**Problem:** Old `borrower` column had NOT NULL constraint, but we're only inserting into `borrower_encrypted` now.

**Fix:** Migration v25 now recreates the loans table to make all old plaintext columns nullable:
- `borrower`, `amount`, `note`, `bank_name`, `borrower_email`
- `repayment_amount`, `repayment_frequency`

This allows us to insert into encrypted columns only without violating NOT NULL constraints.

### 2. Session Password Already Set ✅
The `logged_in_client` fixture in `conftest.py` already sets `user_password` in session (line 103), so encryption should work in tests.

## Remaining Test Issues

### Tests That Need Updates

**tests/test_routes.py:**

1. **`test_loan_repayment`** (line 88)
   ```python
   c.execute("SELECT id FROM loans WHERE borrower = 'Bob'")
   ```
   **Issue:** `borrower` column is now NULL (data is in `borrower_encrypted`)

   **Fix:** Query by user_id or just use the last inserted loan:
   ```python
   c.execute("SELECT id FROM loans ORDER BY id DESC LIMIT 1")
   ```

2. **`test_multiple_repayments`** (line 127)
   ```python
   c.execute("SELECT id FROM loans WHERE borrower = 'Charlie'")
   ```
   **Same issue and fix as above.**

3. **`test_form_submission`** (line 65)
   ```python
   assert b'Alice' in response.data
   ```
   **Issue:** This might actually work! The page should decrypt and show "Alice".

   **Potential issue:** If it's redirecting to login, check if session is persisting.

   **Debug:** Add print statement to see what page is returned:
   ```python
   print(response.data.decode('utf-8'))
   assert b'Alice' in response.data
   ```

4. **`test_index_shows_repayment_columns`** (line 159)
   ```python
   assert response.status_code == 200  # Gets 302 instead
   ```
   **Issue:** Redirecting to login instead of showing loans.

   **Possible cause:** Session not persisting or password check failing.

   **Debug:** Check if user_password is in session:
   ```python
   with logged_in_client.session_transaction() as sess:
       print(f"Session has user_password: {'user_password' in sess}")
       print(f"Password value: {sess.get('user_password')}")

   response = logged_in_client.get('/')
   ```

**tests/test_bank_connections.py:**

5. **`test_match_with_user_connection`** (line 560)
   ```python
   logged_in_client.post('/', data={'borrower': 'Alice', ...})
   ```
   **Should work now** with the nullable columns fix.

**tests/test_loan_routes.py:**

6. **`test_add_loan_via_dashboard`** (line 62)
   ```python
   response = logged_in_client.post('/', data={'borrower': 'Bob Jones', ...})
   ```
   **Should work now** with the nullable columns fix.

## Quick Test Fixes

Here's a quick patch for the most common issue (querying by borrower name):

```python
# OLD (in test_loan_repayment and test_multiple_repayments):
c.execute("SELECT id FROM loans WHERE borrower = 'Bob'")
loan_id = c.fetchone()[0]

# NEW:
c.execute("SELECT id FROM loans ORDER BY id DESC LIMIT 1")
loan_id = c.fetchone()[0]
```

## Expected Test Results After Fixes

After applying these fixes, all tests should pass:

- ✅ Loan creation works (encrypted data inserted)
- ✅ Loan viewing works (encrypted data decrypted)
- ✅ Borrower portal works (token-based decryption)
- ✅ All old tests still work with encryption layer

## How to Test

1. **Run all tests:**
   ```bash
   pytest
   ```

2. **Run specific failing tests:**
   ```bash
   pytest tests/test_routes.py::test_loan_repayment -v
   pytest tests/test_routes.py::test_multiple_repayments -v
   pytest tests/test_routes.py::test_form_submission -v
   ```

3. **Debug session issues:**
   ```bash
   pytest tests/test_routes.py::test_form_submission -xvs
   ```

The `-xvs` flags mean:
- `-x`: Stop on first failure
- `-v`: Verbose output
- `-s`: Show print statements

## If Tests Still Fail

### Debugging Checklist

1. **Check session has password:**
   ```python
   with logged_in_client.session_transaction() as sess:
       assert 'user_password' in sess
       assert sess['user_password'] == 'testpassword123'
   ```

2. **Check loan was created encrypted:**
   ```python
   c.execute("SELECT borrower, borrower_encrypted, encrypted_dek FROM loans WHERE id = ?", (loan_id,))
   row = c.fetchone()
   assert row[0] is None  # borrower (plaintext) should be NULL
   assert row[1] is not None  # borrower_encrypted should exist
   assert row[2] is not None  # encrypted_dek should exist
   ```

3. **Check decryption works:**
   ```python
   from services.encryption import decrypt_field, extract_dek_from_token

   # Get token from database
   c.execute("SELECT borrower_access_token, borrower_encrypted FROM loans WHERE id = ?", (loan_id,))
   token, borrower_enc = c.fetchone()

   # Decrypt using token
   dek = extract_dek_from_token(token)
   borrower = decrypt_field(borrower_enc, dek)
   assert borrower == 'Alice'
   ```

## Summary

**Fixed:**
- ✅ NOT NULL constraint (migration updated)
- ✅ Session password already configured in conftest

**Need to Update:**
- 🔧 3-4 tests that query by plaintext `borrower` column
- 🔍 Investigate why some tests redirect to login (session persistence issue?)

**Expected Time:** 10-15 minutes to update the tests and verify they pass.
