# Input Validation Bug Fixes

## Critical Bug Fixed: Sentry TypeError in send_invite

**Sentry Issue:** https://derekgillett.sentry.io/issues/7036225625/
**Error:** `TypeError: must be real number, not NoneType`
**Location:** `/var/www/lendifyme/templates/send_invite.html` line 91

### Root Cause
The `send_borrower_invite` route in `routes/borrower.py` was querying only plaintext columns (`borrower`, `amount`) which are `NULL` for encrypted loans. When the template tried to format these NULL values:

```html
<p><strong>Loan Amount:</strong> ${{ '%.2f'|format(loan[4]) }}</p>
<p><strong>Amount Repaid:</strong> ${{ '%.2f'|format(loan[5]) }}</p>
```

It raised `TypeError: must be real number, not NoneType`.

### Fix Applied
Updated `routes/borrower.py:150-253` to:
1. Query both plaintext AND encrypted columns
2. Decrypt encrypted fields using DEK
3. Handle NULL values with proper defaults (0.0)
4. Pass properly formatted tuple to template

## Additional Input Validation Fixes

### 1. Repayment Amount Validation (`routes/loan_routes.py`)
**Before:** `payment_amount = float(repayment_amount)` - crashes on invalid input

**After:** Added comprehensive validation:
- Strip whitespace
- Remove currency symbols ($) and thousand separators (,)
- Validate numeric range (> 0, < 999,999,999)
- Graceful error messages for users
- Prevents ValueError crashes

### 2. Loan Creation Validation (`app.py`)
**Before:** `"amount": float(amount_str)` - crashes on invalid input

**After:** Created `_safe_float_parse()` helper function:
- Handles empty strings
- Removes formatting characters
- Validates range
- Returns None on error with user-friendly flash message
- Used for both `amount` and `repayment_amount`

### 3. Loan Edit Validation (`routes/loan_routes.py`)
**Before:** Multiple `float(amount)` and `float(repayment_amount)` - crashes on invalid input

**After:** Added `_safe_float_parse()` helper and validation:
- Validates before processing
- Shows specific error messages
- Redirects back to edit form on error
- Applies to both encrypted and plaintext loan updates

## Comprehensive Test Suite Added

Created `tests/test_input_validation.py` with 50+ test cases covering:

### Input Validation Tests
- Empty values
- Non-numeric strings ("abc", "$100.00", "1,000.00")
- Negative numbers
- Zero values
- Extremely large numbers
- Invalid dates
- XSS attempts (`<script>alert('xss')</script>`)
- SQL injection attempts (`'; DROP TABLE loans;--`)
- CSV injection
- Extremely long text fields

### Authorization Tests
- Users accessing other users' loans
- Cross-user edit attempts
- Cross-user delete attempts
- Cross-user repayment attempts

### Edge Case Tests
- Encrypted loan data handling
- NULL amount_repaid handling
- Malformed CSV data
- Missing CSV columns
- Rate limiting (honeypot, timing)

## Files Modified

1. `routes/borrower.py` - Fixed send_invite route for encrypted loans
2. `routes/loan_routes.py` - Added input validation for repay and edit routes
3. `app.py` - Added input validation for loan creation
4. `tests/test_input_validation.py` - New comprehensive test suite

## Testing Recommendations

Run the full test suite to verify all fixes:

```bash
pytest tests/test_input_validation.py -v
```

Specific tests for the Sentry bug:
```bash
pytest tests/test_input_validation.py::TestSendInviteInputValidation -v
```

## Impact

**Before:** Multiple user input paths could crash with unhandled exceptions
**After:** All numeric inputs are validated, sanitized, and provide user-friendly error messages

**Security:** Protected against:
- SQL injection attempts
- XSS attacks
- CSV injection
- Malformed input causing crashes

**User Experience:** Users now see helpful error messages like:
- "Invalid repayment amount: '$abc'. Please enter a valid number."
- "Repayment amount must be greater than zero"
- Instead of generic 500 errors or silent failures
