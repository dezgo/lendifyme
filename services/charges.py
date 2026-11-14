"""
Itemised charges on a loan — "here's what you owe me for".

A loan can be fed by one or more bank tags, each with a share percentage
(100 = the borrower pays it all, 50 = split, 0 = shown but the lender covers
it). Charges can also be typed in by hand (e.g. home EV charging). Syncing re-reads the tagged
transactions and makes the loan's charges match exactly: new ones are added,
untagged ones removed, changed amounts/shares updated. The loan's amount is
then set to the total of the borrower's shares, so the dashboard, balance,
repayments and borrower portal all keep working unchanged.
"""
import secrets
from services.encryption import encrypt_field
from services import up_bank

# Charges typed in by the lender (not from the bank) use this id prefix, so a
# bank re-sync never removes them.
MANUAL_PREFIX = "manual:"


def get_charge_tags(conn, loan_id):
    c = conn.cursor()
    c.execute(
        "SELECT tag, share_percent FROM loan_charge_tags WHERE loan_id = ? ORDER BY id",
        (loan_id,),
    )
    return [{"tag": r[0], "share_percent": r[1]} for r in c.fetchall()]


def get_charges(conn, loan_id):
    c = conn.cursor()
    c.execute("""
        SELECT id, date, description, full_amount, share_percent, share_amount, tag, pending
        FROM loan_charges WHERE loan_id = ?
        ORDER BY date DESC, id DESC
    """, (loan_id,))
    cols = ["id", "date", "description", "full_amount", "share_percent", "share_amount", "tag", "pending"]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    c.execute("SELECT id FROM loan_charges WHERE loan_id = ? AND source_txn_id LIKE ?",
              (loan_id, MANUAL_PREFIX + "%"))
    manual_ids = {r[0] for r in c.fetchall()}
    for r in rows:
        r["manual"] = r["id"] in manual_ids
    return rows


def save_charge_tags(conn, loan_id, rules):
    c = conn.cursor()
    c.execute("DELETE FROM loan_charge_tags WHERE loan_id = ?", (loan_id,))
    c.executemany(
        "INSERT INTO loan_charge_tags (loan_id, tag, share_percent) VALUES (?, ?, ?)",
        [(loan_id, r["tag"], r["share_percent"]) for r in rules],
    )


def build_charges(rules, transactions_by_tag):
    """
    Pure: turn tagged transactions into charges. A transaction carrying more
    than one of the rule tags takes the higher share.
    """
    charges = {}
    for rule in rules:
        for t in transactions_by_tag.get(rule["tag"], []):
            existing = charges.get(t["id"])
            if existing and existing["share_percent"] >= rule["share_percent"]:
                continue
            charges[t["id"]] = {
                "source_txn_id": t["id"],
                "date": t["date"],
                "description": t["description"],
                "full_amount": round(t["amount"], 2),
                "share_percent": rule["share_percent"],
                "share_amount": round(t["amount"] * rule["share_percent"] / 100, 2),
                "tag": rule["tag"],
                "pending": 1 if t["pending"] else 0,
            }
    return charges


def apply_charges(conn, loan_id, charges, dek):
    """
    Make the loan's charges exactly `charges` and update the loan amount.
    Returns counts {added, updated, removed, total}.
    """
    c = conn.cursor()
    c.execute(
        "SELECT source_txn_id, full_amount, share_percent, pending FROM loan_charges "
        "WHERE loan_id = ? AND source_txn_id NOT LIKE ?",
        (loan_id, MANUAL_PREFIX + "%"),
    )
    existing = {r[0]: r[1:] for r in c.fetchall()}

    removed = [tid for tid in existing if tid not in charges]
    for tid in removed:
        c.execute("DELETE FROM loan_charges WHERE loan_id = ? AND source_txn_id = ?", (loan_id, tid))

    added = updated = 0
    for tid, ch in charges.items():
        if tid in existing:
            if existing[tid] != (ch["full_amount"], ch["share_percent"], ch["pending"]):
                updated += 1
            c.execute("""
                UPDATE loan_charges
                SET date = ?, description = ?, full_amount = ?, share_percent = ?,
                    share_amount = ?, tag = ?, pending = ?
                WHERE loan_id = ? AND source_txn_id = ?
            """, (ch["date"], ch["description"], ch["full_amount"], ch["share_percent"],
                  ch["share_amount"], ch["tag"], ch["pending"], loan_id, tid))
        else:
            added += 1
            c.execute("""
                INSERT INTO loan_charges
                    (loan_id, source_txn_id, date, description, full_amount,
                     share_percent, share_amount, tag, pending)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (loan_id, tid, ch["date"], ch["description"], ch["full_amount"],
                  ch["share_percent"], ch["share_amount"], ch["tag"], ch["pending"]))

    total = update_loan_total(conn, loan_id, dek)
    return {"added": added, "updated": updated, "removed": len(removed), "total": total}


def update_loan_total(conn, loan_id, dek):
    """Set the loan amount to the sum of the borrower's shares. Returns it."""
    c = conn.cursor()
    c.execute("SELECT COALESCE(SUM(share_amount), 0) FROM loan_charges WHERE loan_id = ?", (loan_id,))
    total = round(c.fetchone()[0], 2)
    c.execute(
        "UPDATE loans SET amount_encrypted = ? WHERE id = ?",
        (encrypt_field(str(total), dek), loan_id),
    )
    return total


def has_charges_setup(conn, loan_id):
    """True if this loan is a charges-style loan (has tags or charges)."""
    c = conn.cursor()
    c.execute("""
        SELECT EXISTS (SELECT 1 FROM loan_charges WHERE loan_id = ?)
            OR EXISTS (SELECT 1 FROM loan_charge_tags WHERE loan_id = ?)
    """, (loan_id, loan_id))
    return bool(c.fetchone()[0])


def add_manual_charge(conn, loan_id, date, description, amount, share_percent, dek):
    """Add a hand-entered charge (e.g. home charging) and update the total."""
    conn.execute("""
        INSERT INTO loan_charges
            (loan_id, source_txn_id, date, description, full_amount,
             share_percent, share_amount, tag, pending)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0)
    """, (loan_id, MANUAL_PREFIX + secrets.token_hex(8), date, description,
          round(amount, 2), share_percent, round(amount * share_percent / 100, 2)))
    total = update_loan_total(conn, loan_id, dek)
    conn.commit()
    return total


def remove_manual_charge(conn, loan_id, charge_id, dek):
    """Remove a hand-entered charge. Bank charges are removed by untagging."""
    c = conn.cursor()
    c.execute(
        "DELETE FROM loan_charges WHERE id = ? AND loan_id = ? AND source_txn_id LIKE ?",
        (charge_id, loan_id, MANUAL_PREFIX + "%"),
    )
    removed = c.rowcount
    update_loan_total(conn, loan_id, dek)
    conn.commit()
    return removed


def sync_from_up(conn, loan_id, token, rules, dek):
    """Fetch every rule's tag from Up and apply. Raises up_bank.UpError."""
    available = set(up_bank.list_tags(token))
    missing = [r["tag"] for r in rules if r["tag"] not in available]
    if missing:
        raise up_bank.UpError(
            f"Up has no tag called {', '.join(repr(m) for m in missing)}. "
            f"Your tags are: {', '.join(sorted(available)) or 'none'}."
        )
    by_tag = {r["tag"]: up_bank.fetch_tagged_transactions(token, r["tag"]) for r in rules}
    charges = build_charges(rules, by_tag)
    save_charge_tags(conn, loan_id, rules)
    result = apply_charges(conn, loan_id, charges, dek)
    conn.commit()
    return result
