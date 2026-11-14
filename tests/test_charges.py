"""Itemised charges synced from Up tags."""
import sqlite3
import pytest

from services import up_bank
from services.charges import build_charges


def _txn(tid, amount, date="2026-11-13", desc="Shop", pending=False):
    return {"id": tid, "date": date, "description": desc, "amount": amount, "pending": pending}


FAKE_UP = {
    "Gemma": [_txn("t1", 50.00, desc="Car park"), _txn("t2", 18.99, desc="Tesla", pending=True)],
    "Sydney Gemma": [_txn("t3", 83.00, desc="Two Mountains"), _txn("t4", 24.38, desc="Bar Bubu")],
}


@pytest.fixture
def fake_up(monkeypatch):
    data = {k: list(v) for k, v in FAKE_UP.items()}
    monkeypatch.setattr(up_bank, "list_tags", lambda token: list(data) + ["Bill"])
    monkeypatch.setattr(up_bank, "fetch_tagged_transactions", lambda token, tag, since=None: data.get(tag, []))
    return data


def _make_loan(client, app):
    client.post("/", data={"borrower": "Gemma", "amount": "0.01", "date_borrowed": "2026-11-12",
                           "loan_type": "lending"})
    conn = sqlite3.connect(app.config["DATABASE"])
    loan_id, token = conn.execute("SELECT id, borrower_access_token FROM loans").fetchone()
    conn.close()
    return loan_id, token


SYNC_FORM = {"up_token": "up:yeah:fake", "tag_0": "Gemma", "share_0": "100%",
             "tag_1": "Sydney Gemma", "share_1": "50"}


def test_build_charges_splits_and_prefers_higher_share():
    rules = [{"tag": "A", "share_percent": 50}, {"tag": "B", "share_percent": 100}]
    out = build_charges(rules, {"A": [_txn("x", 10.01), _txn("y", 20)], "B": [_txn("y", 20)]})
    assert out["x"]["share_amount"] == 5.0  # rounded to cents
    assert out["y"]["share_percent"] == 100 and out["y"]["share_amount"] == 20


def test_sync_lists_charges_and_sets_total(logged_in_client, app, fake_up):
    loan_id, token = _make_loan(logged_in_client, app)
    resp = logged_in_client.post(f"/loan/{loan_id}/charges/sync", data=SYNC_FORM)
    assert resp.status_code == 302

    page = logged_in_client.get(f"/loan/{loan_id}/transactions").data.decode()
    # 50 + 18.99 + (83 + 24.38) / 2 = 122.68
    assert "$122.68" in page
    assert "Two Mountains" in page and "pending" in page

    portal = logged_in_client.get(f"/borrower/{token}").data.decode()
    assert "What you owe" in portal
    assert "Car park" in portal and "$41.50" in portal and "$122.68" in portal


def test_resync_drops_untagged_and_payments_reduce_balance(logged_in_client, app, fake_up):
    loan_id, token = _make_loan(logged_in_client, app)
    logged_in_client.post(f"/loan/{loan_id}/charges/sync", data=SYNC_FORM)

    fake_up["Sydney Gemma"] = [t for t in fake_up["Sydney Gemma"] if t["id"] != "t4"]  # untag Bar Bubu
    logged_in_client.post(f"/loan/{loan_id}/charges/sync", data=SYNC_FORM)
    logged_in_client.post(f"/repay/{loan_id}", data={"repayment_amount": "50"})

    portal = logged_in_client.get(f"/borrower/{token}").data.decode()
    assert "Bar Bubu" not in portal
    assert "$110.49" in portal  # 50 + 18.99 + 41.50
    assert "$60.49" in portal   # still owed after paying $50


def test_unknown_tag_shows_available_tags(logged_in_client, app, fake_up):
    loan_id, _ = _make_loan(logged_in_client, app)
    resp = logged_in_client.post(f"/loan/{loan_id}/charges/sync",
                                 data={"up_token": "x", "tag_0": "Gema", "share_0": "100"})
    assert resp.status_code == 400
    assert b"no tag called" in resp.data and b"Sydney Gemma" in resp.data


def test_bad_share_rejected(logged_in_client, app, fake_up):
    loan_id, _ = _make_loan(logged_in_client, app)
    resp = logged_in_client.post(f"/loan/{loan_id}/charges/sync",
                                 data={"up_token": "x", "tag_0": "Gemma", "share_0": "150"})
    assert resp.status_code == 400


def test_cannot_sync_someone_elses_loan(logged_in_client, app, fake_up):
    resp = logged_in_client.post("/loan/999/charges/sync", data=SYNC_FORM)
    assert resp.status_code == 302 and "/loan/999/transactions" not in resp.headers["Location"]
