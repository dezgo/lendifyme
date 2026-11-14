"""
Up Bank (api.up.com.au) — read-only pull of tagged transactions.

Used to fill a loan's itemised charges from transactions the lender has tagged
in the Up app (e.g. "Gemma" = hers, "Sydney Gemma" = shared). The personal
access token is passed in per request and never stored.
"""
import requests

BASE_URL = "https://api.up.com.au/api/v1"
TIMEOUT = 15


class UpError(Exception):
    """A problem talking to Up that's worth showing the user."""


def _get(url, token, params=None):
    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        raise UpError("Couldn't reach Up. Try again in a minute.") from e
    if resp.status_code == 401:
        raise UpError("Up didn't accept that access token. It may have expired — make a new one at api.up.com.au.")
    if resp.status_code >= 400:
        raise UpError(f"Up returned an error ({resp.status_code}).")
    return resp.json()


def list_tags(token):
    """Return every tag name on the Up account."""
    tags = []
    url, params = f"{BASE_URL}/tags", {"page[size]": 100}
    while url:
        data = _get(url, token, params)
        tags.extend(t["id"] for t in data.get("data", []))
        url, params = data.get("links", {}).get("next"), None
    return tags


def fetch_tagged_transactions(token, tag, since=None):
    """
    Return transactions carrying `tag`, newest first.

    Each item: {id, date (YYYY-MM-DD, local), description, amount, pending}
    where `amount` is what was SPENT (positive for a purchase, negative for a
    refund) — i.e. the opposite sign to Up's own value.
    """
    params = {"filter[tag]": tag, "page[size]": 100}
    if since:
        params["filter[since]"] = f"{since}T00:00:00+00:00"
    url = f"{BASE_URL}/transactions"
    out = []
    while url:
        data = _get(url, token, params)
        for t in data.get("data", []):
            a = t["attributes"]
            out.append({
                "id": t["id"],
                "date": a["createdAt"][:10],
                "description": a.get("description") or "",
                "amount": -float(a["amount"]["value"]),
                "pending": a.get("status") == "HELD",
            })
        url, params = data.get("links", {}).get("next"), None
    return out
