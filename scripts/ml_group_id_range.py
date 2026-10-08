#!/usr/bin/env python3
"""Print the subscriber id range of the MailerLite Gated Tools group.

FIX-5b (@ciso 2026-10-07). Output is ONLY: member count (per status and in
total), lowest id, highest id and the bit-pattern check. Never an e-mail
address, a name or a field: the script reads only the "id" of each record.
Use the two ids as BETA_ID_MIN / BETA_ID_MAX for the beta backfill.

Standard library only. Run it yourself, with the key in the environment:

    MAILERLITE_API_KEY=... python3 scripts/ml_group_id_range.py [GROUP_ID]

GROUP_ID defaults to env GATED_TOOLS_GROUP_ID, then to the Gated Tools group
of api/routers/subscribe.py.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://connect.mailerlite.com/api"
DEFAULT_GROUP_ID = "184092079999157302"   # = api/routers/subscribe.py GATED_TOOLS_GROUP_ID
# Every status, because the backfill sees group membership regardless of status.
STATUSES = ("active", "unsubscribed", "unconfirmed", "bounced", "junk")
PAGE_LIMIT = 1000

# Same constants as api/beta.py (a test keeps them equal).
ID_FIXED_MASK = 0x3FF << 10
ID_FIXED_VALUE = 1 << 10


def has_real_id_shape(value: int) -> bool:
    return value > 0 and (value & ID_FIXED_MASK) == ID_FIXED_VALUE


def _get_json(url: str, api_key: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    })
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < 4:
                time.sleep(int(exc.headers.get("Retry-After") or 5))
                continue
            # status only: the body could carry personal data
            raise SystemExit(f"MailerLite answered HTTP {exc.code}") from None
    raise SystemExit("MailerLite: too many retries")


def iter_ids(api_key: str, group_id: str, status: str, get_json=_get_json):
    """Yield subscriber ids (int) of one status in the group, following the cursor."""
    cursor = None
    while True:
        params = {"limit": PAGE_LIMIT, "filter[status]": status}
        if cursor:
            params["cursor"] = cursor
        url = (f"{API_URL}/groups/{urllib.parse.quote(group_id, safe='')}/subscribers?"
               + urllib.parse.urlencode(params))
        page = get_json(url, api_key)
        for row in page.get("data") or []:
            raw = str(row.get("id", "")) if isinstance(row, dict) else ""
            if raw.isdigit():
                yield int(raw)
        cursor = (page.get("meta") or {}).get("next_cursor")
        if not cursor:
            return


def summarize(counts: dict, ids: list) -> list:
    """Lines to print: counts, min, max, pattern check. Ids only, never e-mails."""
    lines = [f"members {status}: {n}" for status, n in counts.items()]
    lines.append(f"members total: {len(ids)}")
    if not ids:
        lines.append("no ids: range not set")
        return lines
    bad = sum(1 for i in ids if not has_real_id_shape(i))
    lines.append(f"min id: {min(ids)}")
    lines.append(f"max id: {max(ids)}")
    lines.append(f"bit pattern (bit 10 = 1, bits 11-19 = 0): "
                 f"{len(ids) - bad}/{len(ids)} match"
                 + ("" if bad == 0 else f", {bad} DO NOT MATCH -> stop, report before deploy"))
    lines.append(f"env: BETA_ID_MIN={min(ids)} BETA_ID_MAX={max(ids)}")
    return lines


def main(argv) -> int:
    api_key = os.environ.get("MAILERLITE_API_KEY", "")
    if not api_key:
        print("MAILERLITE_API_KEY not set", file=sys.stderr)
        return 2
    group_id = (argv[1] if len(argv) > 1
                else os.environ.get("GATED_TOOLS_GROUP_ID", DEFAULT_GROUP_ID))
    counts, ids = {}, []
    for status in STATUSES:
        found = list(iter_ids(api_key, group_id, status))
        counts[status] = len(found)
        ids.extend(found)
    ids = sorted(set(ids))
    for line in summarize(counts, ids):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
