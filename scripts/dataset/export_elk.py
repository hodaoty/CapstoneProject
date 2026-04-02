#!/usr/bin/env python3
"""
export_elk.py  –  Export ALL documents from mlops-api-logs-* via Scroll API.
Output: elk_raw_export.csv
"""

import csv
import json
import sys
import urllib.request
import urllib.error

ELK_URL   = "http://localhost:9200"
INDEX     = "mlops-api-logs-*"
SCROLL_TTL = "2m"
PAGE_SIZE  = 1000
OUTPUT    = "elk_raw_export.csv"

FIELDS = [
    "@timestamp",
    "auth_token_hash",
    "method",
    "path",
    "path_normalized",
    "remote_ip",
    "request_id",
    "response_size",
    "response_time_ms",
    "sampling_flag",
    "status",
    "upstream",
    "user_agent",
    "user_id_hash",
    "user_role",
    "waf_action",
    "waf_rule_id",
]

# CSV header uses friendly names (replace leading @ for cleanliness)
CSV_HEADER = [f.lstrip("@") if f == "@timestamp" else f for f in FIELDS]


def _post(url: str, body: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    req  = urllib.request.Request(url, data=data,
                                   headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def _delete(url: str) -> None:
    req = urllib.request.Request(url, method="DELETE")
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def extract_row(src: dict) -> list:
    row = []
    for f in FIELDS:
        val = src.get(f, "")
        if val is None:
            val = ""
        row.append(str(val))
    return row


def main():
    print(f"[*] Connecting to {ELK_URL}, index={INDEX}")

    # --- initial search ---
    init_url = f"{ELK_URL}/{INDEX}/_search?scroll={SCROLL_TTL}"
    init_body = {
        "size": PAGE_SIZE,
        "query": {"match_all": {}},
        "_source": FIELDS,
    }

    resp       = _post(init_url, init_body)
    scroll_id  = resp["_scroll_id"]
    hits       = resp["hits"]["hits"]
    total_est  = resp["hits"]["total"]
    if isinstance(total_est, dict):
        total_est = total_est.get("value", "?")

    print(f"[*] Estimated total docs: {total_est}")

    total_exported = 0

    with open(OUTPUT, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(CSV_HEADER)

        while hits:
            for hit in hits:
                src = hit.get("_source", {})
                writer.writerow(extract_row(src))
                total_exported += 1

            if total_exported % 10000 == 0:
                print(f"  ... exported {total_exported:,} docs")

            # next scroll page
            scroll_url  = f"{ELK_URL}/_search/scroll"
            scroll_body = {"scroll": SCROLL_TTL, "scroll_id": scroll_id}
            resp        = _post(scroll_url, scroll_body)
            scroll_id   = resp["_scroll_id"]
            hits        = resp["hits"]["hits"]

    # clean up scroll context
    _delete(f"{ELK_URL}/_search/scroll/{scroll_id}")

    print(f"\n[+] Export complete.")
    print(f"    Total documents exported: {total_exported:,}")
    print(f"    Output file: {OUTPUT}")


if __name__ == "__main__":
    main()
