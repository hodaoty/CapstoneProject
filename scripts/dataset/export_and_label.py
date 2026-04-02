#!/usr/bin/env python3
"""
export_and_label.py — Export Broken Authentication logs from Elasticsearch
                       and label them for ML training.

Export window: only documents newer than EXPORT_FROM (set in Step 0).

=== LABEL RULES (first match wins: BA1 → BA2 → BA3) ===

RULE BA1 — Brute-force login (velocity-based):
  Candidates : status==401 AND method=='POST'
               AND path_normalized=='/api/auth/login'
  Count      : per (remote_ip, 1-minute floor window)
  label = 1  : count > 3  (attack burst)
  label = 0  : count <= 3 (isolated failure, benign)

RULE BA2 — Protocol violation on private API:
  Private endpoints:
    /api/cart, /api/orders, /api/users,
    /api/inventory/update, /api/users/by-email/{email}
  label = 1  : status==401 AND auth_token_hash=='' AND path IN private
               (single occurrence is enough — no velocity threshold)

RULE BA3 — Successful unauthorised access:
  label = 1  : status==200 AND auth_token_hash=='' AND path IN private

label = 0 for everything else.
"""

import json
import re
import time
from datetime import datetime

import pandas as pd
import requests

# ── CONFIG ────────────────────────────────────────────────────────────────────
ES_URL     = "http://localhost:9200"
INDEX_PATT = "mlops-api-logs-*"
PAGE_SIZE  = 1_000
OUT_RAW    = "elk_raw_export_broken_auth.csv"
OUT_FINAL  = "dataset_broken_auth_final.csv"

# Timestamp recorded in Step 0 — only export docs NEWER than this
EXPORT_FROM = "2026-03-09T03:49:19Z"

# Expected final column order (18 columns, label last)
EXPECTED_COLS = [
    "@timestamp", "auth_token_hash", "method", "path", "path_normalized",
    "remote_ip", "request_id", "response_size", "response_time_ms",
    "sampling_flag", "status", "upstream", "user_agent", "user_id_hash",
    "user_role", "waf_action", "waf_rule_id", "label",
]

# ── STEP 1: SCROLL EXPORT ─────────────────────────────────────────────────────
def scroll_export(es_url: str, index: str, gte: str, page_size: int) -> list[dict]:
    """Scroll through all docs newer than `gte` and return flat list of dicts."""
    query = {
        "size": page_size,
        "query": {
            "range": {
                "@timestamp": {"gte": gte}
            }
        },
        "_source": True,
    }

    # Initiate scroll
    url = f"{es_url}/{index}/_search?scroll=2m"
    resp = requests.post(url, json=query, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    scroll_id = data["_scroll_id"]
    hits      = data["hits"]["hits"]
    all_docs  = list(hits)
    total_est = data["hits"]["total"]["value"]

    print(f"[*] Total docs matching query: {total_est:,}")
    print(f"[*] Scrolling pages (page_size={page_size})...")

    page = 1
    while hits:
        scroll_resp = requests.post(
            f"{es_url}/_search/scroll",
            json={"scroll": "2m", "scroll_id": scroll_id},
            timeout=60,
        )
        scroll_resp.raise_for_status()
        scroll_data = scroll_resp.json()
        scroll_id   = scroll_data["_scroll_id"]
        hits        = scroll_data["hits"]["hits"]
        all_docs.extend(hits)
        page += 1
        if page % 10 == 0 or not hits:
            print(f"  page {page:>4} | fetched {len(all_docs):,} / {total_est:,}")

    # Clean up scroll context
    try:
        requests.delete(f"{es_url}/_search/scroll",
                        json={"scroll_id": scroll_id}, timeout=10)
    except Exception:
        pass

    print(f"[*] Scroll complete. Total docs fetched: {len(all_docs):,}")
    return all_docs


def docs_to_df(docs: list[dict]) -> pd.DataFrame:
    """Flatten Elasticsearch hits into a DataFrame."""
    rows = []
    for doc in docs:
        row = {"_id": doc["_id"], "_index": doc["_index"]}
        row.update(doc.get("_source", {}))
        rows.append(row)
    return pd.DataFrame(rows)


# ── STEP 2: CLEAN ─────────────────────────────────────────────────────────────
def clean_df(df: pd.DataFrame) -> pd.DataFrame:
    print(f"\n[*] Raw shape: {df.shape}")

    # Drop .keyword columns
    kw_cols = [c for c in df.columns if c.endswith(".keyword")]
    df = df.drop(columns=kw_cols, errors="ignore")

    # Drop metadata / redundant columns
    drop_cols = [
        "_id", "_index", "_score", "@version", "event.original",
        "host.name", "log.file.path", "schema",
    ]
    df = df.drop(columns=drop_cols, errors="ignore")

    # Numeric conversions
    if "response_time_ms" in df.columns:
        df["response_time_ms"] = pd.to_numeric(df["response_time_ms"], errors="coerce")
    if "response_size" in df.columns:
        df["response_size"] = pd.to_numeric(df["response_size"], errors="coerce").astype("Int64")

    # Deduplicate by request_id
    before = len(df)
    if "request_id" in df.columns:
        df = df.drop_duplicates(subset=["request_id"])
    after = len(df)
    if before != after:
        print(f"  Deduped request_id: {before} → {after} rows")

    # Fill missing auth / role columns
    for col in ["auth_token_hash", "user_id_hash", "user_role"]:
        if col in df.columns:
            df[col] = df[col].fillna("GUEST").replace("", "GUEST")

    if "waf_action" in df.columns:
        df["waf_action"] = df["waf_action"].fillna("ALLOW").replace("", "ALLOW")

    # Parse and sort by timestamp
    if "@timestamp" in df.columns:
        df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
        df = df.sort_values("@timestamp").reset_index(drop=True)

    print(f"[*] Cleaned shape: {df.shape}")
    print(f"[*] Columns ({len(df.columns)}): {sorted(df.columns.tolist())}")
    return df


# ── STEP 3: LABEL ─────────────────────────────────────────────────────────────
def add_labels(df: pd.DataFrame) -> tuple:
    """Assign label=1 for BA1/BA2/BA3 attacks, label=0 for benign.

    Returns (df, ba1_mask, ba2_mask, ba3_mask).
    First match wins: BA1 → BA2 → BA3.
    """
    status = df.get("status", pd.Series(dtype=str)).astype(str).str.strip()
    method = df.get("method", pd.Series(dtype=str)).astype(str).str.strip().str.upper()
    path_n = df.get("path_normalized", pd.Series(dtype=str)).astype(str).str.strip()
    token  = df.get("auth_token_hash", pd.Series(dtype=str)).astype(str).str.strip()

    # After clean_df, empty/missing tokens are stored as "GUEST"
    no_token = token.isin(["GUEST", "(empty)", "", "nan"])

    # ── BA1: brute-force login (velocity-based) ────────────────────────────────
    # Candidates: 401 + POST + /api/auth/login
    # Label=1 only when same remote_ip appears > 3 times in a 1-minute window
    ba1_cand_mask = (status == "401") & (method == "POST") & (path_n == "/api/auth/login")
    df["_ts_window"] = df["@timestamp"].dt.floor("1min")
    ba1_counts = (
        df[ba1_cand_mask]
        .groupby(["remote_ip", "_ts_window"])
        .size()
        .rename("_ba1_count")
    )
    df = df.join(ba1_counts, on=["remote_ip", "_ts_window"])
    df["_ba1_count"] = df["_ba1_count"].fillna(0).astype(int)
    ba1_mask = ba1_cand_mask & (df["_ba1_count"] > 3)

    # ── BA2: protocol violation on private API (single occurrence) ─────────────
    # 401 + no auth token + private endpoint (not login page)
    PRIVATE_PATHS = {
        "/api/cart",
        "/api/orders",
        "/api/users",
        "/api/inventory/update",
        "/api/users/by-email/{email}",
    }
    ba2_mask = (status == "401") & no_token & path_n.isin(PRIVATE_PATHS) & ~ba1_mask

    # ── BA3: successful unauthorised access ────────────────────────────────────
    # 200 + no auth token + private endpoint
    ba3_mask = (status == "200") & no_token & path_n.isin(PRIVATE_PATHS) & ~ba1_mask & ~ba2_mask

    # ── Assign labels (first match wins: BA1 → BA2 → BA3) ─────────────────────
    df["label"] = 0
    df.loc[ba3_mask, "label"] = 1
    df.loc[ba2_mask, "label"] = 1
    df.loc[ba1_mask, "label"] = 1

    # Drop temporary helper columns
    df = df.drop(columns=["_ts_window", "_ba1_count"], errors="ignore")

    print(f"\n[*] Labels assigned:")
    print(f"    BA1 (brute-force login, >3/min) : {ba1_mask.sum():,}")
    print(f"    BA2 (401, no token, private)    : {ba2_mask.sum():,}")
    print(f"    BA3 (200, no token, private)    : {ba3_mask.sum():,}")

    return df, ba1_mask, ba2_mask, ba3_mask


# ── STEP 4: REORDER & SAVE ────────────────────────────────────────────────────
def reorder_and_save(df: pd.DataFrame, out_path: str) -> pd.DataFrame:
    # Keep only expected columns that exist; fill missing with ''
    present = [c for c in EXPECTED_COLS if c in df.columns]
    missing = [c for c in EXPECTED_COLS if c not in df.columns]
    if missing:
        print(f"  [!] Missing expected columns (will use empty): {missing}")
        for c in missing:
            df[c] = ""

    df_out = df[EXPECTED_COLS].copy()

    # Convert @timestamp back to ISO string for CSV
    if "@timestamp" in df_out.columns:
        df_out["@timestamp"] = df_out["@timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S.%f").str[:-3] + "Z"

    df_out.to_csv(out_path, index=False)
    print(f"[*] Saved: {out_path}  ({len(df_out):,} rows × {len(df_out.columns)} cols)")
    return df_out


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("Broken Authentication Dataset Export & Label")
    print(f"EXPORT_FROM : {EXPORT_FROM}")
    print(f"ES index    : {INDEX_PATT}")
    print("=" * 60)

    # ── Export ────────────────────────────────────────────────────────────────
    docs = scroll_export(ES_URL, INDEX_PATT, EXPORT_FROM, PAGE_SIZE)
    df   = docs_to_df(docs)

    # Save raw
    df_raw = df.copy()
    if "@timestamp" in df_raw.columns:
        # stringify for raw CSV
        df_raw["@timestamp"] = df_raw["@timestamp"].astype(str)
    df_raw.to_csv(OUT_RAW, index=False)
    print(f"[*] Raw export saved: {OUT_RAW}  ({len(df_raw):,} rows)")

    # ── Clean ─────────────────────────────────────────────────────────────────
    df = clean_df(df)

    # ── Label ─────────────────────────────────────────────────────────────────
    df, ba1_mask, ba2_mask, ba3_mask = add_labels(df)

    # Capture sample rows per rule BEFORE reorder_and_save drops extra cols
    sample_cols = ["@timestamp", "remote_ip", "method", "path_normalized",
                   "status", "auth_token_hash", "label"]
    ba1_sample = df[ba1_mask][sample_cols].head(2)
    ba2_sample = df[ba2_mask][sample_cols].head(2)
    ba3_sample = df[ba3_mask][sample_cols].head(2)

    # ── Save final ────────────────────────────────────────────────────────────
    df_final = reorder_and_save(df, OUT_FINAL)

    # ── Report ────────────────────────────────────────────────────────────────
    n_total  = len(df_final)
    n_benign = (df_final["label"] == 0).sum()
    n_attack = (df_final["label"] == 1).sum()

    print("\n" + "=" * 60)
    print("FINAL REPORT")
    print("=" * 60)
    print(f"Total rows      : {n_total:,}")
    print(f"label=0 (benign): {n_benign:,}  ({n_benign/n_total*100:.1f}%)")
    print(f"label=1 (attack): {n_attack:,}  ({n_attack/n_total*100:.1f}%)")
    print()
    print(f"Per-rule breakdown (label=1 rows):")
    print(f"  BA1 (brute-force login, >3/min) : {ba1_mask.sum():,}")
    print(f"  BA2 (401, no token, private)    : {ba2_mask.sum():,}")
    print(f"  BA3 (200, no token, private)    : {ba3_mask.sum():,}")
    print()

    print("── BA1 sample (2 rows) ──────────────────────────────────")
    print(ba1_sample.to_string(index=False))
    print()
    print("── BA2 sample (2 rows) ──────────────────────────────────")
    print(ba2_sample.to_string(index=False))
    print()
    print("── BA3 sample (2 rows) ──────────────────────────────────")
    print(ba3_sample.to_string(index=False))
    print()

    # Verify timestamp is first, label is last
    cols = list(df_final.columns)
    assert cols[0]  == "@timestamp", f"First column should be @timestamp, got {cols[0]}"
    assert cols[-1] == "label",      f"Last column should be label, got {cols[-1]}"
    print("[OK] @timestamp is first column, label is last column.")
    print("=" * 60)


if __name__ == "__main__":
    main()
