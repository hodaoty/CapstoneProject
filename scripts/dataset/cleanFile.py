#!/usr/bin/env python3
"""
cleanFile.py  –  Clean raw ELK CSV export for LightGBM dataset.

Usage:
    python3 cleanFile.py <input_csv>

Output:
    dataset_cleaned_for_lightgbm.csv
"""

import sys
import pandas as pd

OUTPUT = "dataset_cleaned_for_lightgbm.csv"

# Columns that must always be present (fill with "" if missing)
REQUIRED_COLS = [
    "timestamp",
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

# Numeric columns – coerce to float, NaN -> 0
NUMERIC_COLS = ["response_size", "response_time_ms"]


def clean(input_path: str) -> None:
    print(f"[*] Reading: {input_path}")
    df = pd.read_csv(input_path, dtype=str, low_memory=False)
    print(f"    Raw shape: {df.shape}")

    # --- 1. Normalise column names ---
    # export_elk.py writes "@timestamp" as "timestamp" already; handle both
    df.columns = [c.strip().lstrip("@") for c in df.columns]

    # --- 2. Ensure all required columns exist ---
    for col in REQUIRED_COLS:
        if col not in df.columns:
            df[col] = ""

    # Keep only the known columns (in order) – drop unexpected extras
    df = df[REQUIRED_COLS]

    # --- 3. Fill NaN / None with empty string for string cols ---
    str_cols = [c for c in REQUIRED_COLS if c not in NUMERIC_COLS]
    df[str_cols] = df[str_cols].fillna("").astype(str)

    # --- 4. Strip whitespace from string columns ---
    df[str_cols] = df[str_cols].apply(lambda col: col.str.strip())

    # --- 5. Normalise auth_token_hash: empty -> "(empty)" marker ---
    df["auth_token_hash"] = df["auth_token_hash"].replace("", "(empty)")

    # --- 6. Numeric coercion ---
    for col in NUMERIC_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # --- 7. Normalise status to string without ".0" suffix ---
    df["status"] = (
        pd.to_numeric(df["status"], errors="coerce")
          .fillna(0)
          .astype(int)
          .astype(str)
    )
    # Restore empty status where original was blank
    df.loc[df["status"] == "0", "status"] = ""

    # --- 8. Uppercase method ---
    df["method"] = df["method"].str.upper()

    # --- 9. Drop exact duplicates ---
    before = len(df)
    df = df.drop_duplicates()
    after = len(df)
    if before != after:
        print(f"    Dropped {before - after:,} duplicate rows")

    # --- 10. Reset index ---
    df = df.reset_index(drop=True)

    # --- Save ---
    df.to_csv(OUTPUT, index=False)
    print(f"\n[+] Clean complete.")
    print(f"    Final shape: {df.shape}")
    print(f"    Output: {OUTPUT}")
    print(f"\n    Column list: {list(df.columns)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cleanFile.py <input_csv>")
        sys.exit(1)
    clean(sys.argv[1])
