#!/usr/bin/env python3
"""
add_label.py  –  Add binary label column to cleaned ELK dataset.

Input:  dataset_cleaned_for_lightgbm.csv
Output: dataset_for_leader.csv

Label rules (first match wins, label=1 = attack):
  1. '/api/users/' in path_normalized AND user_role == 'USER'        -> 1  (BOLA)
  2. status == '401' AND method == 'POST'
     AND path_normalized == '/api/auth/login'                        -> 1  (Broken Auth)
  3. status == '401' AND auth_token_hash in ('GUEST','(empty)','')   -> 1  (Broken Auth)
  4. user_role == 'USER' AND path_normalized in
     ['/api/inventory/update', '/api/inventory/{id}']                -> 1  (BFLA)
  5. user_role == 'USER' AND method == 'DELETE'
     AND '/api/users/' in path_normalized                            -> 1  (BFLA)
  6. Everything else                                                 -> 0  (benign)
"""

import pandas as pd

INPUT  = "dataset_cleaned_for_lightgbm.csv"
OUTPUT = "dataset_for_leader.csv"

EXPECTED_COLS = [
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
    "label",
]

BFLA_INV_PATHS = {"/api/inventory/update", "/api/inventory/{id}"}


def assign_label(row) -> int:
    pn   = str(row["path_normalized"])
    role = str(row["user_role"])
    st   = str(row["status"])
    meth = str(row["method"])
    tok  = str(row["auth_token_hash"])

    # Rule 1 – BOLA
    if "/api/users/" in pn and role == "USER":
        return 1

    # Rule 2 – Broken Auth (failed login)
    if st == "401" and meth == "POST" and pn == "/api/auth/login":
        return 1

    # Rule 3 – Broken Auth (missing / guest token)
    if st == "401" and tok in ("GUEST", "(empty)", ""):
        return 1

    # Rule 4 – BFLA (inventory write)
    if role == "USER" and pn in BFLA_INV_PATHS:
        return 1

    # Rule 5 – BFLA (user DELETE by non-admin)
    if role == "USER" and meth == "DELETE" and "/api/users/" in pn:
        return 1

    return 0


def main():
    print(f"[*] Reading: {INPUT}")
    df = pd.read_csv(INPUT, dtype=str, low_memory=False)
    print(f"    Shape: {df.shape}")

    # Apply labeling
    df["label"] = df.apply(assign_label, axis=1)

    # Save
    df.to_csv(OUTPUT, index=False)

    # --- Stats ---
    total = len(df)
    cnt0  = (df["label"] == 0).sum()
    cnt1  = (df["label"] == 1).sum()
    pct0  = cnt0 / total * 100
    pct1  = cnt1 / total * 100

    print(f"\n[+] Labeling complete.")
    print(f"    Total rows  : {total:,}")
    print(f"    label=0 (benign): {cnt0:,}  ({pct0:.2f}%)")
    print(f"    label=1 (attack): {cnt1:,}  ({pct1:.2f}%)")
    print(f"\n    Output: {OUTPUT}")

    # --- Column check ---
    actual_cols = list(df.columns)
    missing = [c for c in EXPECTED_COLS if c not in actual_cols]
    extra   = [c for c in actual_cols if c not in EXPECTED_COLS]

    if not missing and not extra:
        print(f"\n[✓] Column schema matches expected ({len(EXPECTED_COLS)} columns).")
    else:
        if missing:
            print(f"\n[!] Missing columns: {missing}")
        if extra:
            print(f"[!] Extra columns  : {extra}")

    print(f"\n    Columns: {actual_cols}")


if __name__ == "__main__":
    main()
