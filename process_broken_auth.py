import pandas as pd
import re
import numpy as np

# ─── Load ─────────────────────────────────────────────────────────────────────
df = pd.read_csv('/home/kali/CapstoneProject/dataset_broken_auth_final.csv')
print(f"Loaded: {df.shape}")

# ─── STEP 1: Relabel ──────────────────────────────────────────────────────────
# Parse timestamp first (needed for rate check)
df['_ts'] = pd.to_datetime(df['@timestamp'], utc=True)

# Start everyone at 0
df['label'] = 0

# BA1 candidates: POST /api/auth/login + status 401
ba1_mask = (df['method'] == 'POST') & (df['path'] == '/api/auth/login') & (df['status'] == 401)
ba1_df = df[ba1_mask].copy()

# Count per IP per minute window
ba1_df['_minute'] = ba1_df['_ts'].dt.floor('min')
rate = ba1_df.groupby(['remote_ip', '_minute']).transform('count')['_ts']
ba1_df['_rate'] = rate

# Keep only those where same IP has >3 in that minute
ba1_final = ba1_df[ba1_df['_rate'] > 3].index
df.loc[ba1_final, 'label'] = 1

print(f"After relabeling - label=1: {(df['label']==1).sum()}, label=0: {(df['label']==0).sum()}")

# ─── STEP 2: Downsample to 40,000 rows (10k attack, 30k benign) ───────────────
df1 = df[df['label'] == 1]
df0 = df[df['label'] == 0]

n1 = min(10000, len(df1))
n0 = min(30000, len(df0))

df1_s = df1.sample(n=n1, random_state=42)
df0_s = df0.sample(n=n0, random_state=42)

df = pd.concat([df1_s, df0_s]).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"After downsample: {df.shape}, label=1: {(df['label']==1).sum()}, label=0: {(df['label']==0).sum()}")

# ─── STEP 3: Reformat columns ─────────────────────────────────────────────────

# @timestamp: 2026-01-01 00:00:00
df['@timestamp'] = df['_ts'].dt.strftime('%Y-%m-%d %H:%M:%S')

# auth_token_hash: '' or 'GUEST' → empty
df['auth_token_hash'] = df['auth_token_hash'].apply(
    lambda x: '' if (pd.isna(x) or str(x).strip() == '' or str(x).strip() == 'GUEST') else x
)

# user_id_hash: '' → empty
df['user_id_hash'] = df['user_id_hash'].apply(
    lambda x: '' if (pd.isna(x) or str(x).strip() == '') else x
)

# user_role: '' → empty (keep USER, ADMIN, GUEST as-is per rules)
df['user_role'] = df['user_role'].apply(
    lambda x: '' if (pd.isna(x) or str(x).strip() == '') else x
)

# waf_action: '' → empty
df['waf_action'] = df['waf_action'].apply(
    lambda x: '' if (pd.isna(x) or str(x).strip() == '') else x
)

# waf_rule_id: NaN or empty → empty
df['waf_rule_id'] = df['waf_rule_id'].apply(
    lambda x: '' if (pd.isna(x) or str(x).strip() == '') else x
)

# response_time_ms: float with 2 decimal places
df['response_time_ms'] = df['response_time_ms'].apply(lambda x: round(float(x), 2))

# path_normalized: apply normalization rules
def normalize_path(path):
    path = str(path)
    # Split path and query string
    if '?' in path:
        path_part, query_part = path.split('?', 1)
    else:
        path_part, query_part = path, None

    # Check if this is a search/filter path (keep as original)
    search_filter_paths = ['/api/products/search', '/api/products/filter',
                           '/api/search', '/api/filter']
    is_search = any(path_part.rstrip('/') == s for s in search_filter_paths)
    if is_search and query_part is not None:
        # Keep as original
        return path

    # Normalize path segments
    segments = path_part.split('/')
    norm_segments = []
    for seg in segments:
        if seg == '':
            norm_segments.append(seg)
            continue
        # Email pattern
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', seg):
            norm_segments.append('{email}')
        # UUID pattern
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', seg, re.I):
            norm_segments.append('{id}')
        # Pure numeric
        elif re.match(r'^\d+$', seg):
            norm_segments.append('{id}')
        # Hex hash (32+ chars)
        elif re.match(r'^[0-9a-f]{32,}$', seg, re.I):
            norm_segments.append('{id}')
        else:
            norm_segments.append(seg)
    norm_path = '/'.join(norm_segments)

    # Normalize query string values (non-search paths)
    if query_part is not None:
        params = query_part.split('&')
        norm_params = []
        for p in params:
            if '=' in p:
                k, v = p.split('=', 1)
                norm_params.append(f"{k}={{id}}")
            else:
                norm_params.append(p)
        return norm_path + '?' + '&'.join(norm_params)

    return norm_path

df['path_normalized'] = df['path'].apply(normalize_path)

# Drop helper columns
df = df.drop(columns=['_ts', '_minute', '_rate'], errors='ignore')

# ─── Final column order ───────────────────────────────────────────────────────
cols = ['@timestamp', 'auth_token_hash', 'method', 'path', 'path_normalized',
        'remote_ip', 'request_id', 'response_size', 'response_time_ms',
        'sampling_flag', 'status', 'upstream', 'user_agent', 'user_id_hash',
        'user_role', 'waf_action', 'waf_rule_id', 'label']
df = df[cols]

# ─── STEP 4: Verify ───────────────────────────────────────────────────────────
print("\n=== First 3 rows ===")
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 200)
print(df.head(3).to_string())

total = len(df)
n1 = (df['label'] == 1).sum()
n0 = (df['label'] == 0).sum()
print(f"\n=== Label Distribution ===")
print(f"Total rows : {total}")
print(f"label=0    : {n0} ({n0/total*100:.2f}%)")
print(f"label=1    : {n1} ({n1/total*100:.2f}%)")

# ─── STEP 5: Save ─────────────────────────────────────────────────────────────
out_path = '/home/kali/CapstoneProject/BrokenAuthentication_cleaned_final_1.csv'
df.to_csv(out_path, index=False)
print(f"\nSaved to {out_path}")
