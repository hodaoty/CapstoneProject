#!/usr/bin/env python3
"""
generate_traffic.py — synthetic API traffic generator for ML training data
100,000 requests: 75,000 benign (label=0) / 25,000 attack (label=1)
Attack types: A=BOLA, B=BrokenAuth, C=RateLimit, D=BFLA (6,250 each)
"""

import argparse
import json
import random
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
BASE_URL = "http://localhost:8888"

USERS = [{"email": f"user{i}@test.com", "password": "password123"} for i in range(1, 21)]

BENIGN_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/121.0",
    "PostmanRuntime/7.36.0",
    "python-requests/2.31.0",
]

ATTACK_AGENTS = [
    "sqlmap/1.7.2#stable",
    "Nikto/2.1.6",
    "curl/7.81.0",
    "python-httpx/0.25.0",
    "Go-http-client/1.1",
    "masscan/1.3.2",
    "dirbuster/1.0-RC1",
]

BENIGN_IPS  = [f"10.0.0.{i}" for i in range(1, 31)]
ATTACK_IPS  = [f"192.168.50.{i}" for i in range(1, 11)]
BURST_IPS   = ["192.168.50.8", "192.168.50.9", "192.168.50.10"]

# ─── SHARED STATE ─────────────────────────────────────────────────────────────
_tokens: dict[str, dict] = {}          # email → {access_token, obtained_at}
_tokens_lock = threading.Lock()
_counters: dict = defaultdict(int)
_counters_lock = threading.Lock()
_last_milestone = 0
_milestone_lock = threading.Lock()

# ─── LOW-LEVEL HTTP ───────────────────────────────────────────────────────────
def _http(method: str, path: str, headers: dict = None,
          body=None, form: bool = False, timeout: int = 5) -> int:
    """Send one HTTP request; return status code (0 on network error)."""
    url = BASE_URL + path
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
        else:
            data = json.dumps(body).encode()

    h = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
    if headers:
        h.update(headers)

    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

# ─── TOKEN MANAGEMENT ─────────────────────────────────────────────────────────
def _login(email: str, password: str) -> str | None:
    """Return access_token string or None on failure."""
    body = {"username": email, "password": password}
    data = urllib.parse.urlencode(body).encode()
    req = urllib.request.Request(
        BASE_URL + "/api/auth/login", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("access_token")
    except Exception:
        return None

def _get_token(email: str, password: str) -> str | None:
    """Return a valid token, re-logging in if older than 25 minutes."""
    with _tokens_lock:
        entry = _tokens.get(email)
        if entry and (time.time() - entry["obtained_at"]) < 1500:  # 25 min
            return entry["access_token"]

    token = _login(email, password)
    if token:
        with _tokens_lock:
            _tokens[email] = {"access_token": token, "obtained_at": time.time()}
    return token

def _tok(user: dict) -> str | None:
    return _get_token(user["email"], user["password"])

def _auth(token: str | None) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}

# ─── STATS ────────────────────────────────────────────────────────────────────
def _record(status: int, label: int):
    global _last_milestone
    with _counters_lock:
        _counters["total"] += 1
        _counters[f"s{status}"] += 1
        _counters[f"label_{label}"] += 1
        if status == 0:
            _counters["errors"] += 1
        total = _counters["total"]

    milestone = total // 1000
    with _milestone_lock:
        global _last_milestone
        if milestone > _last_milestone:
            _last_milestone = milestone
            _print_progress(total)

def _print_progress(total: int):
    with _counters_lock:
        parts = []
        for code in [200, 201, 301, 307, 400, 401, 403, 404, 405, 422, 500]:
            v = _counters.get(f"s{code}", 0)
            if v:
                parts.append(f"{code}={v}")
        errs = _counters["errors"]
        line = " | ".join(parts) or "—"
    print(f"[{total}/{_TOTAL}] sent={total} | {line} | err={errs}", flush=True)

_TOTAL = 0  # set in main()

# ─── BENIGN REQUESTS (label=0) ─────────────────────────────────────────────────
def _benign() -> int:
    user  = random.choice(USERS)
    token = _tok(user)
    ip    = random.choice(BENIGN_IPS)
    ua    = random.choice(BENIGN_AGENTS)
    ah    = {**_auth(token), "X-Forwarded-For": ip, "User-Agent": ua}

    choice = random.randint(1, 7)
    if choice == 1:
        return _http("GET", "/api/products/", headers=ah)
    elif choice == 2:
        pid = random.randint(1, 50)
        return _http("GET", f"/api/products/{pid}", headers=ah)
    elif choice == 3:
        return _http("GET", "/api/products/search?name=phone&category=electronics", headers=ah)
    elif choice == 4:
        idx = random.randint(1, 20)
        return _http("POST", "/api/auth/login",
                     body={"username": f"user{idx}@test.com", "password": "password123"},
                     headers={"X-Forwarded-For": ip, "User-Agent": ua}, form=True)
    elif choice == 5:
        return _http("GET", "/api/cart/", headers={**ah, "X-User-Role": "USER"})
    elif choice == 6:
        body = {"product_id": random.randint(1, 50), "quantity": random.randint(1, 5)}
        return _http("POST", "/api/cart/", headers={**ah, "X-User-Role": "USER"}, body=body)
    else:
        body = {
            "items": [{"product_id": random.randint(1, 10), "quantity": 1}],
            "shipping_address": f"{random.randint(1,999)} Test St, City"
        }
        return _http("POST", "/api/orders/", headers={**ah, "X-User-Role": "USER"}, body=body)

# ─── ATTACK TYPE A — BOLA (label=1) ───────────────────────────────────────────
def _attack_a() -> int:
    user  = random.choice(USERS)
    token = _tok(user)
    h = {**_auth(token), "X-User-Role": "USER",
         "X-Forwarded-For": random.choice(ATTACK_IPS),
         "User-Agent": random.choice(ATTACK_AGENTS)}
    if random.random() < 0.5:
        return _http("GET", "/api/users/by-email/admin@test.com", headers=h)
    else:
        uid = random.randint(1, 100)
        return _http("GET", f"/api/users/{uid}", headers=h)

# ─── ATTACK TYPE B — BROKEN AUTH (label=1) ────────────────────────────────────
def _attack_b() -> int:
    ip = random.choice(ATTACK_IPS)
    ua = random.choice(ATTACK_AGENTS)
    choice = random.randint(1, 3)
    if choice == 1:
        n = random.randint(1, 99999)
        return _http("POST", "/api/auth/login",
                     body={"username": "admin@test.com", "password": f"wrong{n}"},
                     headers={"X-Forwarded-For": ip, "User-Agent": ua}, form=True)
    elif choice == 2:
        return _http("GET", "/api/cart",
                     headers={"X-Forwarded-For": ip, "User-Agent": ua})
    else:
        return _http("POST", "/api/orders",
                     body={}, headers={"X-Forwarded-For": ip, "User-Agent": ua})

# ─── ATTACK TYPE D — BFLA (label=1) ──────────────────────────────────────────
def _attack_d() -> int:
    user  = random.choice(USERS)
    token = _tok(user)
    h = {**_auth(token), "X-User-Role": "USER",
         "X-Forwarded-For": random.choice(ATTACK_IPS),
         "User-Agent": random.choice(ATTACK_AGENTS)}
    if random.random() < 0.5:
        body = {"product_id": random.randint(1, 50), "quantity_change": random.randint(1, 100)}
        return _http("POST", "/api/inventory/update", headers=h, body=body)
    else:
        uid = random.randint(1, 10)
        return _http("DELETE", f"/api/users/{uid}", headers=h)

# ─── ATTACK TYPE C — RATE BURST (label=1, synchronous) ───────────────────────
def _run_bursts(total_c: int):
    """Send all Type-C requests as synchronous bursts on the calling thread."""
    sent = 0
    while sent < total_c:
        burst = random.randint(15, 25)
        ip    = random.choice(BURST_IPS)
        ua    = random.choice(ATTACK_AGENTS)
        for _ in range(min(burst, total_c - sent)):
            n = random.randint(1, 99999)
            status = _http("POST", "/api/auth/login",
                           body={"username": "victim@test.com", "password": f"guess{n}"},
                           headers={"X-Forwarded-For": ip, "User-Agent": ua}, form=True)
            _record(status, 1)
            sent += 1
            time.sleep(random.uniform(0.05, 0.1))
        time.sleep(random.uniform(3, 5))

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    global _TOTAL

    parser = argparse.ArgumentParser(description="API traffic generator")
    parser.add_argument("--total",   type=int, default=100_000, help="Total requests")
    parser.add_argument("--workers", type=int, default=10,      help="Thread pool size")
    parser.add_argument("--dry-run", action="store_true",       help="Validate config, do not send traffic")
    args = parser.parse_args()

    N_TOTAL   = args.total
    N_BENIGN  = int(N_TOTAL * 0.75)
    N_ATTACK  = N_TOTAL - N_BENIGN
    N_PER     = N_ATTACK // 4          # each of A, B, C, D
    N_BENIGN  = N_TOTAL - N_PER * 4   # correct rounding

    _TOTAL = N_TOTAL

    # ── Dry run ───────────────────────────────────────────────────────────────
    if args.dry_run:
        print("=== DRY RUN ===")
        print(f"  Target     : {BASE_URL}")
        print(f"  Total      : {N_TOTAL:,}")
        print(f"  Benign (0) : {N_BENIGN:,}  (≈{N_BENIGN/N_TOTAL*100:.1f}%)")
        print(f"  Attack (1) : {N_PER*4:,}  (≈{N_PER*4/N_TOTAL*100:.1f}%)")
        print(f"    A BOLA   : {N_PER:,}")
        print(f"    B BrAuth : {N_PER:,}")
        print(f"    C Rate   : {N_PER:,}")
        print(f"    D BFLA   : {N_PER:,}")
        print(f"  Workers    : {args.workers}")
        print()
        print("Testing login for user1@test.com …", end=" ", flush=True)
        tok = _login("user1@test.com", "password123")
        if tok:
            print(f"OK  (token: {tok[:40]}…)")
        else:
            print("FAILED — check credentials / service health")
        print("Testing login for admin@test.com …", end=" ", flush=True)
        tok = _login("admin@test.com", "admin123")
        print(f"OK  (token: {tok[:40]}…)" if tok else "FAILED")
        return

    # ── Prefetch all tokens ───────────────────────────────────────────────────
    print("Prefetching tokens for 20 users …")
    ok_count = 0
    for u in USERS:
        t = _get_token(u["email"], u["password"])
        if t:
            ok_count += 1
        else:
            print(f"  WARNING: login failed for {u['email']}")
    print(f"Tokens obtained: {ok_count}/20\n")
    if ok_count == 0:
        print("ERROR: No tokens — aborting.")
        sys.exit(1)

    # ── Build threaded task list (A + B + D + benign, shuffled) ──────────────
    tasks = (
        [(_benign, 0)]   * N_BENIGN +
        [(_attack_a, 1)] * N_PER    +
        [(_attack_b, 1)] * N_PER    +
        [(_attack_d, 1)] * N_PER
    )
    random.shuffle(tasks)

    # Insert N_PER Type-C placeholders evenly throughout the list
    # We'll track how many C we've "reserved" and run them in bursts
    # between threaded chunks instead of inline (keeps shuffle unbiased)
    n_c_remaining = N_PER

    print(f"Starting traffic generation …")
    print(f"  {N_TOTAL:,} requests  |  {args.workers} workers  |  target {BASE_URL}\n")
    start_time = time.time()

    # Split tasks into 10 chunks; run a C-burst between each chunk
    chunk_size = max(1, len(tasks) // 10)
    chunks = [tasks[i:i + chunk_size] for i in range(0, len(tasks), chunk_size)]
    c_per_interval = max(0, n_c_remaining // max(1, len(chunks) - 1)) if len(chunks) > 1 else n_c_remaining

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for chunk_idx, chunk in enumerate(chunks):
            # Submit this chunk
            futs = []
            for fn, label in chunk:
                f = executor.submit(fn)
                futs.append((f, label))

            for f, label in futs:
                try:
                    status = f.result(timeout=10)
                except Exception:
                    status = 0
                _record(status, label)

            # Run a C-burst between chunks (except after the last chunk)
            if chunk_idx < len(chunks) - 1 and n_c_remaining > 0:
                burst_n = min(c_per_interval, n_c_remaining)
                n_c_remaining -= burst_n
                _run_bursts(burst_n)

        # Drain any remaining C requests
        if n_c_remaining > 0:
            _run_bursts(n_c_remaining)

    elapsed = time.time() - start_time
    rps = _counters["total"] / elapsed if elapsed > 0 else 0

    print("\n" + "=" * 50)
    print("FINAL SUMMARY")
    print("=" * 50)
    print(f"Total sent    : {_counters['total']:,}")
    print(f"Elapsed       : {elapsed:.1f}s  ({rps:.1f} req/s)")
    print(f"\nStatus codes:")
    for key in sorted(k for k in _counters if k.startswith("s") and k[1:].isdigit()):
        code = key[1:]
        print(f"  {code:>5} : {_counters[key]:,}")
    print(f"\nLabels:")
    print(f"  benign (0) : {_counters['label_0']:,}")
    print(f"  attack (1) : {_counters['label_1']:,}")
    print(f"\nErrors (timeout/net) : {_counters['errors']:,}")
    print(f"Req/sec              : {rps:.1f}")


if __name__ == "__main__":
    main()
