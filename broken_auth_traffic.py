#!/usr/bin/env python3
"""
Broken Authentication Traffic Generator
Generates requests: 75% benign + 12.5% BA1 + 12.5% BA2

Rate-limit safe design:
- nftables limits to 10 NEW TCP connections/second (burst 15).
- We create SHARED httpx clients with fixed connection pools:
    fast_client : max 5 concurrent connections
    login_client: max 4 concurrent connections
  → max 9 new TCP connections at startup (within burst 15).
- After initial handshake, all requests reuse established connections.
- Login (auth-service) bottleneck: handled by dedicated pool workers.
"""

import argparse
import random
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

# ── CONFIG ────────────────────────────────────────────────────────────────────
DEFAULT_TARGET  = "http://localhost:8888"
DEFAULT_TOTAL   = 100_000
DEFAULT_WORKERS = 10        # workers for fast requests
LOGIN_WORKERS   = 4         # workers for login (auth bottleneck)

# Connection pool sizes — MUST be ≤ burst(15) total across both pools
FAST_POOL_SIZE  = 20        # shared TCP connections for fast requests
LOGIN_POOL_SIZE = 10        # shared TCP connections for login requests

TIMEOUT_FAST  = 10.0
TIMEOUT_LOGIN = 20.0

BENIGN_IPS = [f"10.0.0.{i}" for i in range(1, 31)]
ATTACK_IPS = [f"192.168.50.{i}" for i in range(1, 11)]

BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "python-httpx/0.28.1",
]

ATTACK_UAS = [
    "python-httpx/0.28.1",
    "curl/7.88.1",
    "Go-http-client/1.1",
]

# Users in DB: user7-user20 + admin
BENIGN_USERS = [f"user{i}@test.com" for i in range(7, 21)]

# BA1 targets: NONE of these exist in DB → bcrypt skipped → fast ~0.5s
BA1_TARGETS = [
    "victim@test.com", "user99@test.com", "root@test.com",
    "hacker@test.com", "attacker@test.com", "admin@fake.com",
    "badguy@test.com", "intruder@test.com",
]

PRODUCT_IDS = list(range(1, 51))


# ── SHARED CLIENTS (created in main, passed to workers) ───────────────────────
_fast_client : httpx.Client | None = None
_login_client: httpx.Client | None = None


def make_clients(pool_f: int, pool_l: int) -> tuple[httpx.Client, httpx.Client]:
    limits_f = httpx.Limits(max_connections=pool_f,
                            max_keepalive_connections=pool_f)
    limits_l = httpx.Limits(max_connections=pool_l,
                            max_keepalive_connections=pool_l)
    return (
        httpx.Client(timeout=TIMEOUT_FAST,  limits=limits_f),
        httpx.Client(timeout=TIMEOUT_LOGIN, limits=limits_l),
    )


# ── LOGIN ─────────────────────────────────────────────────────────────────────
def login_users(target: str) -> dict[str, str]:
    tokens: dict[str, str] = {}
    print(f"[*] Logging in {len(BENIGN_USERS)} users (sequential)...", flush=True)
    c = httpx.Client(timeout=20.0)
    for email in BENIGN_USERS:
        try:
            r = c.post(f"{target}/api/auth/login",
                       data={"username": email, "password": "password123"},
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r.status_code == 200:
                tokens[email] = r.json()["access_token"]
            else:
                print(f"  [!] {email}: {r.status_code}", flush=True)
            time.sleep(0.2)   # ≤5 req/s to stay under rate limit
        except Exception as e:
            print(f"  [!] {email}: {e}", flush=True)
    c.close()
    print(f"[*] Tokens: {len(tokens)}/{len(BENIGN_USERS)}", flush=True)
    return tokens


# ── BUILD REQUEST LISTS ───────────────────────────────────────────────────────
def build_all(target: str, total: int, tokens: dict[str, str]):
    n_attack  = total // 4
    n_ba1     = n_attack // 2
    n_ba2     = n_attack - n_ba1
    n_benign  = total - n_ba1 - n_ba2

    fast_reqs : list[dict] = []
    login_reqs: list[dict] = []

    emails = list(tokens.keys())

    btypes    = ["B1", "B2", "B3", "B4", "B5", "B6", "B7"]
    chunk     = n_benign // len(btypes)
    remainder = n_benign - chunk * len(btypes)

    for i, btype in enumerate(btypes):
        count = chunk + (1 if i < remainder else 0)
        for _ in range(count):
            email  = random.choice(emails)
            token  = tokens[email]
            ip     = random.choice(BENIGN_IPS)
            ua     = random.choice(BENIGN_UAS)
            auth_h = {"Authorization": f"Bearer {token}",
                      "X-Forwarded-For": ip, "User-Agent": ua}

            if btype == "B1":
                fast_reqs.append({"method": "GET",
                                   "url": f"{target}/api/products/",
                                   "headers": auth_h})
            elif btype == "B2":
                fast_reqs.append({"method": "GET",
                                   "url": f"{target}/api/products/{random.choice(PRODUCT_IDS)}",
                                   "headers": auth_h})
            elif btype == "B3":
                fast_reqs.append({"method": "GET",
                                   "url": f"{target}/api/products/search?name=phone&category=electronics",
                                   "headers": auth_h})
            elif btype == "B4":
                login_reqs.append({
                    "method": "POST", "url": f"{target}/api/auth/login",
                    "headers": {"X-Forwarded-For": ip, "User-Agent": ua,
                                "Content-Type": "application/x-www-form-urlencoded"},
                    "data": {"username": email, "password": "password123"},
                    "_label": "B4",
                })
            elif btype == "B5":
                h = {**auth_h, "X-User-Role": "USER"}
                fast_reqs.append({"method": "GET", "url": f"{target}/api/cart/",
                                   "headers": h})
            elif btype == "B6":
                h = {**auth_h, "X-User-Role": "USER"}
                fast_reqs.append({"method": "POST", "url": f"{target}/api/cart/",
                                   "headers": h,
                                   "json": {"product_id": random.choice(PRODUCT_IDS),
                                            "quantity": random.randint(1, 5)}})
            elif btype == "B7":
                h = {**auth_h, "X-User-Role": "USER"}
                fast_reqs.append({"method": "POST", "url": f"{target}/api/orders/",
                                   "headers": h,
                                   "json": {"items": [{"product_id": random.randint(1, 10),
                                                        "quantity": 1}],
                                            "shipping_address": f"{random.randint(1,999)} Test St"}})

    # BA1 → login pool
    for _ in range(n_ba1):
        ip    = random.choice(ATTACK_IPS)
        ua    = random.choice(ATTACK_UAS)
        email = random.choice(BA1_TARGETS)
        login_reqs.append({
            "method": "POST", "url": f"{target}/api/auth/login",
            "headers": {"X-Forwarded-For": ip, "User-Agent": ua,
                        "Content-Type": "application/x-www-form-urlencoded"},
            "data": {"username": email,
                     "password": f"wrongpass{random.randint(1000,9999)}"},
            "_label": "BA1",
        })

    # BA2 → fast pool
    private_eps = [
        ("GET",  "/api/cart/",            None),
        ("POST", "/api/cart/",            {"product_id": 1, "quantity": 1}),
        ("POST", "/api/orders/",          {"items": [{"product_id": 1, "quantity": 1}],
                                           "shipping_address": "123 Test St"}),
        ("GET",  "/api/users/",           None),
        ("POST", "/api/inventory/update", {"product_id": 1, "quantity": 10}),
    ]
    for _ in range(n_ba2):
        ip     = random.choice(ATTACK_IPS)
        ua     = random.choice(ATTACK_UAS)
        method, path, body = random.choice(private_eps)
        req = {"method": method, "url": f"{target}{path}",
               "headers": {"X-Forwarded-For": ip, "User-Agent": ua},
               "_label": "BA2"}
        if body:
            req["json"] = body
        fast_reqs.append(req)

    random.shuffle(fast_reqs)
    random.shuffle(login_reqs)
    return fast_reqs, login_reqs


# ── SEND ──────────────────────────────────────────────────────────────────────
def send_req(req: dict, client: httpx.Client) -> int:
    try:
        r = client.request(req["method"], req["url"],
                           headers=req.get("headers", {}),
                           data=req.get("data"),
                           json=req.get("json"))
        return r.status_code
    except Exception:
        return -1


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Broken Auth traffic generator")
    parser.add_argument("--target",  default=DEFAULT_TARGET)
    parser.add_argument("--total",   type=int, default=DEFAULT_TOTAL)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    tokens = login_users(args.target)
    if not tokens:
        print("[!] No tokens. Aborting.", flush=True)
        return

    fast_reqs, login_reqs = build_all(args.target, args.total, tokens)
    n_ba1    = sum(1 for r in login_reqs if r.get("_label") == "BA1")
    n_ba2    = sum(1 for r in fast_reqs  if r.get("_label") == "BA2")
    n_b4     = sum(1 for r in login_reqs if r.get("_label") == "B4")
    n_benign = len(fast_reqs) - n_ba2
    TOTAL    = len(fast_reqs) + len(login_reqs)

    print(f"\n[*] Request plan:", flush=True)
    print(f"    Total         : {TOTAL:,}", flush=True)
    print(f"    Benign fast   : {n_benign:,}  (B1/B2/B3/B5/B6/B7)", flush=True)
    print(f"    Benign login  : {n_b4:,}  (B4)", flush=True)
    print(f"    BA1 attacks   : {n_ba1:,}  (login failures)", flush=True)
    print(f"    BA2 attacks   : {n_ba2:,}  (no token)", flush=True)
    print(f"    Fast workers  : {args.workers} (pool={FAST_POOL_SIZE} connections)", flush=True)
    print(f"    Login workers : {LOGIN_WORKERS} (pool={LOGIN_POOL_SIZE} connections)", flush=True)

    if args.dry_run:
        print("\n[DRY-RUN] No requests sent.", flush=True)
        return

    # Create shared connection pools
    fast_client, login_client = make_clients(FAST_POOL_SIZE, LOGIN_POOL_SIZE)

    counter   = Counter()
    done      = 0
    done_lock = threading.Lock()
    PROGRESS  = 1_000
    start     = time.time()

    def _update(code: int):
        nonlocal done
        key = "err" if code == -1 else str(code)
        with done_lock:
            counter[key] += 1
            done += 1
            d = done
        if d % PROGRESS == 0:
            elapsed  = time.time() - start
            rps      = d / elapsed if elapsed > 0 else 0
            s        = " | ".join(f"{k}={v}" for k, v in sorted(counter.items()))
            print(f"[{d:>7,}/{TOTAL:,}] {s} | {rps:.0f} req/s", flush=True)

    print(f"\n[*] Sending {TOTAL:,} requests...\n", flush=True)

    def run_fast():
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(send_req, req, fast_client): req
                    for req in fast_reqs}
            for fut in as_completed(futs):
                _update(fut.result())

    def run_login():
        with ThreadPoolExecutor(max_workers=LOGIN_WORKERS) as ex:
            futs = {ex.submit(send_req, req, login_client): req
                    for req in login_reqs}
            for fut in as_completed(futs):
                _update(fut.result())

    t_fast  = threading.Thread(target=run_fast,  daemon=True)
    t_login = threading.Thread(target=run_login, daemon=True)

    t_fast.start()
    t_login.start()
    t_fast.join()
    t_login.join()

    fast_client.close()
    login_client.close()

    elapsed = time.time() - start
    print(f"\n{'='*60}", flush=True)
    print(f"DONE in {elapsed:.1f}s  ({TOTAL/elapsed:.0f} req/s)", flush=True)
    print("Status breakdown:", flush=True)
    for k, v in sorted(counter.items()):
        print(f"  {k:>5}: {v:,}", flush=True)
    print(f"BA1 login failures : {n_ba1:,}", flush=True)
    print(f"B4 benign logins   : {n_b4:,}", flush=True)
    print(f"BA2 no-token       : {n_ba2:,}", flush=True)
    print(f"{'='*60}", flush=True)


if __name__ == "__main__":
    main()
