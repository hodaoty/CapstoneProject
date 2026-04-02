# API Attack Detection System - Flow Documentation

---

## 1. System Overview

The system is a containerized e-commerce platform with an integrated real-time AI threat detection and response layer. It consists of **7 application microservices**, **3 data stores**, **3 observability services**, and **2 security services**, all orchestrated via Docker Compose on a private bridge network (`172.20.0.0/16`).

### Key Components

| Component | Role |
|---|---|
| `nftables-firewall` | Reverse proxy (port 80/8888); enforces IP blocklists using nftables |
| `api-gateway` (Nginx) | Routes HTTP traffic to backend microservices; writes JSON access logs |
| `logstash` | Tails Nginx JSON logs and ships them to Elasticsearch |
| `elasticsearch` | Stores all API access logs; queried by realtime-defender |
| `realtime-defender` | Polls ES every 5 seconds, runs LightGBM inference, triggers actions |
| `firewall-admin` | FastAPI dashboard (port 9000): manual block/unblock, email+Telegram alerts, daily CSV |
| `kibana` | Log visualization (port 5601) |

---

## 2. Main Detection Flow

```
HTTP Request
    │
    ▼
nftables-firewall (port 80)
    │  Checks ddos_blacklist / permanent_ban
    │  Blocked IPs → dropped immediately
    ▼
api-gateway (Nginx)
    │  Proxies to backend microservices
    │  Writes structured JSON to logs_data/api-gateway/access_json.log
    ▼
logstash
    │  Tails access_json.log via file input
    │  Parses and enriches log fields
    │  Pushes to Elasticsearch index: mlops-api-logs-*
    ▼
realtime-defender (polls every 5 seconds)
    │  Queries ES for logs in the last 30-second window
    │  Deduplicates by request_id
    │  Calls build_features() to compute rolling features
    │  Runs LightGBM model → probability score (0.0 – 1.0)
    ▼
Classification
    ├── score >= 0.80  → HIGH
    ├── score >= 0.50  → MEDIUM
    └── score <  0.50  → LOW
```

### Thresholds (realtime_defender.py)

| Level | Condition | Action |
|---|---|---|
| HIGH | score >= 0.8 | Auto-block + notify |
| MEDIUM | 0.5 <= score < 0.8 | Alert admin, no block |
| LOW | score < 0.5 | Log only |

---

## 3. HIGH Threat Flow

```
LightGBM score >= 0.80
    │
    ▼
execute_block_ip()
    │  docker exec nftables-firewall nft add element inet filter ddos_blacklist
    │  { <IP> timeout 1h }
    │  Returns True if block succeeded
    ▼
notify_high_blocked()  →  POST /api/v1/notify-high-blocked (firewall-admin)
    │
    ├── append_to_daily_csv(label=1)       # written immediately
    │
    ├── build_email_html(action="BLOCKED") 
    │   send_firewall_email("[HIGH THREAT] IP {ip} auto-blocked")
    │
    └── _send_tg_with_keyboard()
            Buttons:
            [🔍 View in Kibana]  [🔓 Unblock IP → callback: unblock:<ip>]
```

### Admin presses "Unblock IP" (Telegram webhook):

```
POST /telegram/webhook  (callback_data = "unblock:<ip>")
    │
    ├── nft delete element ddos_blacklist { <ip> }
    ├── nft delete element permanent_ban  { <ip> }
    ├── update_csv_label(ip, 0)           # or append label=0 if not found
    ├── build_email_html(action="UNBLOCKED")
    │   send_firewall_email("[UNBLOCK] IP {ip} has been unblocked")
    └── _send_tg_followup("🔓 IP unblocked")
```

---

## 4. MEDIUM Threat Flow

```
LightGBM score 0.50 – 0.79
    │
    ▼
POST /api/v1/notify (firewall-admin)
    │
    └── _send_tg_with_keyboard()
            Message: "MEDIUM THREAT DETECTED\nIP / Attack Type / Confidence / Endpoint"
            Buttons:
            [Block IP → callback: block:<ip>]  [Ignore → callback: safe:<ip>]
```

### Admin presses "Block IP":

```
POST /telegram/webhook  (callback_data = "block:<ip>")
    ├── nft add element permanent_ban { <ip> }
    ├── append_to_daily_csv(label=1)
    └── _send_tg_followup("✅ IP blocked")
```

### Admin presses "Ignore":

```
POST /telegram/webhook  (callback_data = "safe:<ip>")
    ├── append_to_daily_csv(label=0)
    └── _send_tg_followup("✅ IP marked as safe")
```

> Note: No email is sent for MEDIUM — admin decisions are acknowledged via Telegram only.

---

## 5. LOW Threat Flow

```
LightGBM score < 0.50
    │
    ▼
POST /api/v1/notify-low (firewall-admin)
    │
    └── append_to_daily_csv(label=0)   # silent, no Telegram, no email
```

No blocking or alerting occurs. Traffic is recorded as benign for model retraining.

---

## 6. Daily CSV

Each day a new CSV file is created automatically at:

```
logs_data/daily/YYYY-MM-DD.csv
```

Mapped into `firewall-admin` container at `/app/logs/daily/` (writable volume).

### Columns

```
timestamp, auth_token_hash, method, path, path_normalized,
remote_ip, request_id, response_size, response_time_ms,
sampling_flag, status, upstream, user_agent, user_id_hash,
user_role, waf_action, waf_rule_id, label
```

Column `label`: `1` = attack, `0` = benign.

### How labels are written

| Event | Label | Written by |
|---|---|---|
| HIGH threat detected | 1 | `v1_notify_high_blocked` |
| Admin unblocks a HIGH IP | 0 | Telegram webhook `unblock:` |
| Admin blocks a MEDIUM IP | 1 | Telegram webhook `block:` |
| Admin ignores a MEDIUM IP | 0 | Telegram webhook `safe:` |
| LOW traffic | 0 | `v1_notify_low` |

### Dashboard access

- **View**: Firewall Logs tab → Daily Labeled Logs section → select date → Load
- **Download**: same section → "Download CSV" button → calls `GET /api/daily-labeled-logs/download?date=YYYY-MM-DD`

---

## 7. Firewall Admin Dashboard (port 9000)

URL: `http://localhost:9000` — login required (`ADMIN_USERNAME` / `ADMIN_PASSWORD`).

### Access Logs tab
- Streams last 2000 Nginx JSON log entries
- Client-side pattern matching: SQLi, XSS, Path Traversal, Command Injection, etc.
- Suspicious requests highlighted; manual block available per IP

### Firewall Logs tab
- Live nftables firewall log (raw packet drop events)
- **Daily Labeled Logs** sub-section: tabular view + download of daily CSV

### Blacklist tab
- Shows current `ddos_blacklist` (temporary) and `permanent_ban` (permanent) sets
- Manual block/unblock with reason; triggers email + Telegram on each action

---

## 8. Key Files

| File | Purpose |
|---|---|
| `services/firewall-admin/main.py` | FastAPI backend: all API endpoints, email/Telegram helpers, CSV logic |
| `ai/run/realtime_defender.py` | Main detection loop: ES polling, LightGBM inference, threat handling |
| `ai/features/common_features.py` | Feature engineering: builds rolling-window feature vectors from raw logs |
| `ai/models/lightgbm_threatAPI_detector.pkl` | Trained LightGBM binary classifier (attack vs. benign) |
| `docker-compose.yml` | Full service orchestration, network config, env injection |
| `infra/api-gateway/nginx.conf` | Nginx reverse proxy config; JSON access log format definition |
| `infra/logstash/pipeline/logstash.conf` | Logstash pipeline: file input → filter → Elasticsearch output |
| `infra/nftables-firewall/nftables.conf` | nftables ruleset; defines `ddos_blacklist` and `permanent_ban` sets |

---

## 9. Services and Ports

| Service | Exposed Port | Internal Port | Role |
|---|---|---|---|
| `nftables-firewall` | 80, 8888 | 80, 8888 | Firewall + reverse proxy entry point |
| `firewall-admin` | 9000 | 9000 | Admin dashboard (FastAPI) |
| `api-gateway` | — (internal) | 8080 | Nginx routing to microservices |
| `frontend-service` | — (internal) | 8080 | SPA frontend |
| `user-service` | — (internal) | 8000 | User management (FastAPI + PostgreSQL) |
| `auth-service` | — (internal) | 8001 | JWT authentication (FastAPI + Redis) |
| `product-service` | — (internal) | 8002 | Product catalog (FastAPI + MySQL) |
| `inventory-service` | — (internal) | 8003 | Inventory management (FastAPI + MySQL) |
| `cart-service` | — (internal) | 8004 | Shopping cart (FastAPI + Redis) |
| `order-service` | — (internal) | 8005 | Order processing (FastAPI + PostgreSQL) |
| `payment-service` | — (internal) | 8006 | Payment handling (FastAPI + PostgreSQL) |
| `postgres-db` | 5432 | 5432 | PostgreSQL (users, orders, payments) |
| `mysql-db` | 3307 | 3306 | MySQL (products, inventory) |
| `redis-db` | 6379 | 6379 | Redis (sessions, cart) |
| `elasticsearch` | 9200 | 9200 | Log storage + AI query target |
| `logstash` | 5000, 9600 | 5000, 9600 | Log ingestion pipeline |
| `kibana` | 5601 | 5601 | Log visualization |
| `realtime-defender` | — (none) | — | AI detection loop (outbound only) |

---

## 10. Environment Variables

Create a `.env` file in the project root with the following variables:

### Email (SMTP)

| Variable | Description | Example |
|---|---|---|
| `SMTP_HOST` | SMTP server hostname | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port (STARTTLS) | `587` |
| `SMTP_USER` | Sender Gmail address | `you@gmail.com` |
| `SMTP_PASSWORD` | Gmail app password | `xxxx xxxx xxxx xxxx` |

### Telegram

| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot API token from @BotFather |
| `TELEGRAM_CHAT_ID` | Target chat or group ID (negative for groups) |

### Dashboard URLs

| Variable | Default | Description |
|---|---|---|
| `FIREWALL_ADMIN_URL` | `http://localhost:9000` | Public URL of the admin dashboard (used in email links) |
| `KIBANA_URL` | `http://localhost:5601` | Kibana URL (used in HIGH threat Telegram button) |

### Auth

| Variable | Default |
|---|---|
| `ADMIN_USERNAME` | `admin` |
| `ADMIN_PASSWORD` | `admin123` |

> All variables are injected at container startup via `docker-compose.yml`. The system will start without email/Telegram configured but those notification features will be silently disabled.
