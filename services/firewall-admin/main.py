"""Firewall Admin Dashboard — FastAPI backend"""

import os
import re
import json
import secrets
import ipaddress
import csv
import smtplib
from datetime import date, datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import http.client
import socket
import urllib.parse
import urllib.request
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# ─── Config ───────────────────────────────────────────────────────────────────

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
FIREWALL_ADMIN_URL = os.getenv("FIREWALL_ADMIN_URL", "http://localhost:9000")
KIBANA_URL         = os.getenv("KIBANA_URL", "http://localhost:5601")

ACCESS_LOG   = Path("/app/logs/access_json.log")
FIREWALL_LOG = Path("/app/logs/firewall/firewall.log")
TRAFFIC_CSV  = Path("/app/logs/firewall/traffic.csv")

DAILY_CSV_DIR = Path("/app/logs/daily")

# Columns match the LightGBM training data format (dataset_cleaned_for_lightgbm.csv)
# plus a 'label' column appended at the end.
_CSV_COLUMNS = [
    "timestamp", "auth_token_hash", "method", "path", "path_normalized",
    "remote_ip", "request_id", "response_size", "response_time_ms",
    "sampling_flag", "status", "upstream", "user_agent", "user_id_hash",
    "user_role", "waf_action", "waf_rule_id", "label",
]


def _get_daily_csv_path() -> Path:
    DAILY_CSV_DIR.mkdir(parents=True, exist_ok=True)
    return DAILY_CSV_DIR / f"{date.today().isoformat()}.csv"


def _build_csv_row(entry: dict, label: int) -> dict:
    """Map a block/unblock request body to a training-format CSV row."""
    return {
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "auth_token_hash":  "",
        "method":           entry.get("method", ""),
        "path":             entry.get("endpoint", ""),
        "path_normalized":  entry.get("endpoint", ""),
        "remote_ip":        entry.get("ip", ""),
        "request_id":       "",
        "response_size":    entry.get("response_size", 0),
        "response_time_ms": 0,
        "sampling_flag":    0,
        "status":           entry.get("status_code", ""),
        "upstream":         "",
        "user_agent":       "",
        "user_id_hash":     "",
        "user_role":        "",
        "waf_action":       entry.get("attack_type", ""),
        "waf_rule_id":      "",
        "label":            label,
    }


def append_to_daily_csv(entry: dict, label: int) -> None:
    """Append one row to today's daily CSV. Creates the file with headers if needed."""
    path = _get_daily_csv_path()
    row = _build_csv_row(entry, label)
    write_header = not path.exists()
    try:
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
    except Exception as exc:
        print(f"[CSV] ERROR writing daily log: {exc}")


def update_csv_label(ip: str, new_label: int) -> bool:
    """Find ALL rows in today's CSV where remote_ip == ip and update their label.
    Returns True if at least one row was updated, False if no matching row found."""
    path = _get_daily_csv_path()
    if not path.exists():
        return False
    try:
        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        updated = False
        for row in rows:
            if row.get("remote_ip") == ip:
                row["label"] = str(new_label)
                updated = True
        if updated:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS)
                writer.writeheader()
                writer.writerows(rows)
        return updated
    except Exception as exc:
        print(f"[CSV] ERROR updating label for {ip}: {exc}")
        return False

# ─── App & session store ──────────────────────────────────────────────────────

app = FastAPI(title="Firewall Admin Dashboard", docs_url=None, redoc_url=None)
sessions: set[str] = set()

# ─── Docker helper — pure-Python Docker API over Unix socket ─────────────────

DOCKER_SOCKET = "/var/run/docker.sock"
CONTAINER     = "nftables-firewall"


class _UnixConn(http.client.HTTPConnection):
    """HTTPConnection that connects over a Unix domain socket."""

    def __init__(self, socket_path: str):
        super().__init__("localhost")
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._socket_path)
        self.sock = sock


def _docker_post(path: str, body: dict) -> tuple[int, dict]:
    raw = json.dumps(body).encode()
    conn = _UnixConn(DOCKER_SOCKET)
    conn.request(
        "POST", path, body=raw,
        headers={"Content-Type": "application/json",
                 "Content-Length": str(len(raw)),
                 "Host": "localhost"},
    )
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


def _docker_get(path: str) -> tuple[int, dict]:
    conn = _UnixConn(DOCKER_SOCKET)
    conn.request("GET", path, headers={"Host": "localhost"})
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


def _parse_multiplexed(raw: bytes) -> tuple[str, str]:
    """Parse Docker's multiplexed stdout/stderr stream (8-byte header per frame)."""
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    i = 0
    while i + 8 <= len(raw):
        stream = raw[i]
        size   = int.from_bytes(raw[i + 4:i + 8], "big")
        chunk  = raw[i + 8: i + 8 + size].decode("utf-8", errors="replace")
        if stream == 1:
            stdout_parts.append(chunk)
        elif stream == 2:
            stderr_parts.append(chunk)
        i += 8 + size
    return "".join(stdout_parts), "".join(stderr_parts)


def nft_exec(cmd: list[str]) -> tuple[str, str, int]:
    """
    Equivalent of: docker exec nftables-firewall <cmd>
    Uses the Docker HTTP API directly over /var/run/docker.sock.
    """
    try:
        # 1. Create exec instance
        status, data = _docker_post(
            f"/containers/{CONTAINER}/exec",
            {"AttachStdout": True, "AttachStderr": True, "Cmd": cmd},
        )
        if status != 201:
            return "", f"Exec create failed (HTTP {status}): {data}", 1
        exec_id = data["Id"]

        # 2. Start exec and capture output
        raw_body = json.dumps({"Detach": False, "Tty": False}).encode()
        conn = _UnixConn(DOCKER_SOCKET)
        conn.request(
            "POST", f"/exec/{exec_id}/start", body=raw_body,
            headers={"Content-Type": "application/json",
                     "Content-Length": str(len(raw_body)),
                     "Host": "localhost"},
        )
        resp = conn.getresponse()
        raw_output = resp.read()
        stdout, stderr = _parse_multiplexed(raw_output)

        # 3. Inspect to get exit code
        _, inspect = _docker_get(f"/exec/{exec_id}/json")
        exit_code = inspect.get("ExitCode", 0) or 0

        return stdout, stderr, exit_code

    except FileNotFoundError:
        return "", "Docker socket not found at /var/run/docker.sock", 1
    except ConnectionRefusedError:
        return "", "Docker daemon not reachable", 1
    except Exception as e:
        return "", f"Docker API error: {e}", 1

# ─── Email notification ────────────────────────────────────────────────────────

NOTIFY_TO = "duyenptmse184526@fpt.edu.vn"


def build_email_html(
    action: str,
    ip: str,
    reason: str,
    ts: str,
    attack_type: str   = "",
    score: float       = 0.0,
    endpoint: str      = "",
    method: str        = "",
    status_code: str   = "",
    request_count: int = 0,
    trend: str         = "",
) -> str:
    color = "#c0392b" if action == "BLOCKED" else "#27ae60"
    label = "THREAT ALERT - IP HAS BEEN BLOCKED" if action == "BLOCKED" else "NOTIFICATION - IP HAS BEEN UNBLOCKED"

    attack_section = ""
    if attack_type:
        score_bar  = int(min(score, 100))
        trend_text = trend if trend else "Unknown"
        attack_section = f"""
        <tr><td colspan="2" style="padding:12px 16px 4px;font-weight:bold;color:#555;
            border-top:1px solid #eee;">ATTACK INFORMATION</td></tr>
        <tr>
          <td style="padding:4px 16px;color:#888;width:40%">Attack Type</td>
          <td style="padding:4px 16px;font-weight:bold;color:{color}">{attack_type}</td>
        </tr>
        <tr>
          <td style="padding:4px 16px;color:#888">Confidence (LightGBM)</td>
          <td style="padding:4px 16px">
            <div style="background:#eee;border-radius:4px;height:10px;width:200px">
              <div style="background:{color};width:{score_bar}%;height:10px;border-radius:4px"></div>
            </div>
            <span style="font-size:12px;color:#555">{score:.1f}%</span>
          </td>
        </tr>
        <tr>
          <td style="padding:4px 16px;color:#888">Targeted Endpoint</td>
          <td style="padding:4px 16px;font-family:monospace">{method} {endpoint}</td>
        </tr>
        <tr>
          <td style="padding:4px 16px;color:#888">Status Code</td>
          <td style="padding:4px 16px">{status_code if status_code else "N/A"}</td>
        </tr>
        <tr>
          <td style="padding:4px 16px;color:#888">Request Count</td>
          <td style="padding:4px 16px">{request_count if request_count else "N/A"}</td>
        </tr>
        <tr>
          <td style="padding:4px 16px 12px;color:#888">Attack Trend</td>
          <td style="padding:4px 16px 12px">{trend_text}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:30px 0">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#fff;border-radius:8px;overflow:hidden;
                    box-shadow:0 2px 8px rgba(0,0,0,.1)">
        <tr><td style="background:{color};padding:20px 24px">
          <p style="margin:0;color:#fff;font-size:11px;text-transform:uppercase;
                    letter-spacing:1px">API Threat Detection System</p>
          <h1 style="margin:4px 0 0;color:#fff;font-size:20px">{label}</h1>
        </td></tr>
        <tr><td>
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td colspan="2" style="padding:16px 16px 4px;font-weight:bold;
                color:#555">BASIC INFORMATION</td></tr>
            <tr style="background:#fafafa">
              <td style="padding:8px 16px;color:#888;width:40%">IP Address</td>
              <td style="padding:8px 16px;font-weight:bold;
                  font-size:18px;color:{color}">{ip}</td>
            </tr>
            <tr>
              <td style="padding:8px 16px;color:#888">Action</td>
              <td style="padding:8px 16px">
                <span style="background:{color};color:#fff;padding:2px 10px;
                      border-radius:12px;font-size:13px">{action}</span>
              </td>
            </tr>
            <tr style="background:#fafafa">
              <td style="padding:8px 16px;color:#888">Reason</td>
              <td style="padding:8px 16px">{reason}</td>
            </tr>
            <tr>
              <td style="padding:8px 16px;color:#888">Time (UTC)</td>
              <td style="padding:8px 16px">{ts}</td>
            </tr>
            {attack_section}
            <tr><td colspan="2" style="padding:16px;background:#f9f9f9;
                border-top:1px solid #eee">
              <p style="margin:0;font-size:12px;color:#aaa">
                This email was sent by Firewall Admin Dashboard.<br>
                View details at: <a href="{FIREWALL_ADMIN_URL}"
                style="color:{color}">{FIREWALL_ADMIN_URL}</a>
              </p>
            </td></tr>
          </table>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""

_REQUIRED_SMTP_VARS = ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD")


def _smtp_config() -> tuple[str, int, str, str]:
    """Read SMTP credentials from environment. Raises ValueError if any are missing."""
    missing = [v for v in _REQUIRED_SMTP_VARS if not os.getenv(v)]
    if missing:
        raise ValueError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "Set them before starting the service."
        )
    return (
        os.getenv("SMTP_HOST"),
        int(os.getenv("SMTP_PORT")),
        os.getenv("SMTP_USER"),
        os.getenv("SMTP_PASSWORD"),
    )


def send_firewall_email(subject: str, body: str) -> None:
    """Send an HTML email via Gmail SMTP with STARTTLS.

    Credentials are read exclusively from environment variables.
    If SMTP vars are not set the function logs a warning and returns
    without raising so the API response is never blocked by email failure.
    """
    try:
        host, port, user, password = _smtp_config()
    except ValueError as exc:
        print(f"[EMAIL] WARN: {exc}")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = user
    msg["To"]      = NOTIFY_TO
    msg.attach(MIMEText(body, "html", "utf-8"))

    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(user, password)
            smtp.sendmail(user, [NOTIFY_TO], msg.as_string())
        print(f"[EMAIL] Sent: {subject}")
    except Exception as exc:
        print(f"[EMAIL] ERROR sending '{subject}': {exc}")


def send_telegram_message(text: str, ip_to_block: str | None = None) -> None:
    """Send a message to Telegram via Bot API.

    If ip_to_block is provided, attaches an inline keyboard with two buttons:
      - "Block IP ngay"  → callback_data for the webhook to handle
      - "Bo qua / Xem chi tiet" → opens the dashboard URL
    Uses urllib stdlib only — no external dependencies required.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[TELEGRAM] WARN: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.")
        return

    payload: dict = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       text,
        "parse_mode": "HTML",
    }

    if ip_to_block:
        review_url = f"{FIREWALL_ADMIN_URL}/"
        payload["reply_markup"] = {
            "inline_keyboard": [[
                {
                    "text":          "🚫 Block IP Now",
                    "callback_data": f"block:{ip_to_block}",
                },
                {
                    "text": "👁 Skip / View Details",
                    "url":  review_url,
                },
            ]]
        }

    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data    = data,
        headers = {"Content-Type": "application/json"},
        method  = "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[TELEGRAM] Sent OK (status {resp.status})")
    except Exception as exc:
        print(f"[TELEGRAM] ERROR: {exc}")


def _send_tg_with_keyboard(text: str, inline_keyboard: list) -> None:
    """Send a Telegram message with a fully custom inline keyboard."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[TELEGRAM] WARN: credentials not set.")
        return
    payload = {
        "chat_id":      TELEGRAM_CHAT_ID,
        "text":         text,
        "parse_mode":   "HTML",
        "reply_markup": {"inline_keyboard": inline_keyboard},
    }
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=data, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[TELEGRAM] Sent OK (status {resp.status})")
    except Exception as exc:
        print(f"[TELEGRAM] ERROR: {exc}")


def _send_tg_followup(chat_id, text: str) -> None:
    """Send a follow-up plain message to a specific chat (used after webhook actions)."""
    if not TELEGRAM_BOT_TOKEN:
        return
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=data, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:
        print(f"[TELEGRAM] followup error: {exc}")


# ─── Suspicious pattern detection ─────────────────────────────────────────────

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # SQL injection
    (re.compile(
        r"(?i)select\s.+from\s|union\s.+select|insert\s+into\s|update\s.+set\s"
        r"|delete\s+from\s|drop\s+(?:table|database|schema)\b|exec\s*\(|execute\s*\("
        r"|xp_cmdshell|information_schema|sys\.tables"
    ), "SQLi"),
    (re.compile(r"(?i)'\s*(?:or|and)\s*[\d'\"=]|--\s*(?:\n|$)|#\s*(?:\n|$)|/\*.*?\*/|'\s*;"), "SQLi"),
    # XSS
    (re.compile(
        r"(?i)<\s*script\b|javascript\s*:|vbscript\s*:|onerror\s*=|onload\s*="
        r"|onclick\s*=|onfocus\s*=|onmouseover\s*=|<\s*iframe\b"
        r"|alert\s*\(|document\.cookie\b|eval\s*\(|<\s*img[^>]+onerror"
    ), "XSS"),
    # Path traversal
    (re.compile(r"(?i)\.\.[\\/]|%2e%2e[\\/]|%252e%252e|\.\.%2[fF]|\.\.%5[cC]"), "PathTraversal"),
    # Sensitive file access
    (re.compile(
        r"(?i)/etc/(?:passwd|shadow|hosts|sudoers|crontab)"
        r"|/proc/self|/root/\.ssh|/var/log\b|c:\\+windows"
    ), "FileAccess"),
    # Command injection
    (re.compile(
        r"(?i);\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|nc|netcat|python|perl|ruby)\b"
        r"|\$\(|`[^`]{1,200}`"
    ), "CmdInjection"),
    # Obfuscation
    (re.compile(r"(?i)base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|assert\s*\(\s*base64"), "Obfuscation"),
]

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")


def check_threats(entry: dict) -> list[str]:
    text = " ".join(str(entry.get(k, "")) for k in ("url", "body"))
    found: list[str] = []
    seen: set[str] = set()
    for pattern, label in _PATTERNS:
        if label not in seen and pattern.search(text):
            found.append(label)
            seen.add(label)
    return found


def parse_nft_ips(output: str) -> list[str]:
    return list(dict.fromkeys(_IP_RE.findall(output)))  # unique, order-preserving

# ─── Auth helpers ──────────────────────────────────────────────────────────────

def get_token(request: Request) -> Optional[str]:
    return request.cookies.get("session")


def require_auth(request: Request) -> None:
    if get_token(request) not in sessions:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ─── Auth endpoints ────────────────────────────────────────────────────────────

@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = secrets.token_hex(32)
        sessions.add(token)
        resp = JSONResponse({"ok": True})
        resp.set_cookie("session", token, httponly=True, samesite="lax", max_age=86400)
        return resp
    return JSONResponse({"ok": False, "error": "Invalid credentials"}, status_code=401)


@app.post("/api/logout")
async def logout(request: Request):
    sessions.discard(get_token(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp


@app.get("/api/me")
async def me(request: Request):
    return {"authenticated": get_token(request) in sessions}

# ─── Log endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/access-logs")
async def access_logs(request: Request, limit: int = 2000):
    require_auth(request)
    entries: list[dict] = []
    try:
        text = ACCESS_LOG.read_text(errors="replace")
        for line in text.splitlines()[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                entry = {"raw": line, "timestamp": "", "remote_ip": "", "method": "",
                         "url": line, "status": "", "body": ""}
            # Resolve real client IP: x_forwarded_for → real_ip → remote_ip → remote_addr
            xff = entry.get("x_forwarded_for", "").split(",")[0].strip()
            entry["ip"] = (
                xff
                or entry.get("real_ip", "")
                or entry.get("remote_ip", "")
                or entry.get("remote_addr", "")
            )
            threats = check_threats(entry)
            entry["threats"] = threats
            entry["suspicious"] = bool(threats)
            entries.append(entry)
    except FileNotFoundError:
        pass
    entries.reverse()  # newest first
    return {"logs": entries}


@app.get("/api/firewall-logs")
async def firewall_logs(request: Request, limit: int = 2000):
    require_auth(request)
    lines: list[str] = []
    try:
        text = FIREWALL_LOG.read_text(errors="replace")
        lines = [l.rstrip() for l in text.splitlines() if l.strip()][-limit:]
        lines.reverse()
    except FileNotFoundError:
        pass
    return {"logs": lines}

# ─── Blacklist endpoints ───────────────────────────────────────────────────────

@app.get("/api/blacklist")
async def blacklist(request: Request):
    require_auth(request)
    perm_out, perm_err, _ = nft_exec(["nft", "list", "set", "inet", "filter", "permanent_ban"])
    ddos_out, ddos_err, _ = nft_exec(["nft", "list", "set", "inet", "filter", "ddos_blacklist"])
    errors = [e for e in [perm_err, ddos_err] if e]
    return {
        "permanent_ban":  parse_nft_ips(perm_out),
        "ddos_blacklist": parse_nft_ips(ddos_out),
        "errors": errors,
    }


@app.post("/api/block")
async def block_ip(request: Request):
    require_auth(request)
    body = await request.json()
    ip = body.get("ip", "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip!r}")

    _, stderr, rc = nft_exec(
        ["nft", "add", "element", "inet", "filter", "permanent_ban", f"{{ {ip} }}"]
    )
    if rc != 0 and stderr:
        raise HTTPException(500, stderr.strip())

    ts     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    reason = body.get("reason", "").strip() or "No reason provided"
    html_body = build_email_html(
        action        = "BLOCKED",
        ip            = ip,
        reason        = reason,
        ts            = ts,
        attack_type   = body.get("attack_type", ""),
        score         = float(body.get("score", 0)),
        endpoint      = body.get("endpoint", ""),
        method        = body.get("method", ""),
        status_code   = str(body.get("status_code", "")),
        request_count = int(body.get("request_count", 0)),
        trend         = body.get("trend", ""),
    )
    send_firewall_email(f"[FIREWALL] IP {ip} has been BLOCKED", html_body)
    tg_text = (
        f"<b>\u26a0\ufe0f WARNING: IP BLOCKED</b>\n\n"
        f"IP: <code>{ip}</code>\n"
        f"Reason: {reason}\n"
        + (f"Attack Type: <b>{body.get('attack_type')}</b>\n" if body.get("attack_type") else "")
        + (f"Confidence: {float(body.get('score', 0)):.1f}%\n" if body.get("score") else "")
        + (f"Endpoint: <code>{body.get('method', '')} {body.get('endpoint', '')}</code>\n" if body.get("endpoint") else "")
        + (f"Trend: {body.get('trend')}\n" if body.get("trend") else "")
        + f"Time: {ts}"
    )
    send_telegram_message(tg_text, ip_to_block=ip)
    return {"ok": True, "message": f"{ip} added to permanent_ban", "timestamp": ts}


@app.post("/api/unblock")
async def unblock_ip(request: Request):
    require_auth(request)
    body = await request.json()
    ip = body.get("ip", "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip!r}")

    # Try both sets regardless — one will succeed, one may fail silently
    _, _, rc1 = nft_exec(
        ["nft", "delete", "element", "inet", "filter", "ddos_blacklist", f"{{ {ip} }}"]
    )
    _, _, rc2 = nft_exec(
        ["nft", "delete", "element", "inet", "filter", "permanent_ban", f"{{ {ip} }}"]
    )
    if rc1 != 0 and rc2 != 0:
        raise HTTPException(500, f"{ip} not found in any blacklist")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html_body = build_email_html(action="UNBLOCKED", ip=ip, reason="Admin unblock", ts=ts)
    send_firewall_email(f"[FIREWALL] IP {ip} has been UNBLOCKED", html_body)
    send_telegram_message(
        f"<b>\u2705 IP UNBLOCKED</b>\n\nIP: <code>{ip}</code>\nTime: {ts}",
        ip_to_block=None,
    )
    return {"ok": True, "message": f"{ip} removed from blacklist", "timestamp": ts}

# ─── Public v1 endpoints (no authentication) ──────────────────────────────────

@app.post("/api/v1/block")
async def v1_block_ip(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)
    ip = body.get("ip", "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse({"ok": False, "error": f"Invalid IP address: {ip!r}"}, status_code=400)

    _, stderr, rc = nft_exec(
        ["nft", "add", "element", "inet", "filter", "permanent_ban", f"{{ {ip} }}"]
    )
    if rc != 0 and stderr:
        return JSONResponse({"ok": False, "error": stderr.strip()}, status_code=500)

    ts     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    reason = body.get("reason", "").strip() or "No reason provided"
    html_body = build_email_html(
        action        = "BLOCKED",
        ip            = ip,
        reason        = reason,
        ts            = ts,
        attack_type   = body.get("attack_type", ""),
        score         = float(body.get("score", 0)),
        endpoint      = body.get("endpoint", ""),
        method        = body.get("method", ""),
        status_code   = str(body.get("status_code", "")),
        request_count = int(body.get("request_count", 0)),
        trend         = body.get("trend", ""),
    )
    send_firewall_email(f"[FIREWALL] IP {ip} has been BLOCKED", html_body)
    tg_text = (
        f"<b>\u26a0\ufe0f WARNING: IP BLOCKED</b>\n\n"
        f"IP: <code>{ip}</code>\n"
        f"Reason: {reason}\n"
        + (f"Attack Type: <b>{body.get('attack_type')}</b>\n" if body.get("attack_type") else "")
        + (f"Confidence: {float(body.get('score', 0)):.1f}%\n" if body.get("score") else "")
        + (f"Endpoint: <code>{body.get('method', '')} {body.get('endpoint', '')}</code>\n" if body.get("endpoint") else "")
        + (f"Trend: {body.get('trend')}\n" if body.get("trend") else "")
        + f"Time: {ts}"
    )
    send_telegram_message(tg_text, ip_to_block=ip)
    append_to_daily_csv(body, 1)
    return {"ok": True, "ip": ip, "action": "blocked", "timestamp": ts}


@app.post("/api/v1/unblock")
async def v1_unblock_ip(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)
    ip = body.get("ip", "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse({"ok": False, "error": f"Invalid IP address: {ip!r}"}, status_code=400)

    _, _, rc1 = nft_exec(
        ["nft", "delete", "element", "inet", "filter", "ddos_blacklist", f"{{ {ip} }}"]
    )
    _, _, rc2 = nft_exec(
        ["nft", "delete", "element", "inet", "filter", "permanent_ban", f"{{ {ip} }}"]
    )
    if rc1 != 0 and rc2 != 0:
        return JSONResponse({"ok": False, "error": f"{ip} not found in any blacklist"}, status_code=404)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html_body = build_email_html(action="UNBLOCKED", ip=ip, reason="ML auto-unblock", ts=ts)
    send_firewall_email(f"[FIREWALL] IP {ip} has been UNBLOCKED", html_body)
    send_telegram_message(
        f"<b>\u2705 IP UNBLOCKED</b>\n\nIP: <code>{ip}</code>\nTime: {ts}",
        ip_to_block=None,
    )
    append_to_daily_csv(body, 0)
    return {"ok": True, "ip": ip, "action": "unblocked", "timestamp": ts}


@app.get("/api/v1/blocked")
async def v1_blocked():
    perm_out, _, _ = nft_exec(["nft", "list", "set", "inet", "filter", "permanent_ban"])
    ddos_out, _, _ = nft_exec(["nft", "list", "set", "inet", "filter", "ddos_blacklist"])
    return {
        "permanent_ban":  parse_nft_ips(perm_out),
        "ddos_blacklist": parse_nft_ips(ddos_out),
    }

# ─── Daily firewall log endpoint ───────────────────────────────────────────────

DAILY_LOG_DIR = Path("/app/logs/nftables-logs")

_SIMPLIFIED_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| "
    r"SRC=(?P<src>\S+) DST=(?P<dst>\S+) \| "
    r"PROTO=(?P<proto>\S+)"
    r"(?: SPT=(?P<spt>\d+))?"
    r"(?: DPT=(?P<dpt>\d+))?"
    r" \|\s*(?P<flags>.*)$"
)


@app.get("/api/firewall-logs/daily")
async def firewall_logs_daily(date: str = ""):
    if not date:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid date format, use YYYY-MM-DD"}, status_code=400)

    log_file = DAILY_LOG_DIR / f"{date}.log"
    entries = []
    if log_file.exists():
        for line in log_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            m = _SIMPLIFIED_RE.match(line)
            if not m:
                continue
            flags_str = m.group("flags").strip()
            flags = [f for f in flags_str.split() if f] if flags_str else []
            entry: dict = {
                "timestamp": m.group("ts"),
                "src":       m.group("src"),
                "dst":       m.group("dst"),
                "proto":     m.group("proto"),
                "flags":     flags,
            }
            spt = m.group("spt")
            dpt = m.group("dpt")
            if spt:
                entry["spt"] = int(spt)
            if dpt:
                entry["dpt"] = int(dpt)
            entries.append(entry)
    return {"date": date, "entries": entries}

# ─── Daily labeled logs endpoint ──────────────────────────────────────────────

@app.get("/api/daily-labeled-logs")
async def daily_labeled_logs(date: str = ""):
    if not date:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid date format, use YYYY-MM-DD"}, status_code=400)
    csv_file = DAILY_CSV_DIR / f"{date}.csv"
    if not csv_file.exists():
        return {"date": date, "rows": [], "count": 0}
    try:
        with open(csv_file, "r", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        return {"date": date, "rows": rows, "count": len(rows)}
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


# ─── AI notification endpoints (called by realtime-defender) ─────────────────

@app.post("/api/v1/notify")
async def v1_notify(request: Request):
    """Called by realtime-defender for MEDIUM-confidence threats (not yet blocked).
    Sends Telegram alert with 'Block IP Now' and 'Mark as Safe' buttons.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)

    ip           = body.get("ip", "unknown")
    attack_type  = body.get("attack_type", "")
    score        = float(body.get("score", 0))
    endpoint     = body.get("endpoint", "")
    method       = body.get("method", "")
    trend        = body.get("trend", "")

    text = (
        f"<b>⚠️ MEDIUM THREAT - Not Yet Blocked</b>\n\n"
        f"IP: <code>{ip}</code>\n"
        + (f"Attack Type: <b>{attack_type}</b>\n" if attack_type else "")
        + (f"Confidence: {score:.1f}%\n" if score else "")
        + (f"Endpoint: <code>{method} {endpoint}</code>\n" if endpoint else "")
        + (f"Trend: {trend}\n" if trend else "")
    )
    _send_tg_with_keyboard(text, [[
        {"text": "🚫 Block IP Now",   "callback_data": f"block:{ip}"},
        {"text": "✅ Mark as Safe",   "callback_data": f"safe:{ip}"},
    ]])
    return {"ok": True}


@app.post("/api/v1/notify-high-blocked")
async def v1_notify_high_blocked(request: Request):
    """Called by realtime-defender after AUTO-BLOCKING a HIGH-confidence threat.
    Sends Telegram alert with 'Unblock IP' and 'Confirm Attack' buttons.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)

    ip           = body.get("ip", "unknown")
    attack_type  = body.get("attack_type", "")
    score        = float(body.get("score", 0))
    endpoint     = body.get("endpoint", "")
    method       = body.get("method", "")
    trend        = body.get("trend", "")
    status_code  = body.get("status_code", "")

    text = (
        f"<b>🔴 AUTO BLOCKED IP (HIGH)</b>\n\n"
        f"IP: <code>{ip}</code>\n"
        + (f"Attack Type: <b>{attack_type}</b>\n" if attack_type else "")
        + (f"Confidence: {score:.1f}%\n" if score else "")
        + (f"Endpoint: <code>{method} {endpoint}</code>\n" if endpoint else "")
        + (f"Trend: {trend}\n" if trend else "")
        + "IP has been auto-blocked. Do you want to unblock?"
    )
    append_to_daily_csv({
        "ip": ip,
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "attack_type": attack_type,
    }, label=1)
    html_body = build_email_html(
        action="BLOCKED",
        ip=ip,
        reason=f"AI detected HIGH threat - auto-blocked",
        ts=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        attack_type=attack_type,
        score=score,
        endpoint=f"{method} {endpoint}",
    )
    send_firewall_email(f"[HIGH THREAT] IP {ip} auto-blocked", html_body)
    from_time = (datetime.now(timezone.utc) - timedelta(seconds=30)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    to_time   = (datetime.now(timezone.utc) + timedelta(seconds=30)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    rison_g = urllib.parse.quote(f"(time:(from:'{from_time}',to:'{to_time}'))", safe="")
    rison_a = urllib.parse.quote(f"(query:(language:kuery,query:'remote_ip:\"{ip}\"'))", safe="")
    kibana_url = f"{KIBANA_URL}/app/discover#/?_g={rison_g}&_a={rison_a}"
    _send_tg_with_keyboard(text, [[
        {"text": "🔍 View in Kibana", "url": kibana_url},
        {"text": "🔓 Unblock IP",     "callback_data": f"unblock:{ip}"},
    ]])
    return {"ok": True}


# ─── Telegram webhook (handles inline button callbacks) ───────────────────────

@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    update   = await request.json()
    callback = update.get("callback_query")
    if not callback:
        return {"ok": True}

    data       = callback.get("data", "")
    chat_id    = callback["message"]["chat"]["id"]
    message_id = callback["message"]["message_id"]
    cb_id      = callback["id"]

    if data.startswith("block:"):
        ip_target = data.split(":", 1)[1].strip()
        try:
            ipaddress.ip_address(ip_target)
            nft_exec(["nft", "add", "element", "inet", "filter",
                      "permanent_ban", f"{{ {ip_target} }}"])
            append_to_daily_csv({"ip": ip_target}, 1)
            result_text = f"✅ IP {ip_target} has been blocked. Label 1 saved to today's CSV."
        except Exception as exc:
            result_text = f"❌ Error blocking IP {ip_target}: {exc}"
        _answer_callback(cb_id, result_text)
        _edit_message_reply_markup(chat_id, message_id)
        _send_tg_followup(chat_id, result_text)

    elif data.startswith("unblock:"):
        ip_target = data.split(":", 1)[1].strip()
        try:
            ipaddress.ip_address(ip_target)
            nft_exec(["nft", "delete", "element", "inet", "filter",
                      "ddos_blacklist", f"{{ {ip_target} }}"])
            nft_exec(["nft", "delete", "element", "inet", "filter",
                      "permanent_ban", f"{{ {ip_target} }}"])
            updated = update_csv_label(ip_target, 0)
            if not updated:
                append_to_daily_csv({"ip": ip_target}, 0)
            html_body = build_email_html(
                action="UNBLOCKED",
                ip=ip_target,
                reason="Admin unblock via Telegram button",
                ts=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            )
            send_firewall_email(f"[UNBLOCK] IP {ip_target} has been unblocked", html_body)
            result_text = f"🔓 IP {ip_target} has been unblocked. Label 0 updated in today's CSV."
        except Exception as exc:
            result_text = f"❌ Error unblocking IP {ip_target}: {exc}"
        _answer_callback(cb_id, result_text)
        _edit_message_reply_markup(chat_id, message_id)
        _send_tg_followup(chat_id, result_text)

    elif data.startswith("confirm:"):
        ip_target = data.split(":", 1)[1].strip()
        try:
            ipaddress.ip_address(ip_target)
            append_to_daily_csv({"ip": ip_target}, 1)
            result_text = f"✅ Attack confirmed. IP {ip_target} remains blocked. Label 1 saved to today's CSV."
        except Exception as exc:
            result_text = f"❌ Error confirming IP {ip_target}: {exc}"
        _answer_callback(cb_id, result_text)
        _edit_message_reply_markup(chat_id, message_id)
        _send_tg_followup(chat_id, result_text)

    elif data.startswith("safe:"):
        ip_target = data.split(":", 1)[1].strip()
        try:
            ipaddress.ip_address(ip_target)
            append_to_daily_csv({"ip": ip_target}, 0)
            result_text = f"✅ IP {ip_target} marked as safe. Label 0 saved to today's CSV."
        except Exception as exc:
            result_text = f"❌ Error marking IP {ip_target} as safe: {exc}"
        _answer_callback(cb_id, result_text)
        _edit_message_reply_markup(chat_id, message_id)
        _send_tg_followup(chat_id, result_text)

    return {"ok": True}


def _answer_callback(callback_query_id: str, text: str) -> None:
    payload = json.dumps({
        "callback_query_id": callback_query_id,
        "text":              text,
        "show_alert":        True,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery",
        data=payload, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:
        print(f"[TELEGRAM] answerCallbackQuery error: {exc}")


def _edit_message_reply_markup(chat_id, message_id) -> None:
    """Remove inline keyboard after button is pressed."""
    payload = json.dumps({
        "chat_id":      chat_id,
        "message_id":   message_id,
        "reply_markup": {"inline_keyboard": []},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/editMessageReplyMarkup",
        data=payload, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:
        print(f"[TELEGRAM] editMessageReplyMarkup error: {exc}")


# ─── Serve SPA ─────────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/{full_path:path}")
async def spa(full_path: str):
    return FileResponse("static/index.html")
