"""Firewall Admin Dashboard — FastAPI backend"""

import os
import re
import json
import secrets
import ipaddress
from pathlib import Path
from typing import Optional

import http.client
import socket
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# ─── Config ───────────────────────────────────────────────────────────────────

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

ACCESS_LOG   = Path("/app/logs/access_json.log")
FIREWALL_LOG = Path("/app/logs/firewall/firewall.log")
TRAFFIC_CSV  = Path("/app/logs/firewall/traffic.csv")

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
    return {"ok": True, "message": f"{ip} added to permanent_ban"}


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
    return {"ok": True, "message": f"{ip} removed from blacklist"}

# ─── Serve SPA ─────────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/{full_path:path}")
async def spa(full_path: str):
    return FileResponse("static/index.html")
