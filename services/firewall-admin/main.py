"""Firewall Admin Dashboard — FastAPI backend"""

import os
import re
import json
import hashlib
import ipaddress
from pathlib import Path
from typing import Optional

import http.client
import socket
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# ==============================================================================
# CONFIGURATION
# ==============================================================================

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Fixed authentication token using SHA-256 hash
AUTH_TOKEN = hashlib.sha256(f"{ADMIN_USERNAME}:{ADMIN_PASSWORD}_secure_firewall".encode()).hexdigest()

ACCESS_LOG   = Path("/app/logs/access_json.log")
FIREWALL_LOG = Path("/app/logs/firewall/firewall.log")
TRAFFIC_CSV  = Path("/app/logs/firewall/traffic.csv")

app = FastAPI(title="Firewall Admin Dashboard", docs_url=None, redoc_url=None)

# Global dictionary to store metadata of auto-banned IPs (ip -> request_id)
autoban_meta: dict[str, str] = {}

# ==============================================================================
# DOCKER HELPER - PURE PYTHON UNIX SOCKET
# ==============================================================================

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
    """Parse Docker's multiplexed stdout/stderr stream."""
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
    """Execute command in nftables-firewall container."""
    try:
        status, data = _docker_post(
            f"/containers/{CONTAINER}/exec",
            {"AttachStdout": True, "AttachStderr": True, "Cmd": cmd},
        )
        if status != 201:
            return "", f"Exec create failed (HTTP {status}): {data}", 1
        exec_id = data["Id"]

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

        _, inspect = _docker_get(f"/exec/{exec_id}/json")
        exit_code = inspect.get("ExitCode", 0) or 0

        return stdout, stderr, exit_code

    except FileNotFoundError:
        return "", "Docker socket not found", 1
    except ConnectionRefusedError:
        return "", "Docker daemon not reachable", 1
    except Exception as e:
        return "", f"Docker API error: {e}", 1

# ==============================================================================
# AUTHENTICATION HELPERS
# ==============================================================================

def get_token(request: Request) -> Optional[str]:
    return request.cookies.get("session")

def require_auth(request: Request) -> None:
    if get_token(request) != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ==============================================================================
# API ENDPOINTS
# ==============================================================================

@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        resp = JSONResponse({"ok": True})
        resp.set_cookie("session", AUTH_TOKEN, httponly=True, samesite="lax", max_age=86400)
        return resp
    return JSONResponse({"ok": False, "error": "Invalid credentials"}, status_code=401)

@app.post("/api/logout")
async def logout(request: Request):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp

@app.get("/api/me")
async def me(request: Request):
    return {"authenticated": get_token(request) == AUTH_TOKEN}

@app.get("/api/blacklist")
async def blacklist(request: Request):
    require_auth(request)
    perm_out, perm_err, _ = nft_exec(["nft", "list", "set", "inet", "filter", "permanent_ban"])
    ddos_out, ddos_err, _ = nft_exec(["nft", "list", "set", "inet", "filter", "ddos_blacklist"])
    errors = [e for e in [perm_err, ddos_err] if e]
    
    _IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    
    def parse_ips(out):
        return list(dict.fromkeys(_IP_RE.findall(out)))
        
    perm_ips = parse_ips(perm_out)
    ddos_ips = parse_ips(ddos_out)
    
    # Clean up dictionary if IP has expired or been unblocked
    for ip in list(autoban_meta.keys()):
        if ip not in ddos_ips:
            del autoban_meta[ip]
            
    # Convert to objects containing request_id
    perm_list = [{"ip": ip, "request_id": ""} for ip in perm_ips]
    ddos_list = [{"ip": ip, "request_id": autoban_meta.get(ip, "Unknown")} for ip in ddos_ips]
        
    return {
        "permanent_ban": perm_list,
        "ddos_blacklist": ddos_list,
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

@app.post("/api/autoban")
async def autoban_ip(request: Request):
    require_auth(request)
    body = await request.json()
    ip = body.get("ip", "").strip()
    req_id = body.get("request_id", "").strip()
    
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip!r}")

    _, stderr, rc = nft_exec(
        ["nft", "add", "element", "inet", "filter", "ddos_blacklist", f"{{ {ip} }}"]
    )
    if rc != 0 and stderr:
        raise HTTPException(500, stderr.strip())
        
    # Store request_id in metadata dictionary
    if req_id:
        autoban_meta[ip] = req_id
        
    return {"ok": True, "message": f"{ip} auto-banned by AI"}

@app.post("/api/unblock")
async def unblock_ip(request: Request):
    require_auth(request)
    body = await request.json()
    ip = body.get("ip", "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip!r}")

    _, _, rc1 = nft_exec(
        ["nft", "delete", "element", "inet", "filter", "ddos_blacklist", f"{{ {ip} }}"]
    )
    _, _, rc2 = nft_exec(
        ["nft", "delete", "element", "inet", "filter", "permanent_ban", f"{{ {ip} }}"]
    )
    if rc1 != 0 and rc2 != 0:
        raise HTTPException(500, f"{ip} not found in any blacklist")
        
    # Remove from metadata dictionary if present
    if ip in autoban_meta:
        del autoban_meta[ip]
        
    return {"ok": True, "message": f"{ip} removed from blacklist"}

# ==============================================================================
# STATIC FILES & SPA
# ==============================================================================

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/{full_path:path}")
async def spa(full_path: str):
    return FileResponse("static/index.html")