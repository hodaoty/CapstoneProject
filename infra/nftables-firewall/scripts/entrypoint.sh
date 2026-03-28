#!/bin/bash
# =============================================================================
# ENTRYPOINT — nftables-firewall container
# Merges original init-firewall.sh logic with log rotation + crond.
# =============================================================================
set -e

LOG_DIR="/var/log/firewall"
LOG_FILE="$LOG_DIR/firewall.log"
TCPDUMP_LOG="$LOG_DIR/packets.log"
NFT_LOG="$LOG_DIR/nftables.log"

echo "=========================================="
echo "  Starting nftables DDoS Protection"
echo "=========================================="

mkdir -p "$LOG_DIR"
touch "$LOG_FILE" "$TCPDUMP_LOG" "$NFT_LOG"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Firewall initializing..." >> "$LOG_FILE"

# ── 1. Load nftables rules (pass-all mode) ───────────────────────────────────
echo "[*] Configuring nftables (pass-all + NAT + logging)..."

# Start clean — remove any rules left over from previous runs or block commands
nft flush ruleset

# NAT table: port 80 → frontend (172.20.0.30:8080)
#            port 8888 → api-gateway (172.20.0.20:8080)
nft add table inet nat
nft add chain inet nat prerouting \
    '{ type nat hook prerouting priority -100 ; policy accept ; }'
nft add rule inet nat prerouting tcp dport 80  dnat ip to 172.20.0.30:8080
nft add rule inet nat prerouting tcp dport 8888 dnat ip to 172.20.0.20:8080
nft add chain inet nat postrouting \
    '{ type nat hook postrouting priority 100 ; policy accept ; }'
nft add rule inet nat postrouting masquerade

# Minimal filter table: forward chain with log rule only, policy accept.
# No drop rules — all traffic passes freely (demo / attack-simulation mode).
nft add table inet filter

# Sets required by /api/block endpoint
nft add set inet filter permanent_ban \
    '{ type ipv4_addr ; comment "Manually banned IPs - no expiry" ; }'
nft add set inet filter ddos_blacklist \
    '{ type ipv4_addr ; size 65535 ; flags dynamic,timeout ; timeout 1h ; comment "Auto-banned IPs - 1 hour timeout" ; }'

nft add chain inet filter forward \
    '{ type filter hook forward priority 0 ; policy accept ; }'
nft add rule inet filter forward 'log prefix "nftables: " continue'

echo "[✓] nftables configured: pass-all mode, NAT active, logging enabled"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] nftables configured (pass-all + NAT + log)" >> "$LOG_FILE"

echo ""
echo "[*] Active configuration:"
echo "    - Pass-all mode (no drop rules)"
echo "    - NAT routing intact (port 80 -> frontend, 8888 -> api-gateway)"
echo "    - Traffic logging: $NFT_LOG"
echo ""

# ── 2. Start syslogd + klogd to capture kernel (nftables) log messages ───────
echo "[*] Starting kernel syslog capture..."
# -O: output file  -s 0: unlimited size  -l 7: all priorities (DEBUG+)
syslogd -O "$NFT_LOG" -s 0 -l 7 2>/dev/null || echo "[WARN] syslogd failed — nftables kernel logs may not appear in file"
klogd 2>/dev/null || echo "[WARN] klogd not available"
echo "[✓] Syslog -> $NFT_LOG"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] syslogd started -> $NFT_LOG" >> "$LOG_FILE"

# ── 3. Start tcpdump in background (original logic preserved) ─────────────────
echo "[*] Starting packet capture..."
tcpdump -i eth0 -l -n --immediate-mode -tt \
    'tcp port 8080 or tcp port 80' \
    2>/dev/null | while read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" >> "$TCPDUMP_LOG"
done &
TCPDUMP_PID=$!
echo "[✓] Packet capture started (PID: $TCPDUMP_PID)"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] tcpdump started (PID: $TCPDUMP_PID)" >> "$LOG_FILE"

# ── 4. Run initial log rotation ───────────────────────────────────────────────
echo "[*] Running initial log rotation..."
python3 /scripts/rotate_logs.py
echo "[✓] Initial log rotation done"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Initial log rotation done" >> "$LOG_FILE"

# ── 5. Register cron job: rotate every 30 minutes ────────────────────────────
echo "[*] Registering cron job..."
echo "*/30 * * * * python3 /scripts/rotate_logs.py >> $LOG_FILE 2>&1" | crontab -
echo "[✓] Cron registered (every 30 min)"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Cron registered" >> "$LOG_FILE"

echo ""
echo "[*] Running in daemon mode"
echo "    nftables log : docker exec nftables-firewall tail -f $NFT_LOG"
echo "    firewall log : docker exec nftables-firewall tail -f $LOG_FILE"
echo "    packets log  : docker exec nftables-firewall tail -f $TCPDUMP_LOG"
echo ""
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Startup complete — crond taking over" >> "$LOG_FILE"

# ── 6. Start crond in foreground (keeps container alive, replaces wait) ───────
exec crond -f
