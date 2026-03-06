#!/bin/bash
# =============================================================================
# INIT FIREWALL - Start nftables and monitoring services
# =============================================================================

set -e

LOG_DIR="/var/log/firewall"
LOG_FILE="$LOG_DIR/firewall.log"
TCPDUMP_LOG="$LOG_DIR/packets.log"

echo "=========================================="
echo "  Starting nftables DDoS Protection"
echo "=========================================="

# Create log directory
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
touch "$TCPDUMP_LOG"

# Initialize log
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Firewall initializing..." >> "$LOG_FILE"

# Load nftables rules
echo "[*] Loading nftables rules..."
nft -f /etc/nftables.conf
echo "[✓] nftables rules loaded successfully"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] nftables rules loaded" >> "$LOG_FILE"

# Show loaded rules summary
echo ""
echo "[*] Active protection:"
echo "    - Rate limit: 10 requests/second (burst: 15)"
echo "    - Violation timeout: 30 seconds"
echo "    - Auto-ban after: 3 violations"
echo "    - Ban duration: 1 hour"
echo ""

# Start tcpdump in background for packet capture (optional detailed logging)
echo "[*] Starting packet capture..."
tcpdump -i eth0 -l -n --immediate-mode -tt \
    'tcp port 8080 or tcp port 80' \
    2>/dev/null | while read line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" >> "$TCPDUMP_LOG"
done &
TCPDUMP_PID=$!
echo "[✓] Packet capture started (PID: $TCPDUMP_PID)"

# Check if running in interactive mode
if [ -t 0 ]; then
    echo ""
    echo "[*] Starting interactive monitor..."
    echo "    Press Ctrl+C to exit"
    echo ""
    sleep 2
    /firewall-monitor.sh
else
    echo ""
    echo "[*] Running in background mode"
    echo "    View logs: docker exec nftables-firewall tail -f /var/log/firewall/firewall.log"
    echo "    Interactive: docker exec -it nftables-firewall /firewall-monitor.sh"
    echo ""
    
    # Start monitor in background (non-interactive)
    /firewall-monitor.sh &
    MONITOR_PID=$!
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Monitor started (PID: $MONITOR_PID)" >> "$LOG_FILE"
    
    # Keep container running
    wait $TCPDUMP_PID
fi
