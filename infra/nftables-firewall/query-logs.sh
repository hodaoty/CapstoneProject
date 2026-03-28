#!/bin/bash
# =============================================================================
# QUERY LOGS - Utility to query firewall logs
# Usage: query-logs [option]
# =============================================================================

LOG_FILE="/var/log/firewall/firewall.log"
PACKET_LOG="/var/log/firewall/packets.log"

show_help() {
    echo "Usage: query-logs [option]"
    echo ""
    echo "Options:"
    echo "  -a, --all         Show all logs"
    echo "  -b, --banned      Show only banned IPs"
    echo "  -r, --rate        Show rate-limited events"
    echo "  -t, --tail [n]    Show last n lines (default: 50)"
    echo "  -f, --follow      Follow log in real-time"
    echo "  -s, --stats       Show statistics"
    echo "  -p, --packets     Show packet capture log"
    echo "  -c, --counters    Show nftables counters"
    echo "  -l, --lists       Show blacklists"
    echo "  -h, --help        Show this help"
    echo ""
}

show_stats() {
    echo "═══════════════════════════════════════════"
    echo "           FIREWALL STATISTICS"
    echo "═══════════════════════════════════════════"
    echo ""
    
    # Counter stats
    echo "┌─────────────── COUNTERS ───────────────┐"
    nft list counters inet filter 2>/dev/null | grep -E "counter|packets" | \
        awk '/counter/{name=$2} /packets/{print "│ " name ": " $2 " packets"}'
    echo "└─────────────────────────────────────────┘"
    echo ""
    
    # Banned IPs
    local banned_count=$(nft list set inet filter ddos_blacklist 2>/dev/null | grep -cE '([0-9]{1,3}\.){3}[0-9]{1,3}' || echo 0)
    echo "┌─────────────── BANNED IPs ───────────────┐"
    echo "│ Currently banned: $banned_count IPs"
    if [ "$banned_count" -gt 0 ]; then
        nft list set inet filter ddos_blacklist 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}[^}]*' | \
            while read line; do echo "│   - $line"; done
    fi
    echo "└───────────────────────────────────────────┘"
    echo ""
    
    # Log stats
    if [ -f "$LOG_FILE" ]; then
        echo "┌─────────────── LOG STATS ───────────────┐"
        echo "│ Total log entries: $(wc -l < "$LOG_FILE")"
        echo "│ BANNED events: $(grep -c "BANNED" "$LOG_FILE" 2>/dev/null || echo 0)"
        echo "│ RATE-LIMITED events: $(grep -c "RATE-LIMITED" "$LOG_FILE" 2>/dev/null || echo 0)"
        echo "│ BLOCKED events: $(grep -c "BLOCKED" "$LOG_FILE" 2>/dev/null || echo 0)"
        echo "└─────────────────────────────────────────┘"
    fi
}

show_counters() {
    echo "═══════════════════════════════════════════"
    echo "          NFTABLES COUNTERS"
    echo "═══════════════════════════════════════════"
    nft list counters inet filter 2>/dev/null
}

show_lists() {
    echo "═══════════════════════════════════════════"
    echo "           BLACKLISTS & SETS"
    echo "═══════════════════════════════════════════"
    echo ""
    echo ">>> DDoS Blacklist (auto-ban):"
    nft list set inet filter ddos_blacklist 2>/dev/null
    echo ""
    echo ">>> Rate Limit Violations (tracking):"
    nft list set inet filter rate_limit_violations 2>/dev/null
    echo ""
    echo ">>> Permanent Ban List:"
    nft list set inet filter permanent_ban 2>/dev/null
}

case "${1:-}" in
    -a|--all)
        cat "$LOG_FILE" 2>/dev/null || echo "No logs found"
        ;;
    -b|--banned)
        grep -E "BANNED|AUTO-BAN" "$LOG_FILE" 2>/dev/null || echo "No ban events found"
        ;;
    -r|--rate)
        grep "RATE-LIMITED" "$LOG_FILE" 2>/dev/null || echo "No rate-limit events found"
        ;;
    -t|--tail)
        n="${2:-50}"
        tail -n "$n" "$LOG_FILE" 2>/dev/null || echo "No logs found"
        ;;
    -f|--follow)
        tail -f "$LOG_FILE" 2>/dev/null || echo "No logs found"
        ;;
    -s|--stats)
        show_stats
        ;;
    -p|--packets)
        tail -n "${2:-100}" "$PACKET_LOG" 2>/dev/null || echo "No packet logs found"
        ;;
    -c|--counters)
        show_counters
        ;;
    -l|--lists)
        show_lists
        ;;
    -h|--help|"")
        show_help
        ;;
    *)
        echo "Unknown option: $1"
        show_help
        exit 1
        ;;
esac
