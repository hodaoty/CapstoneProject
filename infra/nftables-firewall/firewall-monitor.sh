#!/bin/bash
# =============================================================================
# FIREWALL MONITOR v2 - With real IP logging for normal traffic
# Uses conntrack to capture IPs of accepted connections
# =============================================================================

LOG_FILE="/var/log/firewall/firewall.log"
CSV_FILE="/var/log/firewall/traffic.csv"
CONNTRACK_FILE="/tmp/conntrack_ips.txt"
POLL_INTERVAL=1

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# State tracking
declare -A PREV_BLACKLIST
declare -A PREV_VIOLATIONS
declare -A IP_REQUEST_COUNT
declare -A IP_FIRST_SEEN
declare -A LOGGED_CONNECTIONS
PREV_RATE_LIMITED=0
PREV_AUTO_BANNED=0
PREV_DDOS_BLOCKED=0
PREV_NORMAL=0

init_csv() {
    if [ ! -f "$CSV_FILE" ] || [ ! -s "$CSV_FILE" ]; then
        echo "timestamp,src_ip,action,packets,total_requests,time_window_sec,in_violation_list,in_blacklist,requests_per_sec,label" > "$CSV_FILE"
    fi
}

log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case "$level" in
        "BLOCKED") echo -e "${RED}[$timestamp] [$level] $message${NC}" ;;
        "BANNED") echo -e "${RED}[$timestamp] [$level] $message${NC}" ;;
        "RATE-LIMITED") echo -e "${YELLOW}[$timestamp] [$level] $message${NC}" ;;
        "ACCEPT") echo -e "${GREEN}[$timestamp] [$level] $message${NC}" ;;
        "INFO") echo -e "${CYAN}[$timestamp] [$level] $message${NC}" ;;
        *) echo "[$timestamp] [$level] $message" ;;
    esac
}

log_csv() {
    local src_ip="$1"
    local action="$2"
    local packets="$3"
    local label="$4"
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local current_time=$(date +%s)
    
    # Skip if IP is 0.0.0.0 (unknown)
    if [ "$src_ip" == "0.0.0.0" ]; then
        return
    fi
    
    # Track requests per IP
    if [ -z "${IP_FIRST_SEEN[$src_ip]}" ]; then
        IP_FIRST_SEEN[$src_ip]=$current_time
        IP_REQUEST_COUNT[$src_ip]=0
    fi
    
    IP_REQUEST_COUNT[$src_ip]=$((${IP_REQUEST_COUNT[$src_ip]} + packets))
    local time_window=$((current_time - ${IP_FIRST_SEEN[$src_ip]}))
    local total_requests=${IP_REQUEST_COUNT[$src_ip]}
    
    # Calculate requests per second
    local req_per_sec=0
    if [ "$time_window" -gt 0 ]; then
        req_per_sec=$(echo "scale=2; $total_requests / $time_window" | bc 2>/dev/null || echo "0")
    fi
    
    # Check violation/blacklist status
    local in_violation=0
    local in_blacklist=0
    nft list set inet filter rate_limit_violations 2>/dev/null | grep -q "$src_ip" && in_violation=1
    nft list set inet filter ddos_blacklist 2>/dev/null | grep -q "$src_ip" && in_blacklist=1
    
    echo "$timestamp,$src_ip,$action,$packets,$total_requests,$time_window,$in_violation,$in_blacklist,$req_per_sec,$label" >> "$CSV_FILE"
}

# Get real IPs from conntrack for accepted connections
get_accepted_ips() {
    # Get unique source IPs that connected to port 80 or 8080 in last few seconds
    conntrack -L 2>/dev/null | grep -E "dport=(80|8080)" | grep -oE 'src=[0-9.]+' | cut -d= -f2 | sort -u | grep -v "^172\.20\." | head -20
}

get_counter_value() {
    nft list counter inet filter "$1" 2>/dev/null | grep "packets" | awk '{print $2}'
}

get_blacklist_ips() {
    nft list set inet filter ddos_blacklist 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
}

get_violation_ips() {
    nft list set inet filter rate_limit_violations 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
}

print_header() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                NFTABLES DDoS PROTECTION MONITOR v2                ║${NC}"
    echo -e "${BLUE}╠═══════════════════════════════════════════════════════════════════════╣${NC}"
    printf "${BLUE}║${NC}  %-69s ${BLUE}║${NC}\n" "Time: $(date '+%Y-%m-%d %H:%M:%S') | TZ: $(cat /etc/timezone 2>/dev/null || echo 'UTC')"
    printf "${BLUE}║${NC}  %-69s ${BLUE}║${NC}\n" "CSV: $CSV_FILE (for LightGBM)"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_status() {
    local rate_limited="$1" auto_banned="$2" ddos_blocked="$3" normal="$4"
    
    echo -e "${CYAN}┌────────────────────── TRAFFIC COUNTERS ──────────────────────┐${NC}"
    printf "${CYAN}│${NC}  ${GREEN}✓ ACCEPT${NC}        %-12s packets                        ${CYAN}│${NC}\n" "$normal"
    printf "${CYAN}│${NC}  ${YELLOW}⚠ RATE-LIMITED${NC} %-12s packets                        ${CYAN}│${NC}\n" "$rate_limited"
    printf "${CYAN}│${NC}  ${RED}✗ AUTO-BANNED${NC}  %-12s packets                        ${CYAN}│${NC}\n" "$auto_banned"
    printf "${CYAN}│${NC}  ${RED}✗ BLOCKED${NC}      %-12s packets                        ${CYAN}│${NC}\n" "$ddos_blocked"
    echo -e "${CYAN}└───────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # CSV stats
    if [ -f "$CSV_FILE" ]; then
        local total=$(($(wc -l < "$CSV_FILE") - 1))
        local attacks=$(grep -c ",attack$" "$CSV_FILE" 2>/dev/null || echo 0)
        local normals=$(grep -c ",normal$" "$CSV_FILE" 2>/dev/null || echo 0)
        echo -e "${CYAN}┌────────────────────── CSV DATASET ───────────────────────────┐${NC}"
        printf "${CYAN}│${NC}  Records: %-8s │ Normal: %-8s │ Attack: %-8s   ${CYAN}│${NC}\n" "$total" "$normals" "$attacks"
        echo -e "${CYAN}└───────────────────────────────────────────────────────────────┘${NC}"
        echo ""
    fi
    
    # Banned IPs
    local blacklist=$(get_blacklist_ips)
    if [ -n "$blacklist" ]; then
        echo -e "${RED}┌────────────────────── BANNED IPs ────────────────────────────┐${NC}"
        for ip in $blacklist; do
            printf "${RED}│${NC}   %-15s\n" "$ip"
        done
        echo -e "${RED}└───────────────────────────────────────────────────────────────┘${NC}"
        echo ""
    fi
    
    # Violations
    local violations=$(get_violation_ips)
    if [ -n "$violations" ]; then
        echo -e "${YELLOW}┌────────────────────── VIOLATION TRACKER ─────────────────────┐${NC}"
        for ip in $violations; do
            printf "${YELLOW}│${NC}    %-15s (next violation = BAN)\n" "$ip"
        done
        echo -e "${YELLOW}└───────────────────────────────────────────────────────────────┘${NC}"
        echo ""
    fi
}

monitor_loop() {
    print_header
    log_message "INFO" "========== Firewall monitor v2 STARTED =========="
    log_message "INFO" "Now tracking real IPs for normal traffic via conntrack"
    
    while true; do
        local rate_limited=$(get_counter_value "rate_limited")
        local auto_banned=$(get_counter_value "auto_banned")
        local ddos_blocked=$(get_counter_value "ddos_blocked")
        local normal=$(get_counter_value "normal_traffic")
        
        rate_limited=${rate_limited:-0}
        auto_banned=${auto_banned:-0}
        ddos_blocked=${ddos_blocked:-0}
        normal=${normal:-0}
        
        local current_violations=$(get_violation_ips)
        local current_blacklist=$(get_blacklist_ips)
        
        # ===== LOG NORMAL TRAFFIC WITH REAL IPs =====
        if [ "$normal" -gt "$PREV_NORMAL" ]; then
            local diff=$((normal - PREV_NORMAL))
            
            # Get real IPs from conntrack
            local accepted_ips=$(get_accepted_ips)
            
            if [ -n "$accepted_ips" ]; then
                for ip in $accepted_ips; do
                    # Skip if IP is in blacklist (shouldn't happen but just in case)
                    if echo "$current_blacklist" | grep -q "$ip"; then
                        continue
                    fi
                    
                    # Log each IP with portion of the packets
                    local ip_count=$(echo "$accepted_ips" | wc -w)
                    local packets_per_ip=$((diff / ip_count))
                    [ "$packets_per_ip" -lt 1 ] && packets_per_ip=1
                    
                    log_message "ACCEPT" "✓ IP $ip - $packets_per_ip connection(s) ACCEPTED"
                    log_csv "$ip" "ACCEPT" "$packets_per_ip" "normal"
                done
            else
                # Fallback if conntrack doesn't return IPs
                if [ "$diff" -ge 3 ]; then
                    log_message "ACCEPT" "✓ $diff connection(s) ACCEPTED (IP unknown)"
                fi
            fi
        fi
        
        # ===== LOG NEW VIOLATIONS =====
        for ip in $current_violations; do
            if [ -z "${PREV_VIOLATIONS[$ip]}" ]; then
                log_message "RATE-LIMITED" "IP $ip exceeded rate limit"
                log_csv "$ip" "RATE_LIMITED" "1" "attack"
                PREV_VIOLATIONS[$ip]=1
            fi
        done
        
        # ===== LOG NEW BANS =====
        for ip in $current_blacklist; do
            if [ -z "${PREV_BLACKLIST[$ip]}" ]; then
                log_message "BANNED" " IP $ip AUTO-BANNED for 1 HOUR"
                log_csv "$ip" "BANNED" "1" "attack"
                PREV_BLACKLIST[$ip]=1
            fi
        done
        
        # ===== LOG RATE-LIMITED PACKETS =====
        if [ "$rate_limited" -gt "$PREV_RATE_LIMITED" ]; then
            local diff=$((rate_limited - PREV_RATE_LIMITED))
            for ip in $current_violations; do
                log_message "RATE-LIMITED" " IP $ip - $diff packet(s) DROPPED"
                log_csv "$ip" "DROP" "$diff" "attack"
            done
        fi
        
        # ===== LOG BLOCKED PACKETS =====
        if [ "$ddos_blocked" -gt "$PREV_DDOS_BLOCKED" ]; then
            local diff=$((ddos_blocked - PREV_DDOS_BLOCKED))
            for ip in $current_blacklist; do
                log_message "BLOCKED" " IP $ip - $diff packet(s) BLOCKED"
                log_csv "$ip" "BLOCKED" "$diff" "attack"
            done
        fi
        
        # ===== CLEANUP EXPIRED =====
        declare -A CURR_V CURR_B
        for ip in $current_violations; do CURR_V[$ip]=1; done
        for ip in $current_blacklist; do CURR_B[$ip]=1; done
        
        for ip in "${!PREV_VIOLATIONS[@]}"; do
            if [ -z "${CURR_V[$ip]}" ]; then
                log_message "INFO" "✓ IP $ip violation expired"
                unset PREV_VIOLATIONS[$ip]
            fi
        done
        
        for ip in "${!PREV_BLACKLIST[@]}"; do
            if [ -z "${CURR_B[$ip]}" ]; then
                log_message "INFO" "✓ IP $ip UNBANNED"
                unset PREV_BLACKLIST[$ip]
            fi
        done
        unset CURR_V CURR_B
        
        PREV_RATE_LIMITED=$rate_limited
        PREV_AUTO_BANNED=$auto_banned
        PREV_DDOS_BLOCKED=$ddos_blocked
        PREV_NORMAL=$normal
        
        # Refresh display
        print_header
        print_status "$rate_limited" "$auto_banned" "$ddos_blocked" "$normal"
        
        echo -e "${CYAN}═══════════════════════ RECENT LOGS ═══════════════════════${NC}"
        tail -10 "$LOG_FILE" 2>/dev/null | while read line; do
            if [[ "$line" == *"BANNED"* ]] || [[ "$line" == *"BLOCKED"* ]]; then
                echo -e "${RED}$line${NC}"
            elif [[ "$line" == *"RATE-LIMITED"* ]]; then
                echo -e "${YELLOW}$line${NC}"
            elif [[ "$line" == *"ACCEPT"* ]]; then
                echo -e "${GREEN}$line${NC}"
            else
                echo -e "${CYAN}$line${NC}"
            fi
        done
        
        sleep $POLL_INTERVAL
    done
}

# Initialize
mkdir -p /var/log/firewall
touch "$LOG_FILE"
init_csv

monitor_loop
