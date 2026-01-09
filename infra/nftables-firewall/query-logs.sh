#!/bin/bash

show_menu() {
    clear
    echo "=========================================================="
    echo "          FIREWALL LOGS VIEWER"
    echo "=========================================================="
    echo ""
    echo "  1. View all traffic (last 30 lines)"
    echo "  2. Search by IP address"
    echo "  3. Filter by port 80"
    echo "  4. Filter by port 8888"
    echo "  5. Real-time monitoring"
    echo "  6. Show ruleset"
    echo "  7. Ban IP permanently"
    echo "  8. Unban IP"
    echo "  9. Traffic summary"
    echo "  0. Exit"
    echo ""
    echo "=========================================================="
    read -p "Select option: " choice
}

while true; do
    show_menu
    case $choice in
        1)
            echo ""
            echo "ALL TRAFFIC (last 30 lines):"
            echo "=========================================================="
            tail -30 /var/log/firewall/access.log
            echo ""
            read -p "Press Enter to continue..."
            ;;
        2)
            read -p "Enter IP address: " ip
            echo ""
            echo "Results for IP: $ip"
            echo "=========================================================="
            grep "$ip" /var/log/firewall/access.log | tail -30
            echo ""
            read -p "Press Enter to continue..."
            ;;
        3)
            echo ""
            echo "PORT 80 TRAFFIC:"
            echo "=========================================================="
            grep "\.80 " /var/log/firewall/access.log | tail -30
            echo ""
            read -p "Press Enter to continue..."
            ;;
        4)
            echo ""
            echo "PORT 8888 TRAFFIC:"
            echo "=========================================================="
            grep "\.8888 " /var/log/firewall/access.log | tail -30
            echo ""
            read -p "Press Enter to continue..."
            ;;
        5)
            echo ""
            echo "REAL-TIME MONITORING (Ctrl+C to stop)"
            echo "=========================================================="
            tail -f /var/log/firewall/access.log
            ;;
        6)
            echo ""
            echo "CURRENT NFTABLES RULESET:"
            echo "=========================================================="
            nft list ruleset
            echo ""
            read -p "Press Enter to continue..."
            ;;
        7)
            read -p "Enter IP to ban permanently: " ip
            if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                nft add element inet filter permanent_ban { $ip }
                echo "IP $ip has been banned permanently"
            else
                echo "Invalid IP address format"
            fi
            sleep 2
            ;;
        8)
            read -p "Enter IP to unban: " ip
            nft delete element inet filter permanent_ban { $ip } 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "IP $ip has been unbanned"
            else
                echo "IP not found in ban list"
            fi
            sleep 2
            ;;
        9)
            echo ""
            echo "TRAFFIC SUMMARY:"
            echo "=========================================================="
            echo "Total packets logged: $(wc -l < /var/log/firewall/access.log)"
            echo ""
            echo "Top 5 source IPs:"
            grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]+ >' /var/log/firewall/access.log | \
                awk '{print $1}' | cut -d'.' -f1-4 | sort | uniq -c | sort -rn | head -5
            echo ""
            echo "Traffic by port:"
            echo "  Port 80:   $(grep -c '\.80 ' /var/log/firewall/access.log) packets"
            echo "  Port 8888: $(grep -c '\.8888 ' /var/log/firewall/access.log) packets"
            echo ""
            read -p "Press Enter to continue..."
            ;;
        0)
            echo ""
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo ""
            echo "Invalid option!"
            sleep 1
            ;;
    esac
done
