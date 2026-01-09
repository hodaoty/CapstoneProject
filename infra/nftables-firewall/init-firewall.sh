#!/bin/bash

echo "=========================================================="
echo "   NFTABLES FIREWALL WITH TCPDUMP LOGGING"
echo "=========================================================="
echo ""

mkdir -p /var/log/firewall
touch /var/log/firewall/access.log
touch /var/log/firewall/accepted.log
touch /var/log/firewall/dropped.log

echo "Loading nftables rules..."
nft -f /etc/nftables.conf

if [ $? -ne 0 ]; then
    echo "ERROR: nftables failed to load!"
    exit 1
fi
echo "OK: nftables rules loaded"
echo ""

echo "=========================================================="
echo "                 FIREWALL RULESET"
echo "=========================================================="
echo ""
nft list ruleset | head -40
echo ""

echo "Starting tcpdump to capture traffic..."
tcpdump -i any -n -l \
    'tcp port 80 or tcp port 8888' \
    2>/dev/null | while read line; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $line" | tee -a /var/log/firewall/access.log
done &

TCPDUMP_PID=$!
sleep 2

if ! kill -0 $TCPDUMP_PID 2>/dev/null; then
    echo "ERROR: tcpdump failed to start!"
    exit 1
fi
echo "OK: tcpdump started (PID: $TCPDUMP_PID)"
echo ""

echo "=========================================================="
echo "              FIREWALL READY"
echo "=========================================================="
echo ""
echo "View logs:"
echo "   docker exec nftables-firewall tail -f /var/log/firewall/access.log"
echo "   docker exec -it nftables-firewall query-logs"
echo ""
echo "Monitoring traffic on ports 80 and 8888..."
echo "=========================================================="
echo ""

wait $TCPDUMP_PID

