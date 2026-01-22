FROM alpine:latest

# Install required packages
RUN apk add --no-cache \
    nftables \
    tcpdump \
    bash \
    coreutils \
    dos2unix \
    grep \
    gawk

# Create log directory
RUN mkdir -p /var/log/firewall

# Set timezone to Vietnam
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime && \
    echo "Asia/Ho_Chi_Minh" > /etc/timezone

# Copy configuration files
COPY nftables.conf /etc/nftables.conf
COPY init-firewall.sh /init-firewall.sh
COPY firewall-monitor.sh /firewall-monitor.sh
COPY query-logs.sh /usr/local/bin/query-logs

# Fix line endings (for Windows compatibility)
RUN dos2unix /init-firewall.sh /firewall-monitor.sh /usr/local/bin/query-logs /etc/nftables.conf 2>/dev/null || true

# Make scripts executable
RUN chmod +x /init-firewall.sh /firewall-monitor.sh /usr/local/bin/query-logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nft list tables > /dev/null 2>&1 || exit 1

# Start firewall
CMD ["/init-firewall.sh"]
