FROM alpine:latest

RUN apk add --no-cache \
    nftables \
    tcpdump \
    bash \
    coreutils \
    dos2unix

RUN mkdir -p /var/log/firewall

COPY nftables.conf /etc/nftables.conf
COPY init-firewall.sh /init-firewall.sh
COPY query-logs.sh /usr/local/bin/query-logs

# Fix line endings cho Windows
RUN dos2unix /init-firewall.sh /usr/local/bin/query-logs /etc/nftables.conf

RUN chmod +x /init-firewall.sh /usr/local/bin/query-logs

CMD ["/init-firewall.sh"]
