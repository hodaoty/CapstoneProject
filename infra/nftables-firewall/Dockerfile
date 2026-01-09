FROM alpine:latest

RUN apk add --no-cache \
    nftables \
    tcpdump \
    bash \
    tzdata

ENV TZ=Asia/Ho_Chi_Minh
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN mkdir -p /var/log/firewall

COPY nftables.conf /etc/nftables.conf
COPY init-firewall.sh /init-firewall.sh
COPY query-logs.sh /usr/local/bin/query-logs

RUN chmod +x /init-firewall.sh /usr/local/bin/query-logs

CMD ["/init-firewall.sh"]
