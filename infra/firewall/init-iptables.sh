#!/bin/sh
# Su dung lenh : "docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' api-gateway"
# De xem IP api-gateway
# Xóa tất cả rule cũ
iptables -F
iptables -t nat -F
iptables -X

# Bật NAT để forward traffic từ firewall → api-gateway
# Giả sử api-gateway chạy trên network với IP 172.20.0.2 (Docker sẽ gán IP nội bộ)
# Bạn có thể thay bằng tên container: api-gateway:8080 nếu dùng DNS nội bộ
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 172.18.0.13:8080
iptables -t nat -A POSTROUTING -j MASQUERADE

# Cho phép traffic đã được NAT đi qua
iptables -A FORWARD -p tcp -d 172.18.0.13 --dport 8080 -j ACCEPT

# Rule chống DDoS cơ bản
# Giới hạn số kết nối mới từ một IP
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP

# Giới hạn tốc độ SYN
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Giới hạn ICMP (ping flood)
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

echo "iptables rules initialized"
