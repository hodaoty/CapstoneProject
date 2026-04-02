import pandas as pd
import joblib
import time
import os
import sys
import subprocess
import requests
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch
from colorama import init, Fore, Style

# Khởi tạo màu sắc cho Terminal
init(autoreset=True)

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN MÔI TRƯỜNG
# ==========================================
# Script nằm trong thư mục /run. Ta lùi lại 1 cấp (..) để ra thư mục gốc
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
APP_ROOT = os.path.abspath(os.path.join(PROJECT_ROOT, '..'))
sys.path.append(APP_ROOT)

# Import module từ thư mục /src (Sau khi đã thêm PROJECT_ROOT vào path)
from ai.features.common_features import build_features

# ==========================================
# CẤU HÌNH HỆ THỐNG
# ==========================================
# ES_URL = "http://127.0.0.1:9200"
# INDEX_NAME = "mlops-api-logs-*"
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200")
INDEX_NAME = os.getenv("INDEX_NAME", "mlops-api-logs-*")
FIREWALL_CONTAINER = os.getenv("FIREWALL_CONTAINER", "nftables-firewall")

# ADDED: notify / review config
FIREWALL_ADMIN_API_URL = os.getenv("FIREWALL_ADMIN_API_URL", "http://firewall-admin:9000")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
FIREWALL_ADMIN_URL = os.getenv("FIREWALL_ADMIN_URL", "http://localhost:9000")

# Tự động trỏ đường dẫn tới file pkl nằm trong thư mục /models của dự án
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "lightgbm_threatAPI_detector.pkl")

# Tần suất quét (Ví dụ: 5 giây quét 1 lần)
POLLING_INTERVAL_SEC = 5
# Cửa sổ thời gian lùi lại để tính toán tính năng Rolling (30 giây cho an toàn)
CONTEXT_WINDOW_MINUTES = 0.5

# ==========================================
# VÙNG XỬ LÝ MỨC ĐỘ ĐE DỌA & HÀNH ĐỘNG
# - Phân loại LOW / MEDIUM / HIGH từ score
# - MEDIUM: gửi cảnh báo quản trị viên
# - HIGH: block IP bằng nftables + gửi cảnh báo
# ==========================================
THRESHOLD_MEDIUM = 0.5
THRESHOLD_HIGH = 0.8


def get_threat_level(score: float) -> str:
    """
    Phân loại mức độ nguy hiểm từ xác suất model trả về.
    """
    if score >= THRESHOLD_HIGH:
        return "HIGH"
    elif score >= THRESHOLD_MEDIUM:
        return "MEDIUM"
    return "LOW"


# def send_admin_alert(ip: str, score: float, level: str, path: str = ""):
#     now = datetime.now().strftime("%H:%M:%S")

#     # 🔹 vẫn giữ log file (optional)
#     alert_msg = f"[{now}] [{level}] IP: {ip} | Score: {score:.4f} | Path: {path}\n"
#     with open("security_alerts.log", "a", encoding="utf-8") as f:
#         f.write(alert_msg)

#     print(Fore.CYAN + f"   [ACTION-NOTIFY] Đang gửi Telegram alert...")

#     # 🔥 TELEGRAM CONFIG
#     BOT_TOKEN = "8567266730:AAEBgoJKHdWfV7T1rMhac9AMPpZXRVfYS6k"
#     CHAT_ID = "-5180306481"

#     message = (
#         f"🚨 *SECURITY ALERT*\n\n"
#         f"🧠 Level: *{level}*\n"
#         f"🌐 IP: `{ip}`\n"
#         f"📊 Score: *{score:.4f}*\n"
#         f"📍 Path: `{path}`\n"
#         f"⏰ Time: {now}"
#     )

#     try:
#         r = requests.post(
#             f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
#             json={
#                 "chat_id": CHAT_ID,
#                 "text": message,
#                 "parse_mode": "Markdown"
#             },
#             timeout=5
#         )

#         print(Fore.CYAN + f"   [TELEGRAM] status={r.status_code}")

#     except Exception as e:
#         print(Fore.YELLOW + f"[TELEGRAM ERROR] {e}")

# ADDED: gửi Telegram cho MEDIUM, chỉ có nút mở web admin
def send_medium_review_alert(ip: str, score: float, path: str = "", method: str = "GET"):
    now = datetime.now().strftime("%H:%M:%S")

    alert_msg = f"[{now}] [MEDIUM] IP: {ip} | Score: {score:.4f} | Path: {path}\n"
    with open("security_alerts.log", "a", encoding="utf-8") as f:
        f.write(alert_msg)

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(Fore.YELLOW + "[TELEGRAM WARN] Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
        return

    message = (
        f"⚠️ <b>MEDIUM SECURITY ALERT</b>\n\n"
        f"🧠 Level: <b>MEDIUM</b>\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📊 Score: <b>{score:.4f}</b>\n"
        f"📍 Endpoint: <code>{method} {path}</code>\n"
        f"⏰ Time: {now}\n\n"
        f"Admin vui lòng vào Firewall Admin để quyết định block hay không."
    )

    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "HTML",
                "reply_markup": {
                    "inline_keyboard": [[
                        {
                            "text": "👁 Open Firewall Admin",
                            "url": f"{FIREWALL_ADMIN_URL}?ip={ip}"
                        }
                    ]]
                }
            },
            timeout=5
        )
        print(Fore.CYAN + f"   [TELEGRAM-MEDIUM] status={r.status_code}")
        # print(Fore.CYAN + f"   [TELEGRAM-MEDIUM] status={r.status_code} body={r.text}")
    except Exception as e:
        print(Fore.YELLOW + f"[TELEGRAM MEDIUM ERROR] {e}")


# ADDED: HIGH đã block xong thì gọi firewall-admin để gửi mail + telegram
def notify_high_blocked(ip: str, score: float, path: str = "", method: str = "GET"):
    payload = {
        "ip": ip,
        "reason": "AI detected HIGH threat and auto-blocked into ddos_blacklist",
        "attack_type": "HIGH",
        "score": round(score * 100, 2),
        "endpoint": path,
        "method": method,
        "status_code": "",
        "request_count": 1,
        "trend": "Auto-block by realtime defender"
    }

    try:
        r = requests.post(
            f"{FIREWALL_ADMIN_API_URL}/api/v1/notify-high-blocked",
            json=payload,
            timeout=8
        )
        print(Fore.CYAN + f"   [NOTIFY-HIGH] status={r.status_code}")
    except Exception as e:
        print(Fore.YELLOW + f"[NOTIFY HIGH ERROR] {e}")


def execute_block_ip(ip: str) -> bool:
    whitelist = ["127.0.0.1", "0.0.0.0"]
    if ip in whitelist:
        return False

    try:
        cmd = [
            "docker", "exec", FIREWALL_CONTAINER,
            "nft", "add", "element",
            "inet", "filter", "ddos_blacklist",
            "{", f"{ip} timeout 1h", "}"
        ]

        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode == 0:
            print(Fore.RED + Style.BRIGHT + f"[BLOCKED] IP {ip} added to ddos_blacklist in {FIREWALL_CONTAINER}")
            return True

        print(Fore.YELLOW + f"[ERROR] Cannot block IP {ip}: {result.stderr.strip()}")
        return False

    except Exception as e:
        print(Fore.YELLOW + f"[ERROR] Cannot block IP {ip}: {e}")
        return False

# def handle_threat(ip: str, score: float, path: str):
#     """
#     Xử lý hành động cuối cùng theo level:
#     - LOW: không làm gì
#     - MEDIUM: gửi cảnh báo
#     - HIGH: block + cảnh báo
#     """
#     level = get_threat_level(score)

#     if level == "HIGH":
#         print(Fore.RED + Style.BRIGHT + f"[HIGH - {score:.4f}] TẤN CÔNG NGUY HIỂM! IP: {ip}")
#         execute_block_ip(ip)
#         send_admin_alert(ip, score, "HIGH", path)

#     elif level == "MEDIUM":
#         print(Fore.YELLOW + f"[MEDIUM - {score:.4f}] Hoạt động nghi vấn từ IP: {ip}")
#         send_admin_alert(ip, score, "MEDIUM", path)

#     else:
#         print(Fore.GREEN + f"[LOW - {score:.4f}] Bình thường | IP: {ip}")

#     return level

def handle_threat(ip: str, score: float, path: str, method: str = "GET"):
    """
    Xử lý hành động cuối cùng theo level:
    - LOW: không làm gì
    - MEDIUM: chỉ gửi Telegram + link qua web admin
    - HIGH: block IP trước, rồi firewall-admin gửi mail + Telegram
    """
    level = get_threat_level(score)

    if level == "HIGH":
        print(Fore.RED + Style.BRIGHT + f"[HIGH - {score:.4f}] TẤN CÔNG NGUY HIỂM! IP: {ip}")

        # ADDED: chỉ notify nếu block thành công
        blocked = execute_block_ip(ip)

        if blocked:
            notify_high_blocked(ip, score, path, method)
        else:
            print(Fore.YELLOW + f"[WARN] Block thất bại, không gửi notify HIGH cho IP {ip}")

    elif level == "MEDIUM":
        print(Fore.YELLOW + f"[MEDIUM - {score:.4f}] Hoạt động nghi vấn từ IP: {ip}")

        # COMMENTED OLD: trước đây MEDIUM dùng chung send_admin_alert
        # send_admin_alert(ip, score, "MEDIUM", path)

        # ADDED: MEDIUM chỉ gửi Telegram + link qua web admin
        try:
            payload = {
                "ip": ip,
                "score": round(score * 100, 2),
                "endpoint": path,
                "method": method,
                "attack_type": "MEDIUM",
                "status_code": "",
                "request_count": 1,
                "trend": ""
            }
            r = requests.post(
                f"{FIREWALL_ADMIN_API_URL}/api/v1/notify",
                json=payload,
                timeout=8
            )
            print(Fore.CYAN + f"   [NOTIFY-MEDIUM] status={r.status_code}")
        except Exception as e:
            print(Fore.YELLOW + f"[NOTIFY MEDIUM ERROR] {e}")
            send_medium_review_alert(ip, score, path, method)

    else:
        print(Fore.GREEN + f"[LOW - {score:.4f}] Bình thường | IP: {ip}")

    return level




# ==========================================
# ==========================================
# ==========================================
# def connect_elasticsearch():
#     try:
#         es = Elasticsearch(
#             ES_URL,
#             request_timeout=10,
#             headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8",
#                      "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8"}
#         )
#         if es.info():
#             print(Fore.GREEN + "Đã kết nối thành công tới Elasticsearch!")
#             return es
#     except Exception as e:
#         print(Fore.RED + f"Lỗi kết nối ES: {e}")
#         sys.exit(1)
def connect_elasticsearch():
    while True:
        try:
            es = Elasticsearch(
                ES_URL,
                request_timeout=10,
                headers={
                    "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
                    "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8"
                }
            )
            es.info()
            print(Fore.GREEN + "Đã kết nối thành công tới Elasticsearch!")
            return es
        except Exception as e:
            print(Fore.YELLOW + f"Elasticsearch chưa sẵn sàng, thử lại sau 5 giây... | {e}")
            time.sleep(5)

def load_ai_model():
    if not os.path.exists(MODEL_PATH):
        print(Fore.RED + f"Không tìm thấy Model tại {MODEL_PATH}")
        sys.exit(1)
    model = joblib.load(MODEL_PATH)
    print(Fore.GREEN + f"Đã tải thành công 'Bộ não' LightGBM!")
    return model

def run_realtime_defender():
    print(Fore.CYAN + Style.BRIGHT + "="*60)
    print(Fore.CYAN + Style.BRIGHT + "HỆ THỐNG API THREAT DEFENDER ĐANG HOẠT ĐỘNG...")
    print(Fore.CYAN + Style.BRIGHT + "="*60)

    es = connect_elasticsearch()
    model = load_ai_model()
    
    # Tập hợp lưu trữ các request_id đã được quét để không cảnh báo trùng lặp
    processed_request_ids = set()

    while True:
        try:
            # 1. Xác định khung thời gian truy vấn (Từ [Bây giờ - 1.5 phút] đến [Bây giờ])
            now_utc = datetime.now(timezone.utc)
            start_time = now_utc - timedelta(minutes=CONTEXT_WINDOW_MINUTES)
            
            start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')

            # Câu truy vấn lấy log trong khung thời gian
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": start_time_str,
                            "lte": end_time_str
                        }
                    }
                },
                "sort": [{"@timestamp": {"order": "asc"}}],
                "size": 5000 # Giới hạn lấy 5000 log gần nhất (để tránh tràn RAM)
            }

            response = es.search(index=INDEX_NAME, body=query)
            hits = response['hits']['hits']

            if len(hits) == 0:
                print(Fore.YELLOW + f"[{now_utc.strftime('%H:%M:%S')}] Không có traffic mới...")
                time.sleep(POLLING_INTERVAL_SEC)
                continue

            # 2. Chuyển đổi dữ liệu ES thành DataFrame
            raw_logs = [hit['_source'] for hit in hits]
            df = pd.DataFrame(raw_logs)

            # Xóa log trùng lặp (do Logstash đẩy trùng)
            df = df.drop_duplicates(subset=['request_id'], keep='last')

            # Lọc ra NHỮNG DÒNG LOG MỚI TINH (Chưa từng dự đoán)
            new_logs_mask = ~df['request_id'].isin(processed_request_ids)
            if not new_logs_mask.any():
                time.sleep(POLLING_INTERVAL_SEC)
                continue

            # 3. Trích xuất Đặc trưng (Đưa cả context 1.5 phút vào để tính toán)
            try:
                # Gọi hàm build_features mà không cần cột label
                X, _ = build_features(df)
            except Exception as e:
                print(Fore.RED + f"Lỗi Feature Engineering: {e}")
                time.sleep(POLLING_INTERVAL_SEC)
                continue

            # Chỉ lấy các vector đặc trưng của những dòng log MỚI để AI phán xét
            X_new = X[new_logs_mask]
            df_new = df[new_logs_mask]

            # 4. AI trả về xác suất thuộc class attack (giá trị từ 0 đến 1)
            probabilities = model.predict_proba(X_new)[:, 1]

            # 5. Phân tích kết quả theo score và gọi handler
            threat_count = 0

            for i in range(len(probabilities)):
                score = float(probabilities[i])
                req_id = df_new.iloc[i]['request_id']
                ip = df_new.iloc[i].get('remote_ip', 'Unknown IP')
                path = df_new.iloc[i].get('path', '/')
                method = df_new.iloc[i].get('method', 'GET')

                # Thêm request_id vào danh sách đã xử lý để tránh xử lý trùng
                processed_request_ids.add(req_id)

                # Gọi bộ xử lý level:
                # - LOW    -> log bình thường
                # - MEDIUM -> cảnh báo admin
                # - HIGH   -> block IP + cảnh báo admin
                # level = handle_threat(ip, score, path)
                level = handle_threat(ip, score, path, method)

                # Chỉ đếm các request có mức đe dọa đáng chú ý
                if level in ["MEDIUM", "HIGH"]:
                    threat_count += 1

                # In thêm thông tin method/path để dễ debug
                print(Fore.WHITE + f"   -> Method: {method} | Path: {path} | Score: {score:.4f} | Level: {level}")

            # Xóa bớt cache ID để tránh tràn RAM
            # Giữ lại khoảng 5000 request_id gần nhất
            if len(processed_request_ids) > 10000:
                processed_request_ids = set(list(processed_request_ids)[-5000:])

            # Nếu không có request nào ở mức MEDIUM/HIGH thì xem như an toàn
            if threat_count == 0:
                print(Fore.GREEN +
                      f"[{now_utc.strftime('%H:%M:%S')}] Đã quét {len(df_new)} requests mới. Hệ thống an toàn.")

        except Exception as e:
            print(Fore.RED + f"Lỗi hệ thống trong lúc quét: {e}")
        
        # Ngủ 5 giây rồi quét tiếp
        time.sleep(POLLING_INTERVAL_SEC)

if __name__ == "__main__":
    run_realtime_defender()