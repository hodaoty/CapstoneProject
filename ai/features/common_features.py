import pandas as pd
import re
import numpy as np

def build_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """
    Sinh đặc trưng chung cho tất cả loại tấn công (Injection, Rate Limiting, BOLA, BFLA).
    Input: DataFrame đã cleaned với schema chuẩn.
    Output: DataFrame với các cột feature sẵn sàng cho training & Cột Label.
    """
    print("Đang trích xuất đặc trưng (Feature Engineering)...")
    
    # Tạo bản sao để tránh cảnh báo SettingWithCopyWarning của Pandas
    df = df.copy()

    # --- 1. Path Features (Bắt Injection) ---
    df['path'] = df['path'].astype(str).fillna('')
    df['path_length'] = df['path'].apply(len)
    df['num_query_params'] = df['path'].apply(lambda x: x.count('&') + x.count('?'))
    
    special_chars = r"[\'\"<>\%\*\;\-\(\)]"
    df['num_special_chars'] = df['path'].apply(lambda x: len(re.findall(special_chars, x)))

    sql_keywords = ['select','union','or','drop','insert','update', '--', '/*']
    xss_keywords = ['script','alert','onerror','onload', 'javascript:']
    df['has_sql_keyword'] = df['path'].apply(lambda x: int(any(k in x.lower() for k in sql_keywords)))
    df['has_xss_keyword'] = df['path'].apply(lambda x: int(any(k in x.lower() for k in xss_keywords)))

    # --- 2. Response Features ---
    df['response_size'] = pd.to_numeric(df['response_size'], errors='coerce').fillna(0)
    df['response_time_ms'] = pd.to_numeric(df['response_time_ms'], errors='coerce').fillna(0)

    # --- 3. User Agent (Bắt Bot/Crawler) ---
    df['is_script'] = df['user_agent'].astype(str).apply(
        lambda x: int(any(bot in x.lower() for bot in ['python', 'curl', 'postman', 'java', 'wget']))
    )

    # --- 4. Auth/User Role (Bắt BFLA) ---
    df['has_auth_token'] = df['auth_token_hash'].apply(lambda x: 0 if pd.isna(x) or str(x).strip() == '' else 1)
    df['has_user_role'] = df['user_role'].apply(lambda x: 0 if pd.isna(x) or str(x).strip() in ["", "(empty)", "GUEST"] else 1)

    # --- 5. Status & Method (Chuẩn hóa cho LightGBM) ---
    # Ép kiểu 'category' thay vì get_dummies để không bị lệch cột khi chạy Real-time
    df['status'] = pd.to_numeric(df['status'], errors='coerce').fillna(200).astype(int).astype('category')
    df['method'] = df['method'].astype(str).fillna('GET').astype('category')

    # --- 6. Time-Series & Rate Limiting (Bắt DDoS, BOLA) ---
    # Sắp xếp thời gian và dùng Rolling Window để quét
    df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
    df = df.dropna(subset=['@timestamp']).sort_values(by='@timestamp')
    df.set_index('@timestamp', inplace=True)

    # Tần suất bắn request của IP trong 10 giây qua (Bắt DDoS / Brute Force cực nhạy)
    df['req_per_10s_ip'] = df.groupby('remote_ip')['request_id'].transform(lambda x: x.rolling('10s').count()).fillna(1)
    
    # Tần suất quét của User trong 1 phút (Bắt BOLA Scanner)
    # Lấp đầy user_id_hash rỗng bằng IP để vẫn nhóm được các user vãng lai
    df['tracking_id'] = df['user_id_hash'].replace('', np.nan).fillna(df['remote_ip'])
    df['req_per_1m_user'] = df.groupby('tracking_id')['request_id'].transform(lambda x: x.rolling('1min').count()).fillna(1)

    # Tỷ lệ dính lỗi (401, 403, 404, 429) của IP trong 1 phút (Dấu hiệu hacker mò mẫm)
    df['is_error'] = (df['status'].astype(int) >= 400).astype(int)
    df['error_per_1m_ip'] = df.groupby('remote_ip')['is_error'].transform(lambda x: x.rolling('1min').sum()).fillna(0)

    # Trả index về dạng số bình thường
    df.reset_index(inplace=True)

    # --- Final Feature Set ---
    features = [
        'method', 'status', # Biến Categorical
        'path_length', 'num_query_params', 'num_special_chars',
        'has_sql_keyword', 'has_xss_keyword',
        'response_size', 'response_time_ms',
        'is_script', 'has_auth_token', 'has_user_role', 
        'req_per_10s_ip', 'req_per_1m_user', 'error_per_1m_ip'
    ]
    
    # Trích xuất nhãn (Label) nếu tồn tại trong file (Dùng lúc Train)
    target = df['label'] if 'label' in df.columns else None

    return df[features], target