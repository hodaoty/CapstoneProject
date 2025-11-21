1. Chuẩn bị môi trường
Cài dependencies:
pip install -r requirements.txt


Yêu cầu các thư viện chính:

scikit-learn

LightGBM

pandas

scipy

rich

Cấu trúc thư mục:

project/
│── src/
│    ├── preprocess_clean.py
│    ├── train_clean.py
│    ├── infer_clean.py
│    ├── utils_clean.py
│── data/
│    ├── bai.csv
│    ├── SQL.csv
│    ├── XSS.csv
│    ├── commmand.csv
│    ├── *optional: SQL_new.csv / XSS_new.csv / CMD_new.csv*
│── dataset/
│── models/

🏗 2. Tiền xử lý dữ liệu
Script: preprocess_clean.py
(đã nâng cấp — chuẩn hóa text, decode nhiều lớp, sinh meta-feature nâng cao)

Chạy:

python src/preprocess_clean.py


Script sẽ:

Load dataset trong thư mục data/

Map lại các nhãn (XSS=2, CMD=3…)

Chuẩn hóa URL + BODY (multi-decode, HTML unescape)

Extract hơn 20 meta-features

Shuffle dữ liệu

Lưu file chuẩn hóa:

dataset/train_df_clean.parquet


Kết quả kỳ vọng:

✔ Dataset saved → dataset/train_df_clean.parquet
📊 Shape: (XXXX, 26)
📌 Label counts:
0: ...
1: ...
2: ...
3: ...


📌 File tham chiếu: preprocess_clean.py 

preprocess_clean

🤖 3. Train mô hình LightGBM

Script: train_clean.py

Chạy:

python src/train_clean.py


Script sẽ:

Load dataset parquet

TF-IDF vectorize (char-level 2–6gram)

Merge meta-features → sparse matrix

Tách: train (64%) / validation (16%) / test (20%)

Huấn luyện LightGBM với early-stopping

Ánh xạ nhãn → {0: Benign, 1: SQL, 2: XSS, 3: CMD}

Lưu model:

models/model_clean.pkl


Kết quả hiển thị:

Classification report

Confusion matrix

Loss giảm theo epoch

📌 File tham chiếu: train_clean.py 

train_clean

🔍 4. Kiểm thử payload (CLI Tester)

Script: infer_clean.py

Chạy:

python src/infer_clean.py


Tính năng:

Load model + TF-IDF

Giao diện terminal đẹp bằng Rich

Test từ file CSV payload:

payloads/benign.csv

payloads/sqli.csv

payloads/xss.csv

payloads/command.csv

Sắp xếp theo độ nguy hiểm

Hiển thị: label, confidence, probability, payload

Ví dụ:

========== PAYLOAD TESTER ==========
1. Test Benign
2. Test SQL Injection
3. Test XSS
4. Test Command Injection
5. Thoát
====================================


📌 File tham chiếu: infer_clean.py 

infer_clean

🛠 5. Mô hình hoạt động thế nào?

Model sử dụng 2 nguồn tín hiệu:

✔ TF-IDF character-level

Bắt các pattern:

' or 1=1 --

<script>

; ls -la

../../etc/passwd

Bypass encode (%27%27%3b)

✔ Meta-features (rất quan trọng)

Ví dụ:

entropy, base64_chunk_count → detect encode/bypass

xss_event_count, rare_tag_count → detect XSS khó

cmd_special_count, shell_pattern_count → detect command injection

sql_logic_count, sql_boolean_ops → detect SQL logic-based

📌 File chức năng: utils_clean.py 

utils_clean

🧪 6. Tích hợp vào Microservice

Model được thiết kế để nhúng vào kiến trúc:

Client → API Gateway → Security Model (SQL/XSS/CMD) → Microservices


Bạn chỉ cần:

Load model từ models/model_clean.pkl

Gọi hàm predict_url(url, body)

Nếu output ≠ Benign → block / log / alert

🎯 7. Lệnh tóm tắt
✔ Tiền xử lý
python src/preprocess_clean.py

✔ Train model
python src/train_clean.py

✔ Test payload
python src/infer_clean.py