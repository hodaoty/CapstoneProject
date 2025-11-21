#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore")

# ===== TẮT LOG LIGHTGBM ĐÚNG CÁCH =====
import lightgbm as lgb

class SilentLogger:
    def info(self, msg):
        pass
    def warning(self, msg):
        pass

lgb.register_logger(SilentLogger())

import joblib
import csv
from scipy.sparse import csr_matrix, hstack
from rich.console import Console
from rich.table import Table
from rich import box

from utils_clean import (
    normalize_for_tfidf,
    calc_entropy,
    count_special_chars,
    longest_special_run,
    find_cmd_keyword_count,
    count_sql_comments,
    count_cmd_special,
    count_sql_keywords,
    count_sql_boolean_ops,
    count_sql_funcs,
    count_xss_tags,
    count_xss_events,
    count_js_protocols,
    count_path_traversal,
    count_sensitive_files,
    count_shell_patterns,
    count_xss_js_uri,
    count_rare_html_tags,
    count_unicode_escapes,
    count_base64_chunks,
    count_sql_logic_patterns,
)

console = Console()

# =============================
# LABELS
# =============================
LABEL_MAP = {
    0: "Benign",
    1: "SQL Injection",
    2: "XSS",
    3: "Command Injection"
}

DANGER_ORDER = {
    "Command Injection": 1,
    "SQL Injection": 2,
    "XSS": 3,
    "Benign": 4
}

# PHẢI KHỚP 100% VỚI train/preprocess
META_COLS = [
    "url_length",
    "entropy",
    "num_special",
    "special_ratio",
    "longest_special_seq",
    "cmd_keyword_count",
    "sql_comment_count",
    "cmd_special_count",
    "sql_keyword_count",
    "sql_boolean_ops",
    "sql_func_count",
    "xss_tag_count",
    "xss_event_count",
    "js_proto_count",
    "path_traversal_count",
    "sensitive_file_count",
    "shell_pattern_count",
    "xss_js_uri_count",
    "xss_rare_tag_count",
    "unicode_escape_count",
    "base64_chunk_count",
    "sql_logic_count",
]

MODEL_BUNDLE = None


# =============================
# LOAD MODEL
# =============================
def load_model():
    global MODEL_BUNDLE
    if MODEL_BUNDLE is None:
        MODEL_BUNDLE = joblib.load("models/model_clean.pkl")
        console.print("[bold green]📘 Loaded model from models/model_clean.pkl[/]")
    return MODEL_BUNDLE


# =============================
# PREPROCESS
# =============================
def preprocess(url, body):
    text = normalize_for_tfidf(str(url) + " " + str(body))

    meta = {
        "url_length": len(text),
        "entropy": calc_entropy(text),
        "num_special": count_special_chars(text),
        "special_ratio": count_special_chars(text) / (len(text) + 1),
        "longest_special_seq": longest_special_run(text),

        # CMD
        "cmd_keyword_count": find_cmd_keyword_count(text),
        "cmd_special_count": count_cmd_special(text),
        "path_traversal_count": count_path_traversal(text),
        "sensitive_file_count": count_sensitive_files(text),
        "shell_pattern_count": count_shell_patterns(text),

        # SQL
        "sql_comment_count": count_sql_comments(text),
        "sql_keyword_count": count_sql_keywords(text),
        "sql_boolean_ops": count_sql_boolean_ops(text),
        "sql_func_count": count_sql_funcs(text),
        "sql_logic_count": count_sql_logic_patterns(text),

        # XSS
        "xss_tag_count": count_xss_tags(text),
        "xss_event_count": count_xss_events(text),
        "js_proto_count": count_js_protocols(text),
        "xss_js_uri_count": count_xss_js_uri(text),
        "xss_rare_tag_count": count_rare_html_tags(text),

        # ENCODE / OBFUSCATION
        "unicode_escape_count": count_unicode_escapes(text),
        "base64_chunk_count": count_base64_chunks(text),
    }

    return text, meta


# =============================
# PREDICT
# =============================
def predict_url(url, body=""):
    bundle = load_model()
    model = bundle["model"]
    tfidf = bundle["tfidf"]

    text, meta = preprocess(url, body)

    X_text = tfidf.transform([text])
    X_meta = csr_matrix([[meta[c] for c in META_COLS]])
    X = hstack([X_text, X_meta])

    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0]

    return LABEL_MAP.get(pred, "Unknown"), prob


# =============================
# CONFIDENCE LEVEL
# =============================
def confidence_level(p):
    if p >= 90:
        return "[bold red]HIGH[/bold red]"
    if p >= 70:
        return "[yellow]MEDIUM[/yellow]"
    return "[cyan]LOW[/cyan]"


def row_color(label):
    return {
        "Command Injection": "bold red",
        "SQL Injection": "red",
        "XSS": "yellow",
        "Benign": "green",
    }.get(label, "white")


# =============================
# CSV PAYLOAD LOADER
# =============================
def load_payload_file(path):
    payloads = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            for row in reader:
                if len(row) >= 2:
                    payloads.append((row[0], row[1]))
    except Exception:
        console.print(f"[bold red]❌ Không thể đọc file: {path}[/]")
    return payloads


# =============================
# MENU
# =============================
def menu():
    console.print("\n[bold cyan]========== PAYLOAD TESTER ==========[/]")
    console.print("1. Test Benign")
    console.print("2. Test SQL Injection")
    console.print("3. Test XSS")
    console.print("4. Test Command Injection")
    console.print("5. Thoát")
    console.print("====================================\n")

    while True:
        c = input("Chọn (1-5): ").strip()
        if c in ["1", "2", "3", "4", "5"]:
            return c
        console.print("[red]❌ Lựa chọn không hợp lệ![/]")


# =============================
# MAIN
# =============================
if __name__ == "__main__":
    load_model()

    FILES = {
        "1": "payloads/benign.csv",
        "2": "payloads/sqli.csv",
        "3": "payloads/xss.csv",
        "4": "payloads/command.csv",
    }

    while True:
        choice = menu()

        if choice == "5":
            console.print("[bold yellow]👋 Thoát.[/]")
            break

        file_path = FILES[choice]
        payloads = load_payload_file(file_path)

        if not payloads:
            console.print("[bold red]❌ Không có payload để test.[/]")
            continue

        console.print(f"[cyan]▶ Đang test file: [bold]{file_path}[/][/]\n")

        result_table = Table(
            title="📊 KẾT QUẢ TEST PAYLOAD – Nâng cấp",
            header_style="bold magenta",
            box=box.HEAVY_EDGE,
        )

        result_table.add_column("#", justify="right", style="yellow")
        result_table.add_column("LABEL", justify="center")
        result_table.add_column("Confidence", justify="center")
        result_table.add_column("URL", style="white")
        result_table.add_column("BODY", style="white")
        result_table.add_column("Prob (%)", justify="right")

        results = []
        for url, body in payloads:
            label, prob = predict_url(url, body)
            max_prob = max(prob) * 100
            results.append((url, body, label, max_prob))

        # sort theo độ nguy hiểm + xác suất
        results.sort(key=lambda x: (DANGER_ORDER[x[2]], -x[3]))

        for idx, (url, body, label, max_prob) in enumerate(results, start=1):
            result_table.add_row(
                str(idx),
                f"[{row_color(label)}]{label}[/{row_color(label)}]",
                confidence_level(max_prob),
                url,
                body,
                f"{max_prob:.2f}",
            )

        console.print(result_table)
        input("\n[cyan]Nhấn ENTER để quay lại menu...[/]")
