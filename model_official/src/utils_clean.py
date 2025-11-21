# utils_clean.py
import math
from collections import Counter
import urllib.parse
import html
import re


# ---------------------------------------------
# BASIC FEATURE FUNCTIONS
# ---------------------------------------------

def calc_entropy(s: str) -> float:
    """Tính entropy thô của chuỗi (dùng để đo độ ngẫu nhiên / encode)."""
    if not s:
        return 0.0
    s = str(s)
    counts = Counter(s)
    total = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def normalize_for_tfidf(text: str, max_decode_rounds: int = 3) -> str:
    """
    Chuẩn hóa text để đưa vào TF-IDF:
    - Multi URL-decode
    - HTML unescape
    - Lowercase
    - Gộp space
    """
    if text is None:
        return ""
    s = str(text)

    # Multi URL decode để lộ payload bị encode nhiều lần
    for _ in range(max_decode_rounds):
        try:
            new_s = urllib.parse.unquote_plus(s)
        except Exception:
            break
        if new_s == s:
            break
        s = new_s

    # HTML entities → char
    s = html.unescape(s)

    # Chuẩn hóa xuống lowercase
    s = s.lower()

    # Thay các ký tự xuống dòng, tab → space
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")

    # Gộp nhiều space
    s = re.sub(r"\s+", " ", s).strip()
    return s


def count_special_chars(s: str) -> int:
    """Đếm số ký tự 'đặc biệt' (không phải chữ/số/space)."""
    if not s:
        return 0
    return sum(1 for ch in s if not ch.isalnum() and not ch.isspace())


def longest_special_run(s: str) -> int:
    """Độ dài chuỗi liên tiếp ký tự đặc biệt dài nhất."""
    if not s:
        return 0
    max_run = 0
    cur = 0
    for ch in s:
        if not ch.isalnum() and not ch.isspace():
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 0
    return max_run


# ---------------------------------------------
# CMD / SHELL FEATURE FUNCTIONS
# ---------------------------------------------

_CMD_KEYWORDS = [
    "ls", "cat", "wget", "curl", "chmod", "chown",
    "rm ", "rm -rf", "mv ", "cp ", "echo ", "id", "whoami",
    "uname", "ping", "nc ", "netcat", "bash", "sh ", "/bin/sh",
    "/bin/bash", "nohup", "python", "perl", "php ", "nc -e",
]

def find_cmd_keyword_count(s: str) -> int:
    """Đếm số lần xuất hiện các từ khóa command injection."""
    if not s:
        return 0
    s_low = s.lower()
    return sum(s_low.count(k) for k in _CMD_KEYWORDS)


def count_cmd_special(s: str) -> int:
    """
    Đếm các ký tự đặc trưng cho shell:
    ; && || | ` $() >
    """
    if not s:
        return 0
    specials = [";", "&&", "||", "|", "`", "$(", ")", ">>", "<", "&"]
    s_low = s.lower()
    return sum(s_low.count(p) for p in specials)


def count_shell_patterns(s: str) -> int:
    """
    Các pattern shell nâng cao: sh -c, /bin/sh, /bin/bash, $(whoami)...
    """
    if not s:
        return 0
    s_low = s.lower()
    pats = [
        "sh -c", "/bin/sh", "/bin/bash",
        "$(whoami", "$(id", "$(uname", "$(curl", "$(wget"
    ]
    return sum(s_low.count(p) for p in pats)


def count_path_traversal(s: str) -> int:
    """Đếm các dấu hiệu path traversal: ../, ..\\, %2e%2e%2f,..."""
    if not s:
        return 0
    s_low = s.lower()
    pats = [
        "../", "..\\", "%2e%2e%2f", "%2e%2e\\",
        "..%2f", "%252e%252e%252f",
    ]
    return sum(s_low.count(p) for p in pats)


def count_sensitive_files(s: str) -> int:
    """Đếm số pattern file nhạy cảm."""
    if not s:
        return 0
    s_low = s.lower()
    targets = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "id_rsa", "id_dsa", "authorized_keys",
        "web.config", "config.php", "settings.py",
        ".htaccess", "wp-config.php",
    ]
    return sum(s_low.count(p) for p in targets)


# ---------------------------------------------
# SQL FEATURE FUNCTIONS
# ---------------------------------------------

_SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete",
    "drop", "truncate", "alter", "create",
    "from", "where", "group by", "order by",
    "having", "limit", "offset",
    "into", "values", "join", "inner join", "outer join",
]

def count_sql_keywords(s: str) -> int:
    if not s:
        return 0
    s_low = s.lower()
    return sum(s_low.count(k) for k in _SQL_KEYWORDS)


def count_sql_comments(s: str) -> int:
    if not s:
        return 0
    s_low = s.lower()
    pats = ["--", "/*", "*/", "# "]
    return sum(s_low.count(p) for p in pats)


def count_sql_boolean_ops(s: str) -> int:
    if not s:
        return 0
    s_low = s.lower()
    pats = [
        " and ", " or ", " xor ",
        " and 1=1", " or 1=1", " and true", " or true",
        " and false", " or false"
    ]
    return sum(s_low.count(p) for p in pats)


_SQL_FUNC_RE = re.compile(
    r"\b(?:ascii|char|count|sum|avg|min|max|substr|substring|md5|sha1|concat|"
    r"database|user|schema|version|sleep|benchmark|if)\s*\(",
    re.IGNORECASE
)

def count_sql_funcs(s: str) -> int:
    if not s:
        return 0
    return len(_SQL_FUNC_RE.findall(s))


def count_sql_logic_patterns(s: str) -> int:
    """
    Đếm các pattern logic SQL thường gặp trong injection:
    1=1, 1=2, true, false, is null, is not null...
    """
    if not s:
        return 0
    s_low = s.lower()
    pats = [
        " 1=1", " 1 = 1",
        " 1=2", " 1 = 2",
        " is null", " is not null",
        " like '%", " like \"%",
    ]
    return sum(s_low.count(p) for p in pats)


# ---------------------------------------------
# XSS / JS FEATURE FUNCTIONS
# ---------------------------------------------

_XSS_TAG_RE = re.compile(
    r"<\s*(script|img|svg|math|iframe|object|embed|video|audio|details|marquee|body|input|textarea|button)\b",
    re.IGNORECASE
)

def count_xss_tags(s: str) -> int:
    if not s:
        return 0
    return len(_XSS_TAG_RE.findall(s))


_XSS_EVENT_RE = re.compile(
    r"\bon\w+\s*=",
    re.IGNORECASE
)

def count_xss_events(s: str) -> int:
    if not s:
        return 0
    return len(_XSS_EVENT_RE.findall(s))


def count_js_protocols(s: str) -> int:
    """Đếm javascript:, vbscript:, data:text/html..."""
    if not s:
        return 0
    s_low = s.lower()
    pats = [
        "javascript:",
        "vbscript:",
        "data:text/html",
        "data:text/javascript",
    ]
    return sum(s_low.count(p) for p in pats)


def count_xss_js_uri(s: str) -> int:
    """
    Tập trung cho XSS dạng protocol: href=javascript:..., src=javascript:...
    """
    if not s:
        return 0
    s_low = s.lower()
    pats = [
        "href=javascript:",
        "src=javascript:",
        "xlink:href=javascript:",
    ]
    return sum(s_low.count(p) for p in pats)


_RARE_TAG_RE = re.compile(
    r"<\s*(svg|math|details|marquee|embed|object|video|audio)\b",
    re.IGNORECASE
)

def count_rare_html_tags(s: str) -> int:
    """
    Đếm các thẻ HTML ít dùng nhưng hay bị lợi dụng trong XSS.
    """
    if not s:
        return 0
    return len(_RARE_TAG_RE.findall(s))


_UNICODE_ESC_RE = re.compile(r"\\u[0-9a-fA-F]{4}")

def count_unicode_escapes(s: str) -> int:
    """Đếm số chuỗi escape unicode kiểu \u0041, hay dùng để bypass filter."""
    if not s:
        return 0
    return len(_UNICODE_ESC_RE.findall(s))


_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

def count_base64_chunks(s: str) -> int:
    """
    Đếm các chuỗi giống base64 dài (VD: dùng để giấu payload).
    """
    if not s:
        return 0
    return len(_BASE64_RE.findall(s))
