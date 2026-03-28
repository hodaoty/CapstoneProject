#!/usr/bin/env python3
"""
rotate_logs.py — nftables traffic log rotation
Source : /var/log/firewall/nftables.log  (kernel syslog via syslogd + klogd)
Output : /var/log/firewall/YYYY-MM-DD.log

Only lines containing the nftables log prefix "nftables: " are treated as
traffic entries.  All other lines (VirtualBox, timesync, X11 kernel noise)
are completely ignored.

Rules:
  - Past dates  : write YYYY-MM-DD.log if file does not exist / is empty,
                  then strip those lines from the source file.
  - Today       : always overwrite YYYY-MM-DD.log; never truncate source.
  - MASTER dir  : never touched.
"""

import re
from datetime import date
from pathlib import Path
from collections import defaultdict

# ─── Simplified line format ────────────────────────────────────────────────────

_KV_RE    = re.compile(r"(\w+)=(\S*)")
_FLAGS_RE = re.compile(r"\b(SYN|ACK|FIN|RST|PSH)\b")

_SYSLOG_TS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})"
)
_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _simplify_line(raw_line: str) -> str | None:
    """Convert one raw nftables kernel log line to simplified format.

    Output: "YYYY-MM-DD HH:MM:SS | SRC=x DST=x | PROTO=P [SPT=N] [DPT=N] | FLAGS"
    Returns None if required fields are missing.
    """
    raw = raw_line.strip()

    # ── Timestamp ──────────────────────────────────────────────────────────────
    m = _SYSLOG_TS_RE.match(raw)
    if not m:
        return None
    month = _MONTHS.get(m.group(1))
    if not month:
        return None
    day  = m.group(2).zfill(2)
    time = m.group(3)
    ts   = f"{date.today().year}-{month}-{day} {time}"

    # ── Key=value fields ───────────────────────────────────────────────────────
    kv: dict[str, str] = {k: v for k, v in _KV_RE.findall(raw)}

    src   = kv.get("SRC")
    dst   = kv.get("DST")
    proto = kv.get("PROTO")
    if not (src and dst and proto):
        return None

    spt = kv.get("SPT")
    dpt = kv.get("DPT")

    # ── TCP flags (standalone words only) ─────────────────────────────────────
    flags = " ".join(_FLAGS_RE.findall(raw))

    # ── Assemble ───────────────────────────────────────────────────────────────
    net_part = f"PROTO={proto}"
    if spt:
        net_part += f" SPT={spt}"
    if dpt:
        net_part += f" DPT={dpt}"

    return f"{ts} | SRC={src} DST={dst} | {net_part} | {flags}"

SOURCE     = Path("/var/log/firewall/nftables.log")
OUTPUT_DIR = Path("/var/log/firewall")
TODAY      = date.today().isoformat()

# Only process lines that contain the nftables log prefix
NFTABLES_MARKER = "nftables: "

# Match syslog-style prefix: "Mar 20 14:23:45" or ISO prefix "2026-03-20"
_SYSLOG_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}
_ISO_RE    = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}")


def _parse_date(line: str) -> str:
    """Return YYYY-MM-DD for a log line, defaulting to today if unparseable."""
    line = line.strip()
    m = _ISO_RE.match(line)
    if m:
        return m.group(1)
    m = _SYSLOG_RE.match(line)
    if m:
        month = _SYSLOG_MONTHS.get(m.group(1), "01")
        day   = m.group(2).zfill(2)
        return f"{date.today().year}-{month}-{day}"
    return TODAY


def main() -> None:
    if not SOURCE.exists():
        print(f"Source not found: {SOURCE}")
        return

    raw_lines = SOURCE.read_text(errors="replace").splitlines()
    all_lines = [l for l in raw_lines if l.strip()]

    # Filter: only nftables traffic entries
    traffic_lines = [l for l in all_lines if NFTABLES_MARKER in l]

    if not traffic_lines:
        print("[no traffic entries found] — no lines with 'nftables: ' prefix in source")
        return

    grouped: dict[str, list[str]] = defaultdict(list)
    for line in traffic_lines:
        grouped[_parse_date(line)].append(line)

    today_lines = grouped.get(TODAY, [])
    past_dates  = sorted(d for d in grouped if d != TODAY)

    # ── Past dates ────────────────────────────────────────────────────────────
    for d in past_dates:
        entries  = grouped[d]
        out_file = OUTPUT_DIR / f"{d}.log"

        if not entries:
            print(f"[{d}] 0 traffic entries, skipped")
            continue

        if out_file.exists() and out_file.stat().st_size > 0:
            print(f"[{d}] already exists, skipped")
            continue

        simplified = [s for s in (_simplify_line(l) for l in entries) if s is not None]
        out_file.write_text("\n".join(simplified) + "\n")
        print(f"[{d}] {len(simplified)}/{len(entries)} lines -> {out_file.name}")

    # ── Today ─────────────────────────────────────────────────────────────────
    if today_lines:
        today_file = OUTPUT_DIR / f"{TODAY}.log"
        simplified_today = [s for s in (_simplify_line(l) for l in today_lines) if s is not None]
        today_file.write_text("\n".join(simplified_today) + "\n")
        print(f"[{TODAY}] {len(simplified_today)}/{len(today_lines)} lines -> {TODAY}.log (today, overwritten)")
    else:
        print(f"[{TODAY}] 0 traffic entries for today")

    # ── Truncate source: keep only today's lines (all content, not just traffic)
    # This preserves the live syslog for today while removing past-date lines.
    if past_dates:
        today_all = [l for l in all_lines if _parse_date(l) == TODAY]
        removed_traffic = sum(len(grouped[d]) for d in past_dates)
        with open(SOURCE, "w") as fh:
            if today_all:
                fh.write("\n".join(today_all) + "\n")
        print(f"Source truncated: {removed_traffic} past-date traffic line(s) removed, "
              f"{len(today_all)} today line(s) kept.")


if __name__ == "__main__":
    main()
