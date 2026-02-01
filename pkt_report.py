#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# pkt_report.py
#
# Copyright (c) 2026 Sean Rima and Murphy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# -----------------------------------------------------------------------------


import argparse
import sqlite3
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
from textwrap import shorten

# ----------------------------------------------------------------------
# Date parsing
# ----------------------------------------------------------------------

def parse_date_any(s: str) -> datetime:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty date")

    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%d %b %y %H:%M:%S",
        "%d-%b-%Y %H:%M",
        "%d-%b-%y",
    ]
    last_err = None
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except ValueError as e:
            last_err = e
            pass
    raise ValueError(f"Unrecognized date format: {s!r}")

def nice_header_date(s: str) -> str:
    return parse_date_any(s).strftime("%d-%b-%y")

# ----------------------------------------------------------------------
# DB helpers
# ----------------------------------------------------------------------

def table_columns(conn, table: str):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return [r[1] for r in cur.fetchall()]

def pick_date_expression(cols):
    """Prefer date_iso, then imported_at, then date_raw.

    Uses COALESCE + NULLIF so empty strings don't break range queries.
    """
    parts = []
    if "date_iso" in cols:
        parts.append("NULLIF(TRIM(date_iso),'')")
    if "imported_at" in cols:
        parts.append("NULLIF(TRIM(imported_at),'')")
    if "date_raw" in cols:
        parts.append("NULLIF(TRIM(date_raw),'')")

    if not parts:
        raise SystemExit("pkt_messages has no usable date columns (need date_iso/imported_at/date_raw).")

    return "COALESCE(" + ", ".join(parts) + ")"

# ----------------------------------------------------------------------
# Buckets
# ----------------------------------------------------------------------

def month_bucket(dt: datetime) -> int:
    # Jan/Feb/Mar shown as 13/14/15 to match your seasonal sample layout
    return dt.month + 12 if dt.month in (1, 2, 3) else dt.month

def build_day_columns(dt_min: datetime, dt_max: datetime):
    """Build a list of daily column keys across the inclusive range.

    We use *date objects* as the internal keys so counting is unambiguous,
    but we can still print a tidy header (DD only) even across month changes.
    """
    cols = []
    d = dt_min.date()
    end = dt_max.date()
    while d <= end:
        cols.append(d)
        d += timedelta(days=1)
    return cols

# ----------------------------------------------------------------------
# Top-per-echo helpers
# ----------------------------------------------------------------------

def _pick_first_column(cols, candidates):
    """Return the first column name from candidates that exists in cols, or None."""
    for c in candidates:
        if c in cols:
            return c
    return None

def _normalize_subject(subj: str) -> str:
    """Normalise subject so that replies with RE: count towards the same thread.

    Strips common "RE:" / "Re:" / "re[2]:" style prefixes repeatedly.
    """
    if not subj:
        return "(no subject)"
    s = subj.strip()
    # Strip repeated RE-style prefixes
    s = re.sub(r'^(re(\[\d+\])?:\s*)+', '', s, flags=re.IGNORECASE)
    s = s.strip()
    return s or "(no subject)"

def run_top_report(conn, date_expr: str, date_from: str, date_to: str, echo_name: str,
                   schema_version: str, limit: int = 10) -> None:
    """Print top posters/subjects for a single echo.

    If the database includes a message size column, also prints size-based TOP tables.
    """
    cur = conn.cursor()
    cols = table_columns(conn, "pkt_messages")

    poster_col = _pick_first_column(
        cols,
        ["from_name", "from_addr", "origin_name", "origin_addr", "sender"]
    )
    subj_col = _pick_first_column(
        cols,
        ["subject", "subj", "title"]
    )

    # Optional message size columns (bytes) and lines.
    size_col = _pick_first_column(
        cols,
        ["msg_size", "message_size", "size_bytes", "msg_bytes", "bytes"]
    )
    lines_col = _pick_first_column(
        cols,
        ["msg_lines", "message_lines", "lines"]
    )

    if not poster_col or not subj_col:
        missing = []
        if not poster_col:
            missing.append("poster column (from_name/from_addr/origin_name/origin_addr/sender)")
        if not subj_col:
            missing.append("subject column (subject/subj/title)")
        raise SystemExit("pkt_messages table is missing required columns: " + ", ".join(missing))

    select_bits = [
        f"{poster_col} AS poster",
        f"{subj_col} AS subject",
    ]
    if size_col:
        select_bits.append(f"{size_col} AS msg_size")
    if lines_col:
        select_bits.append(f"{lines_col} AS msg_lines")

    cur.execute(
        f"""
        SELECT {', '.join(select_bits)}
        FROM pkt_messages
        WHERE echo = ?
          AND {date_expr} >= ? AND {date_expr} <= ?
        """,
        (echo_name, date_from, date_to),
    )
    rows = cur.fetchall()

    if not rows:
        print(f"No messages found in echo {echo_name!r} for selected date range.")
        return

    from collections import Counter

    poster_counts = Counter()
    subject_counts = Counter()

    # Optional size aggregations per poster
    poster_total_bytes = Counter()
    poster_max_bytes = Counter()
    poster_total_lines = Counter()
    poster_max_lines = Counter()

    # Optional list of largest single messages
    biggest_msgs = []  # (size_bytes, lines, poster, subject_root)

    for r in rows:
        poster = (r["poster"] or "").strip() or "(unknown)"
        poster_counts[poster] += 1

        root = _normalize_subject(r["subject"])
        subject_counts[root] += 1

        if size_col:
            try:
                sz = int(r["msg_size"] or 0)
            except Exception:
                sz = 0
            poster_total_bytes[poster] += max(sz, 0)
            poster_max_bytes[poster] = max(poster_max_bytes.get(poster, 0), max(sz, 0))

            if sz > 0:
                ln = 0
                if lines_col:
                    try:
                        ln = int(r["msg_lines"] or 0)
                    except Exception:
                        ln = 0
                biggest_msgs.append((sz, ln, poster, root))

        if lines_col:
            try:
                ln2 = int(r["msg_lines"] or 0)
            except Exception:
                ln2 = 0
            poster_total_lines[poster] += max(ln2, 0)
            poster_max_lines[poster] = max(poster_max_lines.get(poster, 0), max(ln2, 0))

    def print_top_table(counter, label_header: str, title: str):
        print()
        print(title)
        print("=" * len(title))

        items = counter.most_common(limit)
        if not items:
            print("(no data)")
            return

        rank_width = len(str(len(items)))
        max_count = max(c for _, c in items)
        count_width = max(len("Msgs"), len(str(max_count)))

        # Work out a reasonable label column width (cap at 60)
        max_label_len = max(len(str(lbl)) for lbl, _ in items)
        label_width = max(len(label_header), min(60, max_label_len))

        header = f"{'#':>{rank_width}}  {label_header:<{label_width}}  {'Msgs':>{count_width}}"
        print(header)
        print("-" * len(header))

        for idx, (label, count) in enumerate(items, start=1):
            label_disp = shorten(str(label), width=label_width, placeholder="…")
            print(f"{idx:>{rank_width}}  {label_disp:<{label_width}}  {count:>{count_width}}")

    # Overall heading for this echo
    print(f"TCOB1 EchoMail top stats for area {echo_name}")
    print(f"(DB schema v{schema_version})")
    print(f"Statistics from {nice_header_date(date_from)} to {nice_header_date(date_to)}")
    print(f"Total messages in range: {len(rows)}")

    print_top_table(poster_counts, "Poster", "Top posters")
    print_top_table(subject_counts, "Subject", "Top subjects")

    # Size-based tables (if available)
    def _fmt_bytes(n: int) -> str:
        if n is None:
            return "0B"
        n = int(n)
        if n < 1024:
            return f"{n}B"
        if n < 1024 * 1024:
            return f"{n/1024:.1f}K"
        if n < 1024 * 1024 * 1024:
            return f"{n/(1024*1024):.1f}M"
        return f"{n/(1024*1024*1024):.1f}G"

    if size_col:
        print()
        title = "Top posters by total message size"
        print(title)
        print("=" * len(title))

        items = poster_total_bytes.most_common(limit)
        if not items:
            print("(no data)")
        else:
            rank_width = len(str(len(items)))
            max_label_len = max(len(str(lbl)) for lbl, _ in items)
            label_width = max(len("Poster"), min(40, max_label_len))

            max_total = max(v for _, v in items)
            total_width = max(len("Total"), len(_fmt_bytes(max_total)))

            # Max size column is useful context
            max_of_max = max(poster_max_bytes.get(p, 0) for p, _ in items)
            max_width = max(len("Max"), len(_fmt_bytes(max_of_max)))

            header = f"{'#':>{rank_width}}  {'Poster':<{label_width}}  {'Total':>{total_width}}  {'Max':>{max_width}}"
            print(header)
            print("-" * len(header))

            for idx, (poster, total_b) in enumerate(items, start=1):
                max_b = poster_max_bytes.get(poster, 0)
                poster_disp = shorten(str(poster), width=label_width, placeholder="…")
                print(f"{idx:>{rank_width}}  {poster_disp:<{label_width}}  {_fmt_bytes(total_b):>{total_width}}  {_fmt_bytes(max_b):>{max_width}}")

        # Biggest individual messages
        if biggest_msgs:
            biggest_msgs.sort(key=lambda x: x[0], reverse=True)
            top_big = biggest_msgs[:limit]
            print()
            title2 = "Largest individual messages"
            print(title2)
            print("=" * len(title2))
            print(f"{'#':>2}  {'Size':>8}  {'Poster':<20}  Subject")
            print("-" * 60)
            for i, (sz, ln, poster, subj) in enumerate(top_big, start=1):
                poster_disp = shorten(poster, width=20, placeholder="…")
                subj_disp = shorten(subj, width=60, placeholder="…")
                print(f"{i:>2}  {_fmt_bytes(sz):>8}  {poster_disp:<20}  {subj_disp}")
    else:
        print()
        print("(NOTE: no message size column found in pkt_messages; add msg_size/message_size to your indexer to enable size-based TOP stats.)")

# ----------------------------------------------------------------------
# Known / only / exclude areas file loader
# ----------------------------------------------------------------------

def load_area_list(path: str):
    """Load a list of echo areas from a file.

    Supported formats:
      * .txt/.lst: one area per line (blank and # lines ignored)
      * .json: either a JSON list ["AREA1", "AREA2"] or {"areas": [...]}.
    """
    if not path:
        return []

    with open(path, "r", encoding="utf-8") as f:
        data = f.read()

    # JSON if it looks like JSON or endswith .json
    if path.lower().endswith(".json") or data.lstrip().startswith(("[", "{")):
        obj = json.loads(data)
        if isinstance(obj, list):
            areas = obj
        elif isinstance(obj, dict) and isinstance(obj.get("areas"), list):
            areas = obj["areas"]
        else:
            raise SystemExit("Area JSON must be a list or an object with an 'areas' list")
        out = []
        for a in areas:
            if not isinstance(a, str):
                continue
            a = a.strip()
            if a:
                out.append(a)
        return out

    # Plain text list
    out = []
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="TCOB1 EchoMail area reporter (SQLite pkt_index.db)"
    )
    ap.add_argument("--db", "-d", default="pkt_index.db", help="SQLite DB file (default: pkt_index.db)")
    ap.add_argument("--from", dest="date_from", default=None, help="Start date/time (e.g. 2025-12-12)")
    ap.add_argument("--to", dest="date_to", default=None, help="End date/time (e.g. 2025-12-17)")
    ap.add_argument(
        "--date",
        type=str.upper,
        choices=["WEEK", "MONTH", "CMONTH"],
        help=(
            "Preset date ranges relative to DB max date: "
            "WEEK = last 7 days, "
            "MONTH = previous calendar month, "
            "CMONTH = current calendar month so far."
        ),
    )
    ap.add_argument("--period", choices=["auto", "month", "day"], default="auto",
                    help="Grouping period: month (09..12,13..15), day (12..17), or auto (default)")
    ap.add_argument("--days", type=int, default=None,
                    help="Convenience: last N days ending at DB max date (overrides --from/--to)")
    ap.add_argument("--known-areas", default=None,
                    help="Optional file listing areas to always include (zero-count rows). "
                         "Supports .txt (one per line) or .json ([..] or {\"areas\":[..]}).")
    ap.add_argument("--only-areas", default=None,
                    help="Optional file listing areas to report on exclusively (ignore others not listed). "
                         "Same format as --known-areas.")
    ap.add_argument("--exclude-areas", default=None,
                    help="Optional file listing areas to exclude from the report. Same format as --known-areas.")
    ap.add_argument("--top", metavar="ECHO", help="Show top posters/subjects for a single echo (instead of area summary)")
    ap.add_argument("--area-width", type=int, default=34, help="Area column width (default: 34)")
    args = ap.parse_args()

    # Disallow conflicting date options with --date
    if args.date and (args.days is not None or args.date_from or args.date_to):
        raise SystemExit("--date cannot be combined with --from/--to/--days. Use only one date-range option.")

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Ensure meta table exists + schema_version present (safe even for old DBs)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    cur.execute("""
    INSERT OR IGNORE INTO meta (key, value)
    VALUES ('schema_version', '1')
    """)
    conn.commit()

    cur.execute("SELECT value FROM meta WHERE key='schema_version'")
    row = cur.fetchone()
    schema_version = row["value"] if row else "unknown"

    # Validate pkt_messages exists
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pkt_messages'")
    if not cur.fetchone():
        raise SystemExit("No table pkt_messages found in this DB. Are you pointing at the right file?")

    cur.execute("SELECT COUNT(*) AS c FROM pkt_messages")
    total_rows = cur.fetchone()["c"]
    if total_rows == 0:
        # Allow zero-traffic reports if the user supplies a date range and a known-areas file
        if not (args.known_areas and args.date_from and args.date_to):
            raise SystemExit("pkt_messages is empty (0 rows).")

    cols_in_table = table_columns(conn, "pkt_messages")
    date_expr = pick_date_expression(cols_in_table)

    # DB date range (or user-supplied range if there are no message rows yet)
    if total_rows > 0:
        cur.execute(f"SELECT MIN({date_expr}) AS mn, MAX({date_expr}) AS mx FROM pkt_messages")
        r = cur.fetchone()
        db_min_s, db_max_s = r["mn"], r["mx"]
        if not db_min_s or not db_max_s:
            raise SystemExit("Rows exist, but all date fields are empty (date_iso/imported_at/date_raw).")
        db_min = parse_date_any(db_min_s)
        db_max = parse_date_any(db_max_s)
    else:
        db_min_s, db_max_s = args.date_from, args.date_to
        db_min = parse_date_any(db_min_s)
        db_max = parse_date_any(db_max_s)

    # Decide date range based on options
    if args.date:
        # Presets relative to DB max date
        dt_to = db_max

        if args.date == "WEEK":
            # Last 7 days ending at db_max
            dt_from = (dt_to - timedelta(days=6)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )

        elif args.date == "CMONTH":
            # Current month so far (first of month to db_max)
            dt_from = dt_to.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        elif args.date == "MONTH":
            # Previous full calendar month
            year = dt_to.year
            month = dt_to.month
            if month == 1:
                prev_year = year - 1
                prev_month = 12
            else:
                prev_year = year
                prev_month = month - 1

            dt_from = datetime(prev_year, prev_month, 1, 0, 0, 0)
            # First day of current month, then step back 1 second
            first_this_month = datetime(year, month, 1, 0, 0, 0)
            dt_to = first_this_month - timedelta(seconds=1)

        date_from = dt_from.strftime("%Y-%m-%d %H:%M:%S")
        date_to = dt_to.strftime("%Y-%m-%d %H:%M:%S")

    elif args.days is not None:
        # User requested last N days
        dt_to = db_max
        dt_from = (db_max - timedelta(days=max(args.days - 1, 0))).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        date_from = dt_from.strftime("%Y-%m-%d %H:%M:%S")
        date_to = dt_to.strftime("%Y-%m-%d %H:%M:%S")

    else:
        # Explicit from/to or full DB range
        date_from = args.date_from or db_min_s
        date_to = args.date_to or db_max_s
        dt_from = parse_date_any(date_from)
        dt_to = parse_date_any(date_to)

    # If user requested a per-echo top report, do that and exit early
    if args.top:
        run_top_report(conn, date_expr, date_from, date_to, args.top, schema_version)
        conn.close()
        return

    # Decide period
    period = args.period
    if period == "auto":
        span_days = (dt_to.date() - dt_from.date()).days
        period = "day" if span_days <= 31 else "month"

    # Build columns
    if period == "month":
        # Default seasonal columns like your sample: 15..09
        columns = [15, 14, 13, 12, 11, 10, 9]
        col_header = " ".join(f"{c:>4d}" for c in columns)
    else:
        day_cols = build_day_columns(dt_from, dt_to)
        columns = day_cols
        # Tidy day-only header even when month changes
        col_header = " ".join(f"{d.strftime('%d'):>4s}" for d in columns)

    # Query rows in range
    cur.execute(
        f"""
        SELECT echo, {date_expr} AS any_date
        FROM pkt_messages
        WHERE {date_expr} >= ? AND {date_expr} <= ?
        """,
        (date_from, date_to),
    )

    counts = defaultdict(lambda: defaultdict(int))
    areas_seen = set()
    bad_dates = 0

    for row in cur.fetchall():
        area = (row["echo"] or "").strip() or "UNKNOWN"
        try:
            dt = parse_date_any(row["any_date"])
        except Exception:
            bad_dates += 1
            continue

        if period == "month":
            b = month_bucket(dt)
            if b in columns:
                counts[area][b] += 1
        else:
            # Day keys are date objects (see build_day_columns)
            key = dt.date()
            if key in columns:
                counts[area][key] += 1

        areas_seen.add(area)

    # Overlay a fixed list of areas so zero-count rows appear
    if args.known_areas:
        for a in load_area_list(args.known_areas):
            areas_seen.add(a)

    # Restrict report to ONLY areas listed in a file
    only_areas_list = None
    if args.only_areas:
        only_areas_list = load_area_list(args.only_areas)
        # Ensure requested areas appear even if zero-count
        for a in only_areas_list:
            areas_seen.add(a)

    # Areas to exclude
    exclude_areas_list = None
    if args.exclude_areas:
        exclude_areas_list = load_area_list(args.exclude_areas)
        exclude_set = set(exclude_areas_list)
    else:
        exclude_set = set()

    # Print report
    print("TCOB1 EchoMail area reporter")
    print(f"(DB schema v{schema_version})")
    print()
    print(f"Statistics from {nice_header_date(date_from)} to {nice_header_date(date_to)}")
    print()

    area_width = args.area_width
    print(f"{'Area':<{area_width}}{col_header}   Total")
    print("=" * (area_width + len(col_header) + 8))

    # Per-day totals across all included areas (for a totals row at the bottom)
    day_totals = [0] * len(columns)
    grand_total = 0

    # Determine which areas to include (respect --only-areas and --exclude-areas)
    if only_areas_list:
        only_set = set(only_areas_list)
        iter_areas = [a for a in sorted(areas_seen) if a in only_set]
    else:
        iter_areas = sorted(areas_seen)

    if exclude_set:
        iter_areas = [a for a in iter_areas if a not in exclude_set]

    for area in iter_areas:
        row_vals = [counts[area].get(c, 0) for c in columns]
        # Accumulate day totals
        for i, v in enumerate(row_vals):
            day_totals[i] += v
            grand_total += v

        total = sum(row_vals)
        vals_str = " ".join(f"{v:>4d}" for v in row_vals)
        print(f"{shorten(area, width=area_width-1, placeholder='…'):<{area_width}}{vals_str} : {total:>5d}")

    # Totals row
    total_width = area_width + len(col_header) + 8
    sep = ('==' * (total_width // 2)) + ('=' if (total_width % 2) else '')
    print(sep)
    totals_str = " ".join(f"{v:>4d}" for v in day_totals)
    print(f"{'TOTALS':<{area_width}}{totals_str} : {grand_total:>5d}")

    if bad_dates:
        print()
        print(f"(NOTE: skipped {bad_dates} rows with unparseable dates)")

    conn.close()

if __name__ == "__main__":
    main()
