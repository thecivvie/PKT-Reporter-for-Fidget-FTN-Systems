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
import struct
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, List


# ============================================================
# Date Parsing Helpers
# ============================================================

def parse_fido_datetime(s: str) -> Tuple[Optional[str], str]:
    """
    Try to parse a Fido/PKT style date string into ISO format.
    Returns (iso_datetime, raw_string).
    """
    raw = s.strip()
    if not raw:
        return None, s

    fmts = [
        "%d %b %y  %H:%M:%S",
        "%d %b %y %H:%M:%S",
        "%d %b %Y  %H:%M:%S",
        "%d %b %Y %H:%M:%S",
    ]

    for fmt in fmts:
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.isoformat(sep=" "), s
        except ValueError:
            pass

    return None, s


def parse_pkt_datetime(date_str: str) -> Optional[str]:
    """Compatibility wrapper if you ever want a simple call."""
    iso, _ = parse_fido_datetime(date_str)
    return iso


# ============================================================
# Echo & Body Analysis
# ============================================================

def extract_echo(body_text: str) -> Optional[str]:
    """
    Echomail area is usually on a line like:
      AREA:CONNEMARA.WEATHER
    Sometimes preceded by a ^A (0x01). We scan the first ~30 lines.
    """
    for line in body_text.splitlines()[:30]:
        if not line:
            continue
        if line.startswith("\x01"):
            line = line[1:]  # drop kludge prefix

        if line.upper().startswith("AREA:"):
            area = line[5:].strip()
            if area:
                return area
    return None


def analyse_body(body_text: str):
    """
    Analyse the message body text and return:
      (msg_lines, pct_quoted)

    msg_lines:
        number of non-kludge lines (lines NOT starting with ^A)

    pct_quoted:
        percentage of those non-kludge lines that are quoted,
        i.e. begin with '>' (ignoring leading whitespace).
        Returns None if there are no non-kludge lines.
    """
    lines = body_text.splitlines()
    usable = [l for l in lines if not l.startswith("\x01")]  # remove kludges

    total = len(usable)
    if total == 0:
        return 0, None

    quoted = sum(1 for l in usable if re.match(r"\s*>", l))
    pct = (quoted * 100.0) / float(total)
    return total, pct


# ============================================================
# PKT Parsing Helpers
# ============================================================

def read_cstr(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Read a NUL-terminated string starting at offset.
    Returns (decoded_string, new_offset_past_nul).
    """
    end = data.find(b"\x00", offset)
    if end == -1:
        raise ValueError("Missing NUL terminator in PKT string")
    s = data[offset:end]
    return s.decode("latin-1", errors="replace"), end + 1


PKT_HDR_LEN = 58  # Type 2/2+ header length


def parse_pkt_file(pkt_path: Path) -> List[dict]:
    """
    Parse a .pkt and return a list of message dicts with keys:
      pkt_file, msg_index, date_iso, date_raw, echo,
      size_bytes, msg_lines, pct_quoted, from_name, subject
    """
    data = pkt_path.read_bytes()
    if len(data) < PKT_HDR_LEN:
        raise ValueError(f"{pkt_path} too small to be a PKT")

    off = PKT_HDR_LEN
    results: List[dict] = []
    msg_index = 0

    while True:
        if off + 2 > len(data):
            break

        (msg_type,) = struct.unpack_from("<H", data, off)
        off += 2

        # End-of-packet marker
        if msg_type == 0x0000:
            break

        # Expect Type 2 message header (most common)
        # Header is 22 bytes total including msg_type already consumed (2 + 20).
        if off + 20 > len(data):
            raise ValueError(f"{pkt_path}: truncated message header")

        # Remaining header fields (10 uint16s)
        # (origNode,destNode,origNet,destNet,origZone,destZone,
        #  origPoint,destPoint,attr,cost)
        _fields = struct.unpack_from("<HHHHHHHHHH", data, off)
        off += 20

        date_str, off = read_cstr(data, off)
        _to_name, off = read_cstr(data, off)
        from_name, off = read_cstr(data, off)
        subject, off = read_cstr(data, off)

        # Body is NUL-terminated
        end = data.find(b"\x00", off)
        if end == -1:
            raise ValueError(f"{pkt_path}: message body missing terminator")

        body_bytes = data[off:end]
        off = end + 1

        body_text = body_bytes.decode("latin-1", errors="replace")

        # Analyse body text for statistics
        msg_lines, pct_quoted = analyse_body(body_text)

        date_iso, date_raw = parse_fido_datetime(date_str)
        echo = extract_echo(body_text)
        size_bytes = len(body_bytes)

        results.append({
            "pkt_file": str(pkt_path),
            "msg_index": msg_index,
            "date_iso": date_iso,
            "date_raw": date_raw.strip(),
            "echo": echo,
            "size_bytes": size_bytes,
            "msg_lines": msg_lines,
            "pct_quoted": pct_quoted,
            "from_name": from_name.strip(),
            "subject": subject.strip(),
        })

        msg_index += 1

    return results


# ============================================================
# DB Schema & Helpers (schema_version = 2)
# ============================================================

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS pkt_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pkt_file TEXT NOT NULL,
    msg_index INTEGER NOT NULL,

    date_iso TEXT,
    date_raw TEXT,

    echo TEXT,
    size_bytes INTEGER NOT NULL,
    msg_lines INTEGER,
    pct_quoted REAL,

    from_name TEXT,
    subject TEXT,

    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pkt_unique
ON pkt_messages(pkt_file, msg_index);

CREATE INDEX IF NOT EXISTS idx_pkt_date ON pkt_messages(date_iso);
CREATE INDEX IF NOT EXISTS idx_pkt_echo ON pkt_messages(echo);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

INSERT OR IGNORE INTO meta (key, value)
VALUES ('schema_version', '2');
"""


def init_db(db_path: Path) -> sqlite3.Connection:
    """
    Initialise DB and auto-migrate older versions to include msg_lines/pct_quoted.
    Also bumps meta.schema_version to '2'.
    """
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA_SQL)

    # Ensure new columns exist for older databases
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(pkt_messages)")
    cols = [r[1] for r in cur.fetchall()]
    if "msg_lines" not in cols:
        cur.execute("ALTER TABLE pkt_messages ADD COLUMN msg_lines INTEGER")
    if "pct_quoted" not in cols:
        cur.execute("ALTER TABLE pkt_messages ADD COLUMN pct_quoted REAL")

    # Bump schema_version to 2 for any existing DB
    cur.execute("""
        INSERT OR IGNORE INTO meta (key, value)
        VALUES ('schema_version', '2')
    """)
    cur.execute("""
        UPDATE meta
        SET value = '2'
        WHERE key = 'schema_version'
    """)
    conn.commit()
    return conn


def insert_messages(conn: sqlite3.Connection, messages: List[dict]) -> int:
    cur = conn.cursor()
    inserted = 0

    for m in messages:
        cur.execute(
            """
            INSERT OR IGNORE INTO pkt_messages
              (pkt_file, msg_index, date_iso, date_raw, echo,
               size_bytes, msg_lines, pct_quoted, from_name, subject)
            VALUES
              (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                m["pkt_file"],
                m["msg_index"],
                m["date_iso"],
                m["date_raw"],
                m["echo"],
                m["size_bytes"],
                m.get("msg_lines"),
                m.get("pct_quoted"),
                m["from_name"],
                m["subject"],
            )
        )
        inserted += cur.rowcount

    conn.commit()
    return inserted


# ============================================================
# Main
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description="Index FidoNet *.pkt files into a SQLite database "
                    "(schema v2: date/echo/size/lines/quoted/from/subject)."
    )
    ap.add_argument(
        "--folder", "-f", default=".",
        help="Folder containing .pkt files (default: current dir)"
    )
    ap.add_argument(
        "--db", "-d", default="pkt_index.db",
        help="SQLite DB file (default: pkt_index.db)"
    )
    ap.add_argument(
        "--test", action="store_true",
        help="Test mode: list extracted fields; no DB writes, no deletes"
    )
    ap.add_argument(
        "--delete", action="store_true",
        help="After successful import, delete processed .pkt files"
    )
    ap.add_argument(
        "--recursive", action="store_true",
        help="Scan folder recursively for *.pkt"
    )
    args = ap.parse_args()

    folder = Path(args.folder).expanduser().resolve()
    db_path = Path(args.db).expanduser().resolve()

    if not folder.is_dir():
        raise SystemExit(f"Not a directory: {folder}")

    pattern = "**/*.pkt" if args.recursive else "*.pkt"
    pkt_files = sorted(folder.glob(pattern))

    if not pkt_files:
        print(f"No .pkt files found in {folder}")
        return

    if args.test:
        conn = None
    else:
        conn = init_db(db_path)

    total_msgs = 0
    total_inserted = 0
    processed_files = 0

    for pkt in pkt_files:
        try:
            messages = parse_pkt_file(pkt)
        except Exception as e:
            print(f"[ERROR] {pkt}: {e}")
            continue

        if args.test:
            print(f"=== {pkt.name}: {len(messages)} messages ===")
            for m in messages:
                print(
                    f"{m['pkt_file']} #{m['msg_index']}: "
                    f"date_iso={m['date_iso']!r} date_raw={m['date_raw']!r} "
                    f"echo={m['echo']!r} size={m['size_bytes']} "
                    f"lines={m['msg_lines']} quoted={m['pct_quoted']} "
                    f"from={m['from_name']!r} subj={m['subject']!r}"
                )
            total_msgs += len(messages)
            processed_files += 1
            continue

        inserted = insert_messages(conn, messages)
        total_msgs += len(messages)
        total_inserted += inserted
        processed_files += 1

        if args.delete and inserted == len(messages):
            try:
                pkt.unlink()
                print(f"[OK] {pkt.name}: {len(messages)} msgs (inserted {inserted}), deleted")
            except Exception as e:
                print(f"[WARN] {pkt.name}: imported but could not delete: {e}")
        else:
            print(f"[OK] {pkt.name}: {len(messages)} msgs (inserted {inserted})")

    if not args.test and conn:
        conn.close()

    if args.test:
        print(
            f"\nTest complete: {processed_files} files, "
            f"{total_msgs} messages (no DB writes, no deletes)."
        )
    else:
        print(
            f"\nDone: {processed_files} files, {total_msgs} messages, "
            f"{total_inserted} inserted into {db_path}."
        )

if __name__ == "__main__":
    main()
