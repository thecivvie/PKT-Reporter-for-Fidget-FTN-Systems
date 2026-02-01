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

import sqlite3
import argparse
from textwrap import shorten
from pathlib import Path


def get_columns(cur, table: str):
    cur.execute(f"PRAGMA table_info({table})")
    return [r[1] for r in cur.fetchall()]


def main():
    ap = argparse.ArgumentParser(description="Quick inspector for pkt_index.db (supports extended schema)")
    ap.add_argument("--db", "-d", default="pkt_index.db", help="SQLite DB file (default: pkt_index.db)")
    ap.add_argument("--limit", "-n", type=int, default=20, help="Rows to display from pkt_messages (default: 20)")
    args = ap.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"DB file not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print(f"Inspecting: {db_path}\n")

    # --- Check for pkt_messages table ---
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pkt_messages'")
    row = cur.fetchone()
    if not row:
        print("No table 'pkt_messages' found in this database.")
        conn.close()
        return

    # --- Meta / schema_version ---
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='meta'")
    has_meta = bool(cur.fetchone())
    schema_version = "unknown"
    if has_meta:
        cur.execute("SELECT value FROM meta WHERE key='schema_version'")
        r = cur.fetchone()
        if r and r[0] is not None:
            schema_version = r[0]

    print(f"meta.schema_version: {schema_version}")
    if not has_meta:
        print("(NOTE: meta table is missing; this DB predates the current indexer schema.)")

    # --- Column presence ---
    cols = get_columns(cur, "pkt_messages")
    colset = set(cols)

    required_base = {
        "pkt_file", "msg_index", "date_iso", "date_raw", "echo",
        "size_bytes", "from_name", "subject", "imported_at"
    }
    missing_base = sorted(required_base - colset)

    has_msg_lines = "msg_lines" in colset
    has_pct_quoted = "pct_quoted" in colset

    print("\nColumns in pkt_messages:")
    print("  " + ", ".join(cols))

    if missing_base:
        print("\nWARNING: Missing expected base columns:")
        for c in missing_base:
            print(f"  - {c}")

    print("\nExtended body stats:")
    print(f"  msg_lines column present : {'YES' if has_msg_lines else 'NO'}")
    print(f"  pct_quoted column present: {'YES' if has_pct_quoted else 'NO'}")

    # --- Basic row counts / date range ---
    cur.execute("SELECT COUNT(*) FROM pkt_messages")
    total = cur.fetchone()[0]
    print(f"\nTotal messages in pkt_messages: {total}")

    if total > 0:
        # date_iso range (may be NULL for some rows, so use MIN/MAX on non-NULL)
        cur.execute("SELECT MIN(date_iso), MAX(date_iso) FROM pkt_messages WHERE date_iso IS NOT NULL")
        mn, mx = cur.fetchone()
        print(f"date_iso range           : {mn or '-'}  ->  {mx or '-'}")

        cur.execute("SELECT MIN(imported_at), MAX(imported_at) FROM pkt_messages")
        mn_i, mx_i = cur.fetchone()
        print(f"imported_at range        : {mn_i or '-'}  ->  {mx_i or '-'}")

    # --- Sample rows ---
    if total > 0:
        print(f"\nSample of first {min(args.limit, total)} messages:\n")
        cur.execute(
            """SELECT * FROM pkt_messages
                   ORDER BY rowid ASC
                   LIMIT ?""",
            (args.limit,),
        )

        # We'll base printing on available columns
        show_msg_lines = has_msg_lines
        show_pct_quoted = has_pct_quoted

        for row in cur.fetchall():
            keys = row.keys()

            echo = shorten((row["echo"] or "UNKNOWN"), 30) if "echo" in keys else "UNKNOWN"
            date_iso = row["date_iso"] if "date_iso" in keys else None
            size_bytes = row["size_bytes"] if "size_bytes" in keys else None
            from_name = shorten((row["from_name"] or "") if "from_name" in keys else "", 25)
            subject = shorten((row["subject"] or "") if "subject" in keys else "", 40)
            imported = row["imported_at"] if "imported_at" in keys else None

            parts = [
                f"[{row['id']}]" if "id" in keys else "[?]",
                f"Area={echo:<30}",
                f"date_iso={date_iso or '-'}",
                f"size={size_bytes if size_bytes is not None else '-'}",
            ]

            if show_msg_lines:
                ml = row["msg_lines"]
                parts.append(f"lines={ml if ml is not None else '-'}")

            if show_pct_quoted:
                val = row["pct_quoted"]
                parts.append(f"quoted={val:.1f}%"
                             if isinstance(val, (int, float)) else "quoted=-")

            parts.append(f"from={from_name!r}")
            parts.append(f"subj={subject!r}")
            parts.append(f"imported_at={imported or '-'}")

            print("  " + "  ".join(parts))

    conn.close()


if __name__ == "__main__":
    main()
