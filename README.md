# pkt_report / pkt_indexer

A small, practical toolkit for indexing, analysing, and reporting
FidoNet-style packet and echomail traffic using SQLite.

Built for sysops who like clear stats, tidy reports, and scripts that
don’t get in the way.

Developed and used in real-world BBS / FTN environments.

-----------------------------------------------------------------------

## 📦 What’s Included

This repository contains three core tools that work together:

### pkt_indexer.py
Indexes FTN packets and messages into a SQLite database.

What it does:
- Parses incoming packet/message data
- Stores per-message metadata
- Tracks areas, posters, dates, sizes, and message characteristics

Data captured (depending on configuration):
- Area name
- Origin / poster
- Message date
- Message size (bytes)
- Line count (excluding kludges)
- Quoted percentage

This script is normally run periodically or via cron as packets arrive.

-----------------------------------------------------------------------

### pkt_db_check.py
Validates and prepares the SQLite database schema.

What it does:
- Checks the database exists and is accessible
- Verifies required tables and columns
- Creates missing tables/columns if needed
- Ensures schema compatibility with newer report features

This allows the reporter to evolve without breaking existing databases.

-----------------------------------------------------------------------

### pkt_report.py
Generates human-readable traffic reports from the indexed data.

Supported reports:
- Daily traffic tables by area
- Totals and per-day breakdowns
- TOP reports (posters, areas, message sizes)

Notable features:
- Clean day-based headers (robust across month changes)
- Optional filtering by area or zone
- TOP reports including:
  - Total messages
  - Total bytes posted
  - Average message size
  - Largest individual messages

Output is designed for terminal, email, or BBS posting.

-----------------------------------------------------------------------

## 🛠 Requirements

- Python 3.8+
- SQLite3 (standard library)
- No third-party dependencies

Tested on:
- Linux (including Raspberry Pi)
- macOS

-----------------------------------------------------------------------

## 🚀 Typical Workflow

1. Index packets as they arrive:

   python3 pkt_indexer.py --folder /path/to/pkts --db pkt_index.db --delete

2. Verify / inspect the database (safe to re-run):

   python3 pkt_db_check.py --db pkt_index.db

3. Generate reports:

   python3 pkt_report.py --db pkt_index.db --date WEEK

-----------------------------------------------------------------------

## 🧰 Usage / CLI

### pkt_indexer.py
Indexes *.pkt files into SQLite.

Common options:
- --folder, -f     Folder containing .pkt files (default: current directory)
- --db, -d         SQLite database path (default: pkt_index.db)
- --recursive      Scan subfolders for .pkt
- --delete         Delete .pkt files after successful import
- --test           Parse and display data without writing to DB

Examples:

Index a spool directory recursively:
  python3 pkt_indexer.py -f /home/fmail/ftn/inbound --recursive -d pkt_index.db

Test parsing without DB writes:
  python3 pkt_indexer.py -f /home/fmail/ftn/inbound --test

Import and delete packets after success:
  python3 pkt_indexer.py -f /home/fmail/ftn/inbound --recursive --delete

-----------------------------------------------------------------------

### pkt_db_check.py
Database inspector / sanity checker.

Common options:
- --db, -d     SQLite database path (default: pkt_index.db)
- --limit, -n  Number of sample rows to display (default: 20)

Example:

  python3 pkt_db_check.py -d pkt_index.db -n 50

-----------------------------------------------------------------------

### pkt_report.py
Generates traffic summary tables and TOP reports.

Date range options (pick one):
- --date WEEK | MONTH | CMONTH
  WEEK   = last 7 days
  MONTH  = previous calendar month
  CMONTH = current calendar month so far
- --days N
- --from YYYY-MM-DD --to YYYY-MM-DD

Report shaping:
- --period auto | month | day
- --area-width N

Area inclusion / exclusion:
- --known-areas FILE
- --only-areas FILE
- --exclude-areas FILE

Files may be .txt (one area per line, # comments allowed) or .json.

TOP mode:
- --top ECHO
  Shows top posters and message-size statistics (if size data exists)

Examples:

Last 7 days:
  python3 pkt_report.py -d pkt_index.db --date WEEK

Last 30 days:
  python3 pkt_report.py -d pkt_index.db --days 30

Explicit date range:
  python3 pkt_report.py -d pkt_index.db --from 2026-01-26 --to 2026-02-01

Include known areas:
  python3 pkt_report.py -d pkt_index.db --date WEEK --known-areas known.txt

Only selected areas:
  python3 pkt_report.py -d pkt_index.db --date WEEK --only-areas areas.json

Exclude areas:
  python3 pkt_report.py -d pkt_index.db --date WEEK --exclude-areas exclude.txt

TOP report for one echo:
  python3 pkt_report.py -d pkt_index.db --date WEEK --top MIN_CHAT

-----------------------------------------------------------------------

## 📊 Example Output

Statistics from 26-Jan-26 to 01-Feb-26

Area                                26   27   28   29   30   31   01   Total
============================================================================
MIN_CHAT                             4    6    3    9    2    1    5 :    30
MIN_WEATHER                          1    0    2    1    0    3    2 :     9
============================================================================
TOTALS                               5    6    5   10    2    4    7 :    39

TOP message size example:

=== TOP POSTERS BY TOTAL MESSAGE SIZE ===
Poster           Messages   Total KB   Avg KB   Max KB
------------------------------------------------------
Sean                  42       418.2      9.9     22.1
MurphyBot             18       146.5      8.1     18.6

-----------------------------------------------------------------------

## 🧠 Design Notes

- Internal date keys are used for correctness
- Display formatting prioritises readability
- Schema changes are handled defensively
- Scripts are intentionally simple and hackable

-----------------------------------------------------------------------

## 📜 License

MIT License

Copyright (c) 2026 Sean Rima and Murphy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

-----------------------------------------------------------------------

## ☕ Final Words

If you’re running an FTN-style system in 2026 and still care about good stats,
this is for you.

Pull requests welcome. Hacks encouraged. Coffee optional but recommended.

