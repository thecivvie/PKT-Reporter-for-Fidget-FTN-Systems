#!/usr/bin/env python3
"""
fido_attach_mover.py
--------------------
Scans a folder of FidoNet .msg (Hudson/SquishMail binary) netmail messages.
For any message that is a file-attach (FLAGS DIR) addressed to one of the
configured destination addresses, the script:
  1. Moves the attached file to DEST_FOLDER
  2. Deletes the original attachment from its source location
  3. Deletes the .msg file itself

Run with TEST_MODE = True to see what *would* happen without touching anything.

All configuration lives in the CONFIG block below.
"""

import os
import re
import shutil
import struct
import logging

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

# Folder containing the .msg files to process
MSG_FOLDER = "/home/bbbs/fido/mail"

# Where to move matched attachment files
DEST_FOLDER = "/home/bbbs/fido/reporter"

# FidoNet addresses to match in the To: field.
# Accepts 5D (zone:net/node.point) or 4D (zone:net/node) forms.
# Point part is optional – "2:263/1" matches node 2:263/1 regardless of point.
# Add as many addresses as you like.
TARGET_ADDRESSES = [
    "2:263/1.100",
    "618:500/1.100",
    "21:1/229.100",
    "86:553/20.100",
    "314:413/30.100",
    "46:20/119.100",
    "999:1/10.100",
]

# Set to True to log actions without moving or deleting anything
TEST_MODE = False

# Log level: logging.DEBUG shows raw kludge parsing details
LOG_LEVEL = logging.INFO

# ─────────────────────────────────────────────────────────────────────────────
# END CONFIG
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ── .msg binary layout (Hudson/FIDO style, 238 bytes fixed header) ────────────
#
#  Offset  Size  Field
#  0       36    From name (null-padded)
#  36      36    To name   (null-padded)
#  72      72    Subject / attached filename (null-padded)
#  144     20    Date string (null-padded)
#  164     2     Times read
#  166     2     Dest node
#  168     2     Orig node
#  170     2     Cost
#  172     2     Orig net
#  174     2     Dest net
#  176     4     (date written, unused here)
#  180     4     (date arrived, unused here)
#  184     2     Reply
#  186     4     Attribute word (see FLAG_* below)
#  190     2     Next
#  192     2     Orig zone / text length (varies by variant)
#  194-237       padding / zone bytes
#  238+          Message text (kludge lines + body)
#
# Attribute flags (word at offset 186):
FLAG_FILE   = 0x0010   # Message has file attach
FLAG_KFS    = 0x0200   # Kill File after Sent (= KFS in FLAGS line)
# DIR (direct) is a kludge flag not a header bit in most implementations,
# but we detect it in the kludge lines too.

HEADER_SIZE = 190  # We only need up to the attribute word reliably

MSG_HEADER_FMT = "<36s36s72s20sHHHHHH4s4sHIH"
MSG_HEADER_FIELDS = (
    "from_name", "to_name", "subject",
    "date_str",
    "times_read",
    "dest_node", "orig_node", "cost",
    "orig_net", "dest_net",
    "_dw", "_da",
    "reply", "attr", "next_msg",
)


def parse_msg_header(data: bytes) -> dict:
    """Parse the fixed 190-byte Hudson .msg header."""
    size = struct.calcsize(MSG_HEADER_FMT)
    if len(data) < size:
        raise ValueError(f"File too short for header (need {size}, got {len(data)})")
    fields = struct.unpack(MSG_HEADER_FMT, data[:size])
    h = {k: v for k, v in zip(MSG_HEADER_FIELDS, fields)}
    # Decode null-terminated strings
    for key in ("from_name", "to_name", "subject", "date_str"):
        h[key] = h[key].split(b"\x00")[0].decode("cp437", errors="replace").strip()
    return h


def parse_kludges(text: bytes) -> dict[str, list[str]]:
    """
    Extract FidoNet kludge lines (0x01-prefixed) from message text.
    Returns a dict of {KLUDGE_NAME: [value, ...]} (upper-cased key).
    """
    kludges: dict[str, list[str]] = {}
    for line in text.split(b"\r"):
        if line.startswith(b"\x01"):
            parts = line[1:].decode("cp437", errors="replace").split(None, 1)
            if parts:
                key = parts[0].upper()
                val = parts[1] if len(parts) > 1 else ""
                kludges.setdefault(key, []).append(val.strip())
    return kludges


def fido_addr_to_tuple(addr: str):
    """
    Convert a FidoNet address string to a comparable tuple.
    Returns (zone, net, node, point) with point=0 if not specified.
    Accepts: "2:263/1.100", "2:263/1", "618:500/1.100"
    """
    addr = addr.strip()
    m = re.match(r"^(\d+):(\d+)/(\d+)(?:\.(\d+))?$", addr)
    if not m:
        raise ValueError(f"Cannot parse FidoNet address: {addr!r}")
    zone, net, node = int(m.group(1)), int(m.group(2)), int(m.group(3))
    point = int(m.group(4)) if m.group(4) else 0
    return (zone, net, node, point)


def build_target_set(addresses: list[str]):
    """
    Build a set of (zone, net, node, point) tuples from config addresses.
    Also builds a set of node-only tuples for addresses without a point,
    so "2:263/1" matches "2:263/1.100" as well.
    Returns (exact_set, node_wildcards).
    """
    exact = set()
    wildcards = set()  # (zone, net, node) – match any point
    for addr in addresses:
        t = fido_addr_to_tuple(addr)
        exact.add(t)
        if t[3] == 0:
            wildcards.add(t[:3])
    return exact, wildcards


def addr_matches(addr_tuple, exact_set, wildcards):
    """Return True if addr_tuple matches the configured targets."""
    if addr_tuple in exact_set:
        return True
    # Try without point
    if addr_tuple[:3] in wildcards:
        return True
    return False


def resolve_to_address(header: dict, kludges: dict) -> tuple | None:
    """
    Derive the true destination FidoNet address.
    Priority:
      1. INTL kludge  → "zone:net/node zone:net/node"  (dest is first token)
         combined with TOPT kludge for point
      2. Header dest_net / dest_node (zone unknown without INTL)
    Returns (zone, net, node, point) or None on failure.
    """
    intl_vals = kludges.get("INTL", [])
    topt_vals = kludges.get("TOPT", [])
    point = 0
    if topt_vals:
        try:
            point = int(topt_vals[0])
        except ValueError:
            pass

    if intl_vals:
        # INTL value: "dest_addr orig_addr"
        dest_str = intl_vals[0].split()[0]
        try:
            t = fido_addr_to_tuple(dest_str)
            return (t[0], t[1], t[2], point)
        except ValueError:
            log.debug("Could not parse INTL dest %r", dest_str)

    # Fallback: use header node/net, zone unknown (0)
    net = header.get("dest_net", 0)
    node = header.get("dest_node", 0)
    if net or node:
        log.debug("No INTL kludge; falling back to header net=%d node=%d", net, node)
        return (0, net, node, point)

    return None


def is_file_attach(header: dict, kludges: dict) -> bool:
    """
    Return True if the message is a file-attach.
    Checks: attribute FLAG_FILE bit, or FLAGS kludge containing DIR.
    """
    if header.get("attr", 0) & FLAG_FILE:
        return True
    flags = " ".join(kludges.get("FLAGS", []))
    if "DIR" in flags.upper():
        return True
    return False


def get_attachment_path(header: dict, kludges: dict) -> str | None:
    """
    Return the attachment file path.
    The subject field holds the path in Hudson .msg file-attach messages.
    """
    path = header.get("subject", "").strip()
    return path if path else None


def process_msg_file(msg_path: str, exact_set, wildcards, test_mode: bool) -> bool:
    """
    Process a single .msg file.
    Returns True if it was matched and actioned (or would be in test mode).
    """
    try:
        with open(msg_path, "rb") as f:
            data = f.read()
    except OSError as e:
        log.error("Cannot read %s: %s", msg_path, e)
        return False

    try:
        header = parse_msg_header(data)
    except (ValueError, struct.error) as e:
        log.warning("Skipping %s – header parse error: %s", msg_path, e)
        return False

    # Text body starts at fixed offset 190 in Hudson .msg format.
    # (struct.calcsize may be 192 due to alignment padding, which would
    #  clip the first two bytes of the kludge block.)
    text_body = data[190:]
    kludges = parse_kludges(text_body)

    log.debug("MSG %s | to=%r subject=%r attr=0x%04x kludges=%s",
              os.path.basename(msg_path),
              header["to_name"], header["subject"],
              header.get("attr", 0), list(kludges))

    if not is_file_attach(header, kludges):
        log.debug("  → not a file-attach, skipping")
        return False

    to_addr = resolve_to_address(header, kludges)
    if to_addr is None:
        log.warning("  → could not determine destination address in %s", msg_path)
        return False

    addr_str = f"{to_addr[0]}:{to_addr[1]}/{to_addr[2]}.{to_addr[3]}"
    log.debug("  → resolved To address: %s", addr_str)

    if not addr_matches(to_addr, exact_set, wildcards):
        log.debug("  → address %s not in target list, skipping", addr_str)
        return False

    attach_path = get_attachment_path(header, kludges)
    if not attach_path:
        log.warning("  → matched address %s but no attachment path in %s", addr_str, msg_path)
        return False

    log.info("MATCH: %s → to=%s attach=%s",
             os.path.basename(msg_path), addr_str, attach_path)

    attach_exists = os.path.isfile(attach_path)
    attach_name = os.path.basename(attach_path)
    dest_path = os.path.join(DEST_FOLDER, attach_name)

    if test_mode:
        log.info("  [TEST] Would move attachment: %s → %s", attach_path, dest_path)
        if not attach_exists:
            log.warning("  [TEST] Attachment not found on disk: %s", attach_path)
        log.info("  [TEST] Would delete .msg: %s", msg_path)
        return True

    # ── Live mode ────────────────────────────────────────────────────────────
    os.makedirs(DEST_FOLDER, exist_ok=True)

    if attach_exists:
        try:
            shutil.move(attach_path, dest_path)
            log.info("  Moved attachment: %s → %s", attach_path, dest_path)
        except OSError as e:
            log.error("  Failed to move attachment %s: %s", attach_path, e)
            return False
    else:
        log.warning("  Attachment not found on disk (already gone?): %s", attach_path)

    try:
        os.remove(msg_path)
        log.info("  Deleted .msg: %s", msg_path)
    except OSError as e:
        log.error("  Failed to delete .msg %s: %s", msg_path, e)
        return False

    return True


def main():
    log.info("fido_attach_mover starting%s", " [TEST MODE]" if TEST_MODE else "")
    log.info("MSG folder   : %s", MSG_FOLDER)
    log.info("Dest folder  : %s", DEST_FOLDER)
    log.info("Target addrs : %s", TARGET_ADDRESSES)

    try:
        exact_set, wildcards = build_target_set(TARGET_ADDRESSES)
    except ValueError as e:
        log.error("Bad address in TARGET_ADDRESSES: %s", e)
        return

    if not os.path.isdir(MSG_FOLDER):
        log.error("MSG_FOLDER does not exist: %s", MSG_FOLDER)
        return

    msg_files = sorted(
        f for f in os.listdir(MSG_FOLDER)
        if f.lower().endswith(".msg")
    )

    if not msg_files:
        log.info("No .msg files found in %s", MSG_FOLDER)
        return

    log.info("Found %d .msg file(s)", len(msg_files))
    matched = 0
    for fname in msg_files:
        full_path = os.path.join(MSG_FOLDER, fname)
        if process_msg_file(full_path, exact_set, wildcards, TEST_MODE):
            matched += 1

    log.info("Done. %d/%d messages matched.", matched, len(msg_files))
    if TEST_MODE:
        log.info("(No files were moved or deleted – TEST_MODE is True)")


if __name__ == "__main__":
    main()
