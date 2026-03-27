"""
================================================================================
COM5413 — The Benji Protocol
Task 1: The Evidence Collector
File:   gateway_parser.py
================================================================================
"""

import argparse
import csv
import re
import sys
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# COMPILED REGEX PATTERNS
# Module-level constants — compiled once when the file loads, reused on every
# line. UPPERCASE names = Python convention for values that never change.
#
# Three patterns cover the log sources in the Benji lab:
#
#   PROFTPD_LOGIN_FAILED — ProFTPD failed FTP authentication.
#     Source: /var/log/proftpd/proftpd.log or /var/log/auth.log
#     ProFTPD logs its own failure format — not PAM. The IP appears in the
#     form (IP[IP]) before the USER field.
#     Example:
#       Mar 26 14:29:14 metasploitable3-ub1404 proftpd[5579]: localhost
#       (172.16.19.10[172.16.19.10]) - USER vagrant (Login failed): Incorrect password
#
#   FAILED_PASSWORD — OpenSSH failed password attempt.
#     Source: /var/log/auth.log
#     Example:
#       2024-03-15T01:01:27+00:00 gateway-01 sshd[4512]: Failed password for
#       admin from 5.188.206.12 port 44017 ssh2
#
#   INVALID_USER — OpenSSH connection closed for unknown username.
#     Source: /var/log/auth.log
#     Example:
#       2024-03-15T01:04:14+00:00 gateway-01 sshd[4659]: Connection closed by
#       invalid user postgres 194.26.29.18 port 44197 [preauth]
#
# Timestamp note — syslog vs ISO 8601:
#   ProFTPD writes syslog timestamps ("Mar 26 14:29:14") with no year.
#   SSH on the gateway writes ISO 8601 ("2024-03-15T01:01:27").
#   normalize_timestamp() converts both to a consistent ISO 8601 string
#   before the record is stored.
# ─────────────────────────────────────────────────────────────────────────────

PROFTPD_LOGIN_FAILED = re.compile(
    # Syslog timestamp — "Mar 26 14:29:14" or "Mar  4 09:00:01" (space-padded day)
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+\S+"  # hostname — skip, don't capture
    r"\s+proftpd\[\d+\]:\s+"  # service and PID — skip
    r"\S+\s+"  # connection label ("localhost") — skip
    # IP appears as (172.16.19.10[172.16.19.10]) — capture the first occurrence
    r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\["
    r"[^\)]*\)"  # rest of the bracket — skip
    r"\s+-\s+USER\s+"
    r"(?P<username>\S+)"  # the attempted username
    r"\s+\(Login failed\)"  # literal failure marker
)

FAILED_PASSWORD = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"  # ISO 8601 timestamp
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # or syslog timestamp
    r".*?"  # skip to anchor (non-greedy)
    r"Failed password for "  # literal anchor
    r"(?:invalid user )?"  # optional prefix (non-capturing)
    r"(?P<username>\S+)"  # the username
    r" from "  # literal separator
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"  # IP address
)

INVALID_USER = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"  # ISO 8601 timestamp
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # or syslog timestamp
    r".*?"  # skip to keyword (non-greedy)
    r"(?:Connection closed by |)"  # optional prefix phrase
    r"[Ii]nvalid user "  # case-insensitive variant
    r"(?P<username>\S+)"  # the username
    r" "  # space separator
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"  # IP address
)

# Order matters: ProFTPD is checked first, then SSH signatures.
# Each tuple describes: (service, event_type, compiled_pattern)
PATTERNS = [
    ("proftpd", "ftp_login_failed", PROFTPD_LOGIN_FAILED),
    ("sshd", "ssh_failed_password", FAILED_PASSWORD),
    ("sshd", "ssh_invalid_user", INVALID_USER),
]


# ─────────────────────────────────────────────────────────────────────────────
# TIMESTAMP NORMALISATION
# ─────────────────────────────────────────────────────────────────────────────


def normalize_timestamp(raw: str) -> str:
    """Convert a raw log timestamp to ISO 8601 format.

    Handles two formats:
      - ISO 8601:  "2024-03-15T01:01:27..."  → returned as-is (truncated to seconds)
      - Syslog:    "Mar 26 14:29:14"         → year inferred from current year

    Syslog caveat: logs spanning a year boundary will have the wrong year
    for entries from the previous year. This is a known limitation of the
    syslog format and cannot be resolved without external context.

    Args:
        raw: The raw timestamp string extracted by the regex.

    Returns:
        ISO 8601 string "YYYY-MM-DDTHH:MM:SS", or the original string if
        parsing fails (so the record is not silently dropped).
    """
    # ISO 8601 — already correct, just truncate timezone suffix if present
    if raw[0].isdigit():
        return raw[:19]

    # Syslog — normalise whitespace (space-padded day: "Mar  4" → "Mar 4")
    cleaned = " ".join(raw.split())
    try:
        dt = datetime.strptime(cleaned, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now().year).strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return raw  # return raw rather than drop the record


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────


def parse_arguments():
    """Handle command-line arguments.

    Returns:
        Namespace with attributes:
          .input_file — path to the log file
          .output     — path to the CSV output file (default: suspect.csv)
    """
    parser = argparse.ArgumentParser(
        description="Parses a log file and extracts failed authentication attempts."
    )

    parser.add_argument(
        "input_file",
        help="Path to the log file to parse",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Path to the output CSV file (default: suspect.csv)",
        default="suspect.csv",
    )

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# LOG PARSING
# ─────────────────────────────────────────────────────────────────────────────


def parse_log(file_path: str) -> list[dict]:
    """Read a log file and extract failed authentication attempts.

    Tries each pattern in PATTERNS against every line. On the first match,
    extracts timestamp, IP address, username, and attack metadata.
    De-duplicates on the (timestamp, ip, username, service, event_type)
    tuple before adding to results.

    Args:
        file_path: Path to the log file (string or Path-like).

    Returns:
        A list of dicts, one per unique event.
        Each dict has keys: timestamp, ip_address, username, service, event_type.
    """
    path = Path(file_path)

    if not path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    records = []
    seen = set()

    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            for service, event_type, pattern in PATTERNS:
                m = pattern.search(line)
                if m:
                    record_key = (
                        normalize_timestamp(m.group("timestamp")),
                        m.group("ip"),
                        m.group("username"),
                        service,
                        event_type,
                    )

                    if record_key not in seen:
                        seen.add(record_key)
                        records.append(
                            {
                                "timestamp": record_key[0],
                                "ip_address": record_key[1],
                                "username": record_key[2],
                                "service": record_key[3],
                                "event_type": record_key[4],
                            }
                        )

                    break  # one match per line — do not try remaining patterns

    return records


# ─────────────────────────────────────────────────────────────────────────────
# CSV OUTPUT
# ─────────────────────────────────────────────────────────────────────────────


def write_csv(records: list[dict], output_path: str) -> None:
    """Write extracted records to a CSV file.

    Args:
        records:     List of dicts with keys: timestamp, ip_address, username,
                     service, event_type.
        output_path: Path to the output CSV file (string or Path-like).
    """
    path = Path(output_path)

    fieldnames = ["timestamp", "ip_address", "username", "service", "event_type"]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Written {len(records)} record(s) to {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    """Coordinate the parser pipeline:
    1. Read command-line arguments
    2. Parse the log file
    3. Write results to CSV, or report if empty
    """
    args = parse_arguments()
    records = parse_log(args.input_file)

    if not records:
        print("[-] No matching records found.", file=sys.stderr)
        sys.exit(0)

    write_csv(records, args.output)


if __name__ == "__main__":
    main()
