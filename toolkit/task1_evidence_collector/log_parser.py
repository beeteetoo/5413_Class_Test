"""
================================================================================
COM5413 — The Benji Protocol
Task 1: The Evidence Collector
File:   log_parser.py
================================================================================

MISSION BRIEF
-------------
Before any operation, Benji pulls the logs. Something happened on that server.
The evidence is in the noise — if you know how to read it.

Your job is to parse a Linux auth.log file and extract Indicators of Compromise
(IoC). Specifically, you are looking for failed authentication attempts that
suggest a brute-force attack. Your output must be structured, consistent, and
machine-readable — sloppy evidence gets people killed in the field.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept a log file path as a command-line argument (argparse — NO input()).
2. Use regular expressions (re) to identify lines containing:
   - "Failed password"
   - "Invalid user"
3. Extract from each matching line:
   - Timestamp
   - IP Address
   - User Account
4. Write a CSV report to suspects.csv (or a path specified via --output).
   CSV headers must be exactly: Timestamp, IP_Address, User_Account
5. Handle errors gracefully:
   - File not found
   - Empty file
   - No matches found (report zero results, do not crash)

CONSTRAINTS
-----------
- Python 3.10+ only.
- Standard library only (re, csv, argparse, pathlib).
- NO use of input() — all input via argparse.
- NO use of os.system() or subprocess.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
CSV file with headers: Timestamp, IP_Address, User_Account
Rows are comma-separated, one per matching log event.
Duplicate entries must be de-duplicated (same timestamp + IP + user = one row).

EXAMPLE USAGE
-------------
    python log_parser.py /var/log/auth.log
    python log_parser.py /var/log/auth.log --output /tmp/suspects.csv

BUILD LOG
---------
Use docs/build.md to record your development notes, decisions, and reflections
as you build this tool. Benji documents everything.
================================================================================
"""

# Your imports go here
import argparse
import csv
import re
import sys
from pathlib import Path


def parse_arguments():
    """
    Define and parse command-line arguments.
    Returns the parsed namespace object.
    """
    # TODO: Implement argparse
    # Required: input_file (positional)
    # Optional: --output (default: suspects.csv)
    pass


def parse_log(file_path: Path) -> list[dict]:
    """
    Read the log file and extract IoC records.

    Args:
        file_path: Path object pointing to the log file.

    Returns:
        A list of dicts, each containing:
        {'Timestamp': str, 'IP_Address': str, 'User_Account': str}

    Raises:
        FileNotFoundError: If the log file does not exist.
        ValueError: If the file is empty.
    """
    # TODO: Implement log parsing logic
    # Hint: compile your regex patterns before the loop for efficiency
    pass


def write_csv(records: list[dict], output_path: Path) -> None:
    """
    Write extracted records to a CSV file.

    Args:
        records:     List of IoC record dicts.
        output_path: Path object for the output CSV file.
    """
    # TODO: Implement CSV writing
    # Headers must be exactly: Timestamp, IP_Address, User_Account
    pass


def main():
    args = parse_arguments()
    # TODO: Wire parse_arguments → parse_log → write_csv
    # Handle exceptions and print informative messages to stderr
    pass


if __name__ == "__main__":
    main()
