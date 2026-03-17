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
from pathlib import Path

FAILED_PASSWORD = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"  # Group 1: the timestamp
    r".*?"  # Skip characters (non-greedy)
    r"Failed password for "  # Literal anchor text
    r"(?:invalid user )?"  # Optional prefix (non-capturing)
    r"(?P<username>\S+)"  # Group 2: the username
    r" from "  # Literal separator
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"  # Group 3: the IP address
)

INVALID_USER = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"  # ISO timestamp
    r".*?"  # skip to keyword (non-greedy)
    r"(?:Connection closed by |)"  # optional prefix phrase
    r"[Ii]nvalid user "  # 'Invalid user' or 'invalid user'
    r"(?P<username>\S+)"  # the username
    r" "  # space separator
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"  # IP address
)


def parse_arguments():
    """Handles Command-line arguments
    Returns an object with two attributes:
    .input_file = path to the logfile
    .output - path to the cvs file (this is optional and defaults to susptect.cvs)
    """

    parser = argparse.ArgumentParser(
        # how to read the command line arguments.
        description="Parses the log file and extracts relevant information"
    )

    # First argument:  The log path file.
    parser.add_argument(
        "input_file",  # positional argument - no dashes
        help="Path to the log file to parse",
    )

    # Second argument : the output file path - optional with default value.
    parser.add_argument(
        "-o",
        "--output",  # optional argument with short and long form
        help="Path to the output CSV file (default: suspect.csv)",
        default="suspect.csv",
    )

    return parser.parse_args()


def parse_log(file_path):
    """
    Read a log file and extract failed authentication attempts.

    Args:
        file_path: path to the log file (string)

    Returns:
        A list of dictionaries, one per unique suspicious event.
        Each dictionary has keys: Timestamp, IP_Address, User_Account
    """
    # Wrap string path in a Path object for safe file handling
    path = Path(file_path)

    # Check the file exists before trying to open it
    if not path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    # Two data structures to track our work:
    # 'records' — the output. A list of dictionaries, one per event.
    # 'seen' — a set of tuples for de-duplication.
    records = []
    seen = set()

    # Open the file safely — 'with' guarantees closure
    with path.open(encoding="utf-8", errors="ignore") as f:

        # Read the file one line at a time
        for line in f:

            # Try each pattern against this line.
            # [FAILED_PASSWORD, INVALID_USER] is a list of our two compiled patterns.
            # If we add a third pattern later, we add it to this list. Nothing else changes.
            for pattern in [FAILED_PASSWORD, INVALID_USER]:

                # Attempt to match this pattern against the current line
                m = pattern.search(line)

                # Did the pattern match? (m is not None)
                if m:
                    # Build a tuple of the three extracted values.
                    # This tuple is used as a key for de-duplication.
                    record_key = (
                        m.group("timestamp"),  # from the named group
                        m.group("ip"),  # from the named group
                        m.group("username"),  # from the named group
                    )

                    # Have we seen this exact combination before?
                    if record_key not in seen:
                        # First time — record it
                        seen.add(record_key)  # add to the de-duplication set

                        # Build the output dictionary.
                        # The keys MUST match the CSV header names exactly.
                        records.append(
                            {
                                "timestamp": record_key[0],
                                "ip_address": record_key[1],
                                "username": record_key[2],
                            }
                        )

                    # 'break' exits the INNER for loop (the pattern loop).
                    # If FAILED_PASSWORD matched this line, we do NOT also
                    # try INVALID_USER on the same line.
                    # One match per line is enough. Move to the next line.
                    break

    # All lines processed. Return whatever we found.
    return records


def write_csv(records, output_path):
    """
    Write extracted records to a CSV file.

    Args:
        records:     list of dictionaries (keys: Timestamp, IP_Address, User_Account)
        output_path: path to the output CSV file (string)
    """
    # Wrap the output path in a Path object
    path = Path(output_path)

    # Open the file for writing.
    # 'w'          = write mode. Creates the file, or overwrites if it exists.
    # newline=''   = REQUIRED for the csv module.
    #                The csv module writes its own line endings.
    #                If the file object ALSO adds line endings (the default),
    #                you get blank rows between your data rows.
    #                newline='' tells the file to not add extra ones.
    # encoding     = explicit UTF-8, as always.
    with path.open("w", newline="", encoding="utf-8") as f:

        # DictWriter takes a file object and a list of column names.
        # The fieldnames define both the header row and the column order.
        writer = csv.DictWriter(
            f, fieldnames=["Timestamp", "IP_Address", "User_Account"]
        )

        # Write the header row — the column names
        writer.writeheader()

        # Write all data rows at once.
        # Each dictionary in the list becomes one row.
        # Dictionary keys are matched to fieldnames.
        writer.writerows(records)

    # Confirm what was written — this goes to stdout
    print(f"[+] Written {len(records)} record(s) to {output_path}")


def main():
    """
    Coordinate the parser pipeline:
    1. Read command-line arguments
    2. Parse the log file
    3. Write results to CSV (or report if empty)
    """
    # Step 1: get the file paths from the command line
    args = parse_arguments()

    # Step 2: parse the log file — returns a list of record dictionaries
    records = parse_log(args.input_file)

    # Step 3: check if we found anything
    if not records:
        # 'not records' is True when the list is empty.
        print("[-] No matching records found.", file=sys.stderr)
        sys.exit(0)  # exit 0 = success. Empty results are valid.

    # Step 4: write the results to CSV
    write_csv(records, args.output)


if __name__ == "__main__":
    main()
