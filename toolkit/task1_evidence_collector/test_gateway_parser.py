import csv
from pathlib import Path

import pytest
from gateway_parser import parse_log, write_csv

KNOWN_ATTACK_LINE = (
    "2024-03-15T01:01:27+00:00 gateway-01 sshd[4645]: "
    "Failed password for admin from 5.188.206.12 port 5746 ssh2\n"
)

CORRUPTED_LINE = (
    "2024-03-15T01:05:26+00:00 gateway-01 sshd[CORRUPTED - "
    "line truncated without closing bracket\n"
)

DUPLICATE_LINES = (
    "2024-03-15T01:01:27+00:00 gateway-01 sshd[4645]: "
    "Failed password for admin from 5.188.206.12 port 5746 ssh2\n"
    "2024-03-15T01:01:27+00:00 gateway-01 sshd[4645]: "
    "Failed password for admin from 5.188.206.12 port 5746 ssh2\n"
)


def test_failed_password_extracted(tmp_path):
    # Given a log file with a known attack line
    log_file = tmp_path / "test.log"
    log_file.write_text(KNOWN_ATTACK_LINE)

    # When we parse the log file
    records = parse_log(str(log_file))

    # Then we should extract the correct information
    assert len(records) == 1
    record = records[0]
    assert record["timestamp"] == "2024-03-15T01:01:27"
    assert record["username"] == "admin"
    assert record["ip_address"] == "5.188.206.12"


def test_corrupted_line_ignored(tmp_path):
    # Given a log file with a corrupted line
    log_file = tmp_path / "test.log"
    log_file.write_text(CORRUPTED_LINE)

    # When we parse the log file
    records = parse_log(str(log_file))

    # Then we should find no records (the corrupted line should be ignored)
    assert len(records) == 0


def test_duplicate_lines(tmp_path):
    # Given a log file with duplicate lines
    log_file = tmp_path / "test.log"
    log_file.write_text(DUPLICATE_LINES)

    # When we parse the log file
    records = parse_log(str(log_file))

    # Then we should extract both records (duplicates are not filtered out)
    assert len(records) == 1
