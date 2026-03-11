"""
================================================================================
COM5413 — The Benji Protocol
IMF Field Test — Task 1: The Evidence Collector
================================================================================

These tests verify that log_parser.py meets the output contract defined in
the assessment brief. They are run by the auto-grader at submission and can
be run locally by you at any time.

Run with:
    pytest field_tests/test_task1.py -v

All tests must pass for full marks on the automated component of Task 1.
A failing test tells you exactly what the contract violation is — fix it.
================================================================================
"""

import csv
import subprocess
import sys
from pathlib import Path

# Path resolution — tests run from repo root
SCRIPT = Path("toolkit/task1_evidence_collector/log_parser.py")
SAMPLE_LOG = Path("field_tests/fixtures/sample_auth.log")
OUTPUT_CSV = Path("field_tests/fixtures/test_output.csv")

# ---------------------------------------------------------------------------
# Fixture: synthetic auth.log with known content
# ---------------------------------------------------------------------------

SAMPLE_LOG_CONTENT = """\
Jan 10 06:55:48 ubuntu sshd[1234]: Failed password for root from 192.168.56.200 port 22 ssh2
Jan 10 06:55:49 ubuntu sshd[1235]: Failed password for invalid user admin from 10.0.0.5 port 22 ssh2
Jan 10 06:55:50 ubuntu sshd[1236]: Invalid user testuser from 172.16.0.1 port 22
Jan 10 06:55:51 ubuntu sshd[1237]: Accepted password for msfadmin from 192.168.56.1 port 22 ssh2
Jan 10 06:55:52 ubuntu sshd[1238]: Failed password for root from 192.168.56.200 port 22 ssh2
"""


def setup_fixtures():
    """Create fixture files needed for tests."""
    fixture_dir = Path("field_tests/fixtures")
    fixture_dir.mkdir(parents=True, exist_ok=True)
    SAMPLE_LOG.write_text(SAMPLE_LOG_CONTENT)
    if OUTPUT_CSV.exists():
        OUTPUT_CSV.unlink()


def run_parser(args: list[str]) -> subprocess.CompletedProcess:
    """Helper: run log_parser.py with given arguments."""
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args,
        capture_output=True,
        text=True
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_script_exists():
    """Task 1 script must exist at the expected path."""
    assert SCRIPT.exists(), f"Script not found at {SCRIPT}"


def test_script_runs_without_error():
    """Script must execute without Python errors against a valid log."""
    setup_fixtures()
    result = run_parser([str(SAMPLE_LOG), "--output", str(OUTPUT_CSV)])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"


def test_output_csv_created():
    """suspects.csv (or --output target) must be created."""
    setup_fixtures()
    run_parser([str(SAMPLE_LOG), "--output", str(OUTPUT_CSV)])
    assert OUTPUT_CSV.exists(), "Output CSV was not created."


def test_csv_headers():
    """CSV must have exactly the required headers in the correct order."""
    setup_fixtures()
    run_parser([str(SAMPLE_LOG), "--output", str(OUTPUT_CSV)])
    with open(OUTPUT_CSV, newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == ["Timestamp", "IP_Address", "User_Account"], \
            f"Unexpected headers: {reader.fieldnames}"


def test_correct_ip_extraction():
    """Must correctly extract IP addresses from Failed password lines."""
    setup_fixtures()
    run_parser([str(SAMPLE_LOG), "--output", str(OUTPUT_CSV)])
    with open(OUTPUT_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    ips = {row["IP_Address"] for row in rows}
    assert "192.168.56.200" in ips, "Expected IP 192.168.56.200 not found."
    assert "10.0.0.5" in ips, "Expected IP 10.0.0.5 not found."
    assert "172.16.0.1" in ips, "Expected IP 172.16.0.1 not found."


def test_accepted_password_excluded():
    """Accepted password lines must NOT appear in output."""
    setup_fixtures()
    run_parser([str(SAMPLE_LOG), "--output", str(OUTPUT_CSV)])
    with open(OUTPUT_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    ips = [row["IP_Address"] for row in rows]
    assert "192.168.56.1" not in ips, \
        "Accepted password IP incorrectly included in suspects.csv"


def test_deduplication():
    """Duplicate entries (same timestamp+IP+user) must appear only once."""
    setup_fixtures()
    run_parser([str(SAMPLE_LOG), "--output", str(OUTPUT_CSV)])
    with open(OUTPUT_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    # 192.168.56.200 appears twice in the fixture — should appear once after dedup
    root_rows = [r for r in rows if r["IP_Address"] == "192.168.56.200" and r["User_Account"] == "root"]
    assert len(root_rows) == 1, \
        f"Duplicate entries not removed: found {len(root_rows)} rows for 192.168.56.200/root"


def test_missing_file_handled():
    """Script must exit cleanly (non-zero) when log file does not exist."""
    result = run_parser(["/tmp/this_file_does_not_exist_com5413.log"])
    assert result.returncode != 0, "Script should exit non-zero for missing input file."


def test_no_input_function_used():
    """Script must not contain input() calls — this breaks automation."""
    source = SCRIPT.read_text()
    assert "input(" not in source, \
        "input() found in script. All input must use argparse. NO EXCEPTIONS."
