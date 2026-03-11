#!/usr/bin/env bash
# =============================================================================
# The Benji Protocol — COM5413 GitHub Classroom Starter Repository Setup
# University of Bolton | Programming for Cyber Security
# =============================================================================
# Usage:
#   chmod +x setup_benji_protocol.sh
#   ./setup_benji_protocol.sh
#
# This script creates the full starter repository structure for The Benji
# Protocol assessment. Run this once in the root of your GitHub Classroom
# template repository before pushing it as the starter code.
# =============================================================================

set -e

echo "========================================================"
echo "  The Benji Protocol — Repository Initialisation"
echo "  COM5413 | Programming for Cyber Security"
echo "  University of Bolton"
echo "========================================================"
echo ""

# =============================================================================
# DIRECTORY STRUCTURE
# =============================================================================

mkdir -p toolkit/task1_evidence_collector
mkdir -p toolkit/task2_network_cartographer
mkdir -p toolkit/task3_access_validator
mkdir -p toolkit/task4_web_enumerator
mkdir -p field_tests
mkdir -p vulnerability_hunt
mkdir -p docs

echo "[+] Directory structure created."

# =============================================================================
# TOOLKIT — TASK 1: THE EVIDENCE COLLECTOR
# =============================================================================

cat > toolkit/task1_evidence_collector/log_parser.py << 'PYEOF'
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
PYEOF

# Placeholder output artefact
touch toolkit/task1_evidence_collector/suspects.csv
echo "Timestamp,IP_Address,User_Account" > toolkit/task1_evidence_collector/suspects.csv

echo "[+] Task 1 — Evidence Collector scaffolded."

# =============================================================================
# TOOLKIT — TASK 2: THE NETWORK CARTOGRAPHER
# =============================================================================

cat > toolkit/task2_network_cartographer/scan.py << 'PYEOF'
"""
================================================================================
COM5413 — The Benji Protocol
Task 2: The Network Cartographer
File:   scan.py
================================================================================

MISSION BRIEF
-------------
Ethan cannot go in blind. Benji maps every door, every service, every version
number. The scan is not the attack — it is the intelligence that makes the
attack possible. A missed service or a wrong version assumption costs the
mission.

Your job is to build a threaded TCP port scanner that identifies open ports and
grabs the service banner from each one. The banner is the service telling you
exactly what it is and what version it is running. Listen carefully.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept a target IP and port range/list as command-line arguments.
2. Attempt a TCP connection to each port using Python's socket library.
3. If the port is open, attempt to receive the service banner (the greeting
   text the service sends on connection).
4. Use threading (ThreadPoolExecutor) to scan multiple ports concurrently.
5. Implement a connection timeout (default 0.5s) — hanging the scanner is not
   an option in the field.
6. Output results as JSON: printed to stdout AND saved to recon_results.json.

CONSTRAINTS
-----------
- Python 3.10+ only.
- Use socket — do NOT wrap nmap or any external scanner.
- NO use of input() — all input via argparse.
- Timeout must be configurable via --timeout argument.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
JSON structure:
{
    "target": "192.168.x.x",
    "scan_time": "YYYY-MM-DD HH:MM:SS",
    "open_ports": [
        {"port": 21, "banner": "220 (vsFTPd 2.3.4)"},
        {"port": 22, "banner": "SSH-2.0-OpenSSH_4.7p1"},
        {"port": 80, "banner": ""}
    ]
}
"banner" must always be present — use empty string if no banner received.

EXAMPLE USAGE
-------------
    python scan.py 192.168.56.101 --ports 1-1024
    python scan.py 192.168.56.101 --ports 21,22,80,443
    python scan.py 192.168.56.101 --ports 1-65535 --timeout 1.0 --threads 100

BUILD LOG
---------
Use docs/build.md to record your development notes, decisions, and reflections
as you build this tool. Pay particular attention to documenting what you observe
in the banner output when scanning Metasploitable — this feeds directly into
the Vulnerability Hunt.
================================================================================
"""

# Your imports go here
import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path


def parse_arguments():
    """
    Define and parse command-line arguments.

    Returns the parsed namespace object.
    Required: target (positional IP address)
    Optional: --ports, --timeout, --threads, --output
    """
    # TODO: Implement argparse
    # --ports should accept both ranges (1-1024) and lists (21,22,80)
    pass


def parse_port_input(port_string: str) -> list[int]:
    """
    Parse a port string into a list of integer port numbers.

    Accepts:
        "1-1024"    → [1, 2, 3, ..., 1024]
        "21,22,80"  → [21, 22, 80]

    Args:
        port_string: Raw string from argparse.

    Returns:
        Sorted list of port integers.

    Raises:
        ValueError: If the format is unrecognised or ports are out of range.
    """
    # TODO: Implement port range/list parsing
    pass


def grab_banner(sock: socket.socket, timeout: float = 0.5) -> str:
    """
    Attempt to receive a banner string from an open socket.

    Args:
        sock:    An already-connected socket object.
        timeout: Seconds to wait for banner data.

    Returns:
        Decoded banner string, or empty string if no banner received.
    """
    # TODO: Implement banner grabbing
    # Handle: timeout, decode errors, empty response
    pass


def check_port(target: str, port: int, timeout: float) -> dict | None:
    """
    Attempt a TCP connection to target:port.

    Args:
        target:  IP address string.
        port:    Port number integer.
        timeout: Connection timeout in seconds.

    Returns:
        Dict {"port": int, "banner": str} if open, None if closed/filtered.
    """
    # TODO: Implement TCP connect attempt
    # On success: call grab_banner(), return result dict
    # On failure: return None (do not raise)
    pass


def main():
    args = parse_arguments()
    # TODO: Wire parse_arguments → parse_port_input → ThreadPoolExecutor
    #       → collect results → write JSON output
    pass


if __name__ == "__main__":
    main()
PYEOF

touch toolkit/task2_network_cartographer/recon_results.json
echo '{"target": "", "scan_time": "", "open_ports": []}' > toolkit/task2_network_cartographer/recon_results.json

echo "[+] Task 2 — Network Cartographer scaffolded."

# =============================================================================
# TOOLKIT — TASK 3: THE ACCESS VALIDATOR
# =============================================================================

cat > toolkit/task3_access_validator/brute.py << 'PYEOF'
"""
================================================================================
COM5413 — The Benji Protocol
Task 3: The Access Validator
File:   brute.py
================================================================================

MISSION BRIEF
-------------
Some doors are locked. Some are locked with the factory default. A good
operative checks quietly, one at a time, without tripping the alarm. Benji
does not kick doors down — he tries the handle first, then tries the spare key,
then the one labelled "admin123" that someone left on a sticky note.

Your job is to build a targeted credential testing tool for SSH and FTP
services. This is a precision instrument, not a battering ram — the mandatory
delay between attempts is not optional, and it is not a courtesy. It is what
separates a professional test from a denial-of-service attack.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept target IP, service (ssh/ftp), username, and wordlist path as
   command-line arguments.
2. For FTP: use ftplib to attempt authentication.
3. For SSH: use paramiko to attempt authentication.
4. Iterate through the wordlist, attempting each password in sequence.
5. Include time.sleep(0.1) between each attempt — this is a hard requirement.
6. Stop immediately upon finding valid credentials.
7. Log each attempt (timestamp, username, password tried, result) to a file.

CONSTRAINTS
-----------
- Python 3.10+ only.
- SSH: must use paramiko. FTP: must use ftplib.
- time.sleep(0.1) MUST be present between attempts — auto-grader checks this.
- NO use of input() — all input via argparse.
- Wordlist may contain empty lines and non-ASCII characters — handle both.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
On success, print exactly:
    [+] SUCCESS: Password found: <password>

On exhaustion (no valid credentials found), print exactly:
    [-] EXHAUSTED: No valid credentials found for user <username>

EXAMPLE USAGE
-------------
    python brute.py 192.168.56.101 --service ftp --user msfadmin --wordlist rockyou_small.txt
    python brute.py 192.168.56.101 --service ssh --user root --wordlist common_passwords.txt

BUILD LOG
---------
Use docs/build.md to document your testing approach. Record what you observe
when testing against Metasploitable — attempt counts, timing, any connection
drops. This becomes part of your evidence trail.
================================================================================
"""

# Your imports go here
import argparse
import ftplib
import time
import sys
from datetime import datetime
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("[-] paramiko not installed. Run: pip install paramiko", file=sys.stderr)
    sys.exit(1)


def parse_arguments():
    """
    Define and parse command-line arguments.

    Returns the parsed namespace object.
    Required: target (positional), --service, --user, --wordlist
    """
    # TODO: Implement argparse
    # --service must be constrained to choices: ['ssh', 'ftp']
    pass


def load_wordlist(wordlist_path: Path) -> list[str]:
    """
    Load passwords from a wordlist file.

    Args:
        wordlist_path: Path to the wordlist file.

    Returns:
        List of password strings with empty lines and whitespace stripped.

    Raises:
        FileNotFoundError: If wordlist does not exist.
    """
    # TODO: Implement wordlist loading
    # Handle: empty lines, non-ASCII bytes (use errors='ignore' on open)
    pass


def attempt_ftp(target: str, user: str, password: str) -> bool:
    """
    Attempt FTP authentication using ftplib.

    Args:
        target:   IP address string.
        user:     Username string.
        password: Password string to test.

    Returns:
        True if authentication succeeds, False otherwise.
    """
    # TODO: Implement FTP auth attempt
    # Handle: connection refused, timeout, authentication error
    # Do NOT let exceptions propagate — return False on any failure
    pass


def attempt_ssh(target: str, user: str, password: str) -> bool:
    """
    Attempt SSH authentication using paramiko.

    Args:
        target:   IP address string.
        user:     Username string.
        password: Password string to test.

    Returns:
        True if authentication succeeds, False otherwise.
    """
    # TODO: Implement SSH auth attempt
    # Use paramiko.SSHClient with AutoAddPolicy for host key
    # Handle: AuthenticationException, SSHException, socket errors
    # Do NOT let exceptions propagate — return False on any failure
    pass


def main():
    args = parse_arguments()
    # TODO: Wire parse_arguments → load_wordlist → attempt loop
    # Remember: time.sleep(0.1) between EVERY attempt
    # Log each attempt to a file for the evidence trail
    pass


if __name__ == "__main__":
    main()
PYEOF

echo "[+] Task 3 — Access Validator scaffolded."

# =============================================================================
# TOOLKIT — TASK 4: THE WEB ENUMERATOR
# =============================================================================

cat > toolkit/task4_web_enumerator/web_enum.py << 'PYEOF'
"""
================================================================================
COM5413 — The Benji Protocol
Task 4: The Web Enumerator
File:   web_enum.py
================================================================================

MISSION BRIEF
-------------
The web layer talks too much. Server versions buried in HTTP headers. Developer
notes left in HTML comments. Sensitive paths left exposed because nobody
thought to check. Benji listens. A well-configured web server tells you almost
nothing; most servers are not well-configured.

Your job is to build an HTTP reconnaissance tool that extracts intelligence
from HTTP response headers and HTML source. This is passive reconnaissance —
you are reading what the server is already broadcasting, not probing for
weaknesses directly.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept a target URL as a command-line argument.
2. Send an HTTP GET request and analyse the response headers for:
   - Server (e.g., Apache/2.2.8)
   - X-Powered-By (e.g., PHP/5.2.4)
   - Any other headers that reveal technology or version information.
3. Parse the HTML response using BeautifulSoup to extract:
   - All HTML comments (<!-- --> blocks) — flags are often hidden here.
4. Check for the existence of sensitive paths:
   - /robots.txt
   - /admin
   - /phpmyadmin
   - /login
   - /.git
   (Report found/not found for each — do not enumerate further.)
5. Output a structured summary (JSON or formatted plaintext).

CONSTRAINTS
-----------
- Python 3.10+ only.
- Must use requests and beautifulsoup4 (bs4).
- Set a request timeout (default 5s) — never hang.
- Handle redirects gracefully (requests does this by default — be aware of it).
- NO use of input() — all input via argparse.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
Print a summary containing at minimum:
    [HEADERS]
    Server: <value or "Not present">
    X-Powered-By: <value or "Not present">

    [COMMENTS]
    Found <n> HTML comment(s):
    1. <comment text>
    2. <comment text>

    [SENSITIVE PATHS]
    /robots.txt       → FOUND (200)
    /admin            → NOT FOUND (404)
    ...

EXAMPLE USAGE
-------------
    python web_enum.py http://192.168.56.101
    python web_enum.py http://192.168.56.101/dvwa --timeout 10

BUILD LOG
---------
Use docs/build.md to record what you find when running against Metasploitable.
HTML comments in particular — document what you find and what it implies.
This intelligence feeds directly into the Vulnerability Hunt diagnosis phase.
================================================================================
"""

# Your imports go here
import argparse
import sys
from urllib.parse import urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"[-] Missing dependency: {e}. Run: pip install requests beautifulsoup4", file=sys.stderr)
    sys.exit(1)


# Sensitive paths to probe — this list can be extended
SENSITIVE_PATHS = [
    "/robots.txt",
    "/admin",
    "/phpmyadmin",
    "/login",
    "/.git",
]


def parse_arguments():
    """
    Define and parse command-line arguments.

    Returns the parsed namespace object.
    Required: url (positional)
    Optional: --timeout (default 5)
    """
    # TODO: Implement argparse
    pass


def analyse_headers(response: requests.Response) -> dict:
    """
    Extract security-relevant information from HTTP response headers.

    Args:
        response: A requests.Response object.

    Returns:
        Dict of relevant header names to values.
        Use "Not present" for missing headers.
    """
    # TODO: Extract Server, X-Powered-By, and any other revealing headers
    pass


def extract_comments(html: str) -> list[str]:
    """
    Extract all HTML comments from a page's source.

    Args:
        html: Raw HTML string.

    Returns:
        List of comment strings (stripped of <!-- --> delimiters).
    """
    # TODO: Use BeautifulSoup to find Comment objects
    # from bs4 import Comment
    # soup.find_all(string=lambda text: isinstance(text, Comment))
    pass


def check_sensitive_paths(base_url: str, timeout: int) -> dict:
    """
    Probe a list of sensitive paths and record HTTP status codes.

    Args:
        base_url: The target base URL.
        timeout:  Request timeout in seconds.

    Returns:
        Dict mapping path string to status code integer (or None if error).
    """
    # TODO: Iterate SENSITIVE_PATHS, HEAD or GET request each, record status
    # Use urljoin to construct full URLs safely
    pass


def main():
    args = parse_arguments()
    # TODO: Wire parse_arguments → analyse_headers → extract_comments
    #       → check_sensitive_paths → print formatted output
    pass


if __name__ == "__main__":
    main()
PYEOF

echo "[+] Task 4 — Web Enumerator scaffolded."

# =============================================================================
# FIELD TESTS — Week 1 test released at start; others pushed weekly
# =============================================================================

cat > field_tests/test_task1.py << 'PYEOF'
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
PYEOF

# Placeholder test files for weeks 2-4 (released progressively)
for i in 2 3 4; do
cat > field_tests/test_task${i}.py << PYEOF
"""
================================================================================
COM5413 — The Benji Protocol
IMF Field Test — Task ${i}
================================================================================

This test file will be released at the start of Week ${i} Session A.

Pull from the template repository before Session A begins:
    git pull origin main

Do not modify this file. Run with:
    pytest field_tests/test_task${i}.py -v
================================================================================
"""

def test_placeholder():
    """This test suite will be released in Week ${i}. Check back then."""
    pass
PYEOF
done

mkdir -p field_tests/fixtures
touch field_tests/fixtures/.gitkeep

echo "[+] Field tests scaffolded."

# =============================================================================
# VULNERABILITY HUNT
# =============================================================================

cat > vulnerability_hunt/exploit.py << 'PYEOF'
"""
================================================================================
COM5413 — The Benji Protocol
Vulnerability Hunt — Exploit Script
File:   exploit.py
================================================================================

MISSION BRIEF
-------------
This is where the mission goes live. You have mapped the target (Task 2),
identified the vulnerable service, and confirmed access vectors. Now you write
the Python logic that triggers the vulnerability.

This file is your exploit script. It must:
1. Connect to the target using only Python — NO Metasploit, NO auto-pwn tools.
2. Implement the specific exploitation logic for the identified vulnerability.
3. Retrieve the Flag from the target system.
4. Print the Flag to stdout in the format: FLAG: <value>

You will not know the specific vulnerability until the Vulnerability Hunt
session begins. However, the structure of this script should already be in
place — connection logic, argument parsing, output format. Benji does not
improvise the scaffolding on the day. He improvises the payload.

WHAT MUST BE HERE AT SUBMISSION
--------------------------------
- Working exploit logic that retrieves the Flag via Python.
- Argparse interface accepting at minimum: --target, --port.
- The Flag printed to stdout.
- Your approach documented in REPORT.md.

CONSTRAINTS
-----------
- Python 3.10+ only.
- NO Metasploit. NO automated exploit frameworks.
- You must write the connection and trigger logic yourself.
- Code you cannot explain during the session will be flagged for review.

EXAMPLE USAGE (structure — payload depends on scenario)
-------------------------------------------------------
    python exploit.py --target 192.168.56.101 --port 21

BUILD LOG
---------
Document your exploit development in docs/build.md AS YOU GO.
Capture: what you tried, what failed, what worked, and why.
This is Benji's mission log — it is evidence of your thinking process.
================================================================================
"""

import argparse
import socket
import sys


def parse_arguments():
    """
    Define and parse command-line arguments.
    Minimum required: --target, --port
    Add additional arguments as your exploit logic requires.
    """
    # TODO: Implement argparse
    pass


def main():
    args = parse_arguments()
    # TODO: Implement exploit logic
    # Print flag as: FLAG: <value>
    pass


if __name__ == "__main__":
    main()
PYEOF

cat > vulnerability_hunt/fix.py << 'PYEOF'
"""
================================================================================
COM5413 — The Benji Protocol
Vulnerability Hunt — Remediation Script
File:   fix.py
================================================================================

MISSION BRIEF
-------------
Getting in is only half the job. Benji does not leave doors open behind him.
Your remediation script must close the vulnerability that your exploit.py
triggered — while keeping the service running. A patch that kills the service
is not a patch, it is an outage.

This file is your remediation script. It must:
1. Connect to the target (via SSH using paramiko, or direct file manipulation).
2. Implement the specific remediation action for the identified vulnerability.
3. Verify that the service is still running after remediation.
4. Print a confirmation that the remediation was applied.

WHAT MUST BE HERE AT SUBMISSION
--------------------------------
- Working remediation logic (script) OR a detailed configuration patch with
  step-by-step commentary explaining each action.
- Argparse interface accepting at minimum: --target.
- Confirmation output showing remediation was applied.
- Your approach documented in REPORT.md.

RUBRIC CONTEXT
--------------
- Exceptional (80%+): Fully automated — runs with one command, patches and
  verifies automatically.
- Distinction (70-79%): Working script or valid configuration file with
  correct logic.
- Merit (60-69%): Descriptive text guide rather than executable code.
- Pass (50-59%): Partial attempt with correct intent.

EXAMPLE USAGE
-------------
    python fix.py --target 192.168.56.101

BUILD LOG
---------
Document your remediation approach in docs/build.md.
What does this vulnerability look like from the defender's perspective?
What is the minimal change that closes it without disrupting the service?
================================================================================
"""

import argparse
import sys

try:
    import paramiko
except ImportError:
    print("[-] paramiko not installed. Run: pip install paramiko", file=sys.stderr)
    sys.exit(1)


def parse_arguments():
    """
    Define and parse command-line arguments.
    Minimum required: --target
    Add additional arguments as your remediation logic requires.
    """
    # TODO: Implement argparse
    pass


def main():
    args = parse_arguments()
    # TODO: Implement remediation logic
    pass


if __name__ == "__main__":
    main()
PYEOF

cat > vulnerability_hunt/REPORT.md << 'EOF'
# The Benji Protocol — Vulnerability Hunt Report

**Student Name:**
**Student ID:**
**Date:**
**Target:** Metasploitable (192.168.x.x)

---

## 1. Diagnose

### Reconnaissance Summary
<!-- What did scan.py and web_enum.py reveal? Paste key JSON output here. -->

### Identified Vulnerability
<!-- Service name, version, CVE reference if applicable. -->
<!-- What does this vulnerability allow an attacker to do? -->

### Evidence
<!-- Commit reference or paste of the recon_results.json entry that identified the target service. -->

---

## 2. Exploit

### Approach
<!-- Describe the exploitation logic in plain English before showing code. -->
<!-- What does the exploit do mechanically? Why does it work? -->

### Execution
<!-- Command used: -->
```
python exploit.py --target x.x.x.x --port xx
```

### Flag
```
FLAG: <paste flag here>
```

---

## 3. Remediate

### Approach
<!-- What change closes this vulnerability? -->
<!-- Why does this change work — what is the root cause you are addressing? -->

### Execution
<!-- Command used or configuration change applied: -->
```
python fix.py --target x.x.x.x
```

### Verification
<!-- How did you confirm the vulnerability is closed and the service is still running? -->

---

## 4. Reflection

<!-- 150-200 words. -->
<!-- What was the most significant technical obstacle you encountered? -->
<!-- What would you do differently if you had more time? -->
<!-- How does this exercise connect to your understanding of the broader vulnerability management lifecycle? -->
EOF

echo "[+] Vulnerability Hunt directory scaffolded."

# =============================================================================
# DOCUMENTATION DIRECTORY
# =============================================================================

cat > docs/build.md << 'EOF'
# The Benji Protocol — Build Log

**Student Name:**
**Student ID:**
**GitHub Repository:**

---

> "Benji documents everything. Not because he is asked to. Because a tool with
> no history is a tool you cannot trust, and a mission with no record is a
> mission that never happened."

This is your running build log. Update it after every significant coding
session. It is not an essay — it is a technical journal. Short entries are
fine. No entry is not fine.

The build log serves three purposes:
1. It is evidence of your development process for the portfolio marker.
2. It is your own reference when something breaks at 23:00 the night before
   the Vulnerability Hunt.
3. It demonstrates that the code in your repository is yours.

---

## How to Use This Document

Add a new entry for each session using the template below. Commit this file
alongside your code — the build log and the code should tell the same story.

---

## Entry Template

### [DATE] — [TASK / SESSION]

**What I built / changed:**

**What broke and how I fixed it:**

**Decisions I made and why:**

**What the tool output when I ran it against Metasploitable:**

**Questions or things to revisit:**

---

## Week 1 — Task 1: Evidence Collector

### [DATE] — Session A



### [DATE] — Session B



---

## Week 2 — Task 2: Network Cartographer

### [DATE] — Session A

**Metasploitable scan output (paste key results):**
```json

```

**Observations — what services did you find? What do the banners tell you?**



### [DATE] — Session B



---

## Week 3 — Task 3: Access Validator

### [DATE] — Session A



### [DATE] — Session B



---

## Week 4 — Task 4: Web Enumerator

### [DATE] — Session A

**Metasploitable web recon output:**


**HTML comments found:**


**Sensitive paths found:**



### [DATE] — Session B



---

## Week 5 — Vulnerability Hunt

> This section is your mission log. Update it in real time during the session.
> Benji does not write the mission log after the mission. He writes it during.

### Pre-Hunt Checklist

- [ ] All four toolkit tools pass their field tests locally
- [ ] `requirements.txt` is up to date (`pip freeze > requirements.txt`)
- [ ] `AI_LOG.md` is current
- [ ] `vulnerability_hunt/exploit.py` — argument parsing in place
- [ ] `vulnerability_hunt/fix.py` — argument parsing in place
- [ ] `vulnerability_hunt/REPORT.md` — headings populated, ready to fill
- [ ] Git remote confirmed, can push
- [ ] Tags w1, w2, w3, w4 in place

### Hunt Log

**[TIME] — Diagnosis phase:**


**[TIME] — Vulnerability identified:**


**[TIME] — Exploit development:**


**[TIME] — Flag retrieved:**
```
FLAG:
```

**[TIME] — Remediation:**


**[TIME] — Final commit and push:**

EOF

echo "[+] Documentation directory scaffolded."

# =============================================================================
# ROOT LEVEL FILES
# =============================================================================

cat > AI_LOG.md << 'EOF'
# AI Transparency Log — The Benji Protocol

**Student Name:**
**Student ID:**

---

## Policy Summary

You may use GenAI tools (ChatGPT, GitHub Copilot, etc.) to debug, explain,
or refactor code. You must document every substantive use in this log.

You may NOT paste the Vulnerability Hunt scenario into an AI tool and ask
for the solution. Code you cannot explain during the session will be flagged.

---

## Log Format

| Week | Task | Prompt Used | AI Output Summary | My Verification / Changes Made |
|------|------|-------------|-------------------|-------------------------------|
| Example | Task 1 | "Write a regex to extract IP addresses from auth.log" | Provided `\b(?:\d{1,3}\.){3}\d{1,3}\b` | Tested against fixture — missed IPs embedded mid-line. Added word boundary adjustment. |

---

## Entries

| Week | Task | Prompt Used | AI Output Summary | My Verification / Changes Made |
|------|------|-------------|-------------------|-------------------------------|
|      |      |             |                   |                                |

EOF

cat > requirements.txt << 'EOF'
# The Benji Protocol — COM5413
# Add any libraries beyond the standard list here.
# Run: pip freeze > requirements.txt before final submission.
#
# Pre-approved libraries (no addition needed):
paramiko
requests
beautifulsoup4
EOF

cat > README.md << 'EOF'
# The Benji Protocol

**COM5413 — Programming for Cyber Security**
**University of Bolton | HE5**

---

**Student Name:**
**Student ID:**
**Cohort:**

---

## Repository Structure

```
/toolkit/                          # Weekly tool builds (Part 1)
/field_tests/                      # IMF-issued unit tests — do not modify
/vulnerability_hunt/               # Capstone assessment submission (Part 2)
/docs/                             # Build log and documentation
AI_LOG.md                          # AI usage audit — mandatory
requirements.txt                   # Python dependencies
```

---

## The Toolkit

Brief one-line description of each tool as you complete it:

| Task | Tool | What It Does | Status |
|------|------|--------------|--------|
| 1 | `log_parser.py` | | |
| 2 | `scan.py` | | |
| 3 | `brute.py` | | |
| 4 | `web_enum.py` | | |

---

## Running the Tools

```bash
# Task 1
python toolkit/task1_evidence_collector/log_parser.py <log_file>

# Task 2
python toolkit/task2_network_cartographer/scan.py <target_ip> --ports 1-1024

# Task 3
python toolkit/task3_access_validator/brute.py <target_ip> --service ftp --user <user> --wordlist <file>

# Task 4
python toolkit/task4_web_enumerator/web_enum.py <url>
```

---

## Running the Field Tests

```bash
pip install pytest
pytest field_tests/ -v
```

---

## Git Tag Reference

| Tag | Meaning |
|-----|---------|
| `w1` | Task 1 complete — tests passing |
| `w2` | Task 2 complete — tests passing |
| `w3` | Task 3 complete — tests passing |
| `w4` | Task 4 complete — tests passing |
| `hunt-final` | Vulnerability Hunt submission — NO COMMITS AFTER THIS TAG |
EOF

echo "[+] Root files created."

# =============================================================================
# INITIALISE GIT REPOSITORY
# =============================================================================

if [ ! -d ".git" ]; then
    git init
    echo "[+] Git repository initialised."
fi

git add .
git commit -m "scaffold: initial Benji Protocol repository structure

- Toolkit task stubs with full docstrings and function scaffolding
- Field test suite for Task 1 (Tasks 2-4 released progressively)
- Vulnerability Hunt directory with exploit.py, fix.py, REPORT.md stubs
- Documentation directory with build.md mission log template
- AI_LOG.md, requirements.txt, README.md

This is your starting point. Benji builds from here."

echo ""
echo "========================================================"
echo "  Setup complete."
echo ""
echo "  Repository structure:"
echo ""
find . -not -path './.git/*' -not -name '.gitkeep' | sort | sed 's|[^/]*/|  |g'
echo ""
echo "  Next steps:"
echo "  1. Push this to GitHub Classroom as the template repository."
echo "  2. Release field_tests/test_task2.py before Week 2 Session A."
echo "  3. Release field_tests/test_task3.py before Week 3 Session A."
echo "  4. Release field_tests/test_task4.py before Week 4 Session A."
echo "========================================================"
EOF
