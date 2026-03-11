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
