#!/usr/bin/env python3
"""
gateway_scanner.py

TCP connect scanner with banner grabbing.
Concept vehicle for COM5413 Week 2.

This tool finds open ports on a target and reads what those services
say when you connect to them. That is it. Unassuming. Effective.

Transfer the architecture to scan.py for your assessment.
Same four functions. Different filename. Different context.
The transfer is the point — not the copy.

Usage:
    python3 gateway_scanner.py 172.16.19.101 --ports 1-1024
    python3 gateway_scanner.py 172.16.19.101 --ports 21,22,80
    python3 gateway_scanner.py 172.16.19.101 --ports 1-65535 --threads 200
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 1 OF 4: parse_port_input
#
# The user types something at the command line. This function turns that
# something into a list of integers that the scanner can iterate over.
#
# It has absolutely no idea what a socket is. It does not care.
# Its entire world is strings going in and lists coming out.
# This ensures we handle user input in one place, and the rest of the code can trust that it is
# ─────────────────────────────────────────────────────────────────────────────


def parse_port_input(port_str: str) -> list[int]:
    """
    Convert a port specification string into a sorted, deduplicated list.

    '80'          → [80]
    '1-1024'      → [1, 2, 3, ... , 1023, 1024]  (yes, all of them)
    '21,22,80'    → [21, 22, 80]
    '1-3,8,10-12' → [1, 2, 3, 8, 10, 11, 12]
    """
    ports = []

    # Split on commas first. '21,22,80' becomes ['21', '22', '80'].
    # Each piece is either a single port or a range. We handle both below.
    for part in port_str.split(","):
        part = part.strip()  # defensive against '21, 22, 80' with spaces

        if "-" in part:
            # It is a range: '1-1024'
            # split('-', 1) limits to ONE split — the 1 is not optional.
            # '1-1024'.split('-', 1) → ['1', '1024']  ✓
            # Without the 1: still fine here, but worth being explicit.
            pieces = part.split("-", 1)
            start, end = [int(x.strip()) for x in pieces]
            # ^ That is a list comprehension. [expression for item in iterable]
            # Equivalent to start = int(pieces[0].strip()); end = int(pieces[1].strip())
            # Two lines compressed to one. Both are correct.

            # range(start, end + 1) — the + 1 is because range() excludes the end.
            # range(1, 1025) gives 1 to 1024. Not range(1, 1024). Easy to forget.
            ports.extend(range(start, end + 1))

            # HINT: What should happen if start is 0? Or end is 70000?
            # Or someone types '80-20' (start bigger than end)?
            # Right now: nothing good, go on try it.
            # Something useful would involve ValueError.

        else:
            # It is a single port: '80'
            ports.append(int(part))

            # HINT: What should happen if part is 'abc'?
            # int('abc') does not quietly return 0.
            # That exception currently propagates upward uncaught.
            # Whether that is acceptable is a question worth asking.

    # sorted() guarantees ascending order — the JSON contract requires it.
    # set() removes duplicates — '1-5,3,4' should produce [1,2,3,4,5].
    # Both operations happen in one line. Python is occasionally kind to your eyes.
    return sorted(set(ports))


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 2 OF 4: check_port
#
# Asks the operating system if anything listening on this port?
# The OS sends a TCP SYN packet, waits for a response, and reports back.
# Your code does not send the packet. The kernel of the OS does.
# The OS response is either "yes, open", "no, closed", or "I waited and got nothing back".
#
# Returns True if open. Returns False if closed or filtered.
# That is the entire API surface of this function.
# ─────────────────────────────────────────────────────────────────────────────


def check_port(target: str, port: int, timeout: float = 0.5) -> bool:
    """
    Attempt a TCP connection to target:port.

    Returns True  if OPEN     — connect_ex() returned 0.
    Returns False if CLOSED   — non-zero errno (connection refused).
    Returns False if FILTERED — socket.timeout raised (no response).
    """
    # socket.socket() asks the OS to allocate a socket resource.
    # AF_INET = IPv4. SOCK_STREAM = TCP. Together: a TCP socket over IPv4.
    # Every web browser, SSH client, and FTP tool uses this same combination.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # settimeout BEFORE connect_ex.
    # calleing it after has no effect on a connection attempt already in flight.
    # Without it: filtered ports block for 20-120 seconds (kernel default).
    # That is not a timeout more like a snooze!
    sock.settimeout(timeout)

    # connect_ex() returns 0 on success, an errno integer on failure.
    # Unlike connect(), it does not raise an exception for refused connections.
    result = sock.connect_ex((target, port))

    # Release the file descriptor immediately.
    # Every open socket holds an OS resource. The default limit is 1024.
    # With 50 threads in flight, unclosed sockets add up faster than you think.
    sock.close()

    # result == 0 evaluates to True (open) or False (not open).
    # Non-zero errno codes — 111 (ECONNREFUSED), 113 (EHOSTUNREACH) etc —
    # all evaluate to False. We do not need to distinguish between them here.
    return result == 0

    # HINT: What happens if connect_ex raises socket.timeout?
    # That is the FILTERED case — the OS waited and got nothing back.
    # Currently: the exception propagates. The scan crashes on filtered ports.
    # socket.timeout should be caught and return False, not a traceback.

    # HINT: What if the target is not reachable at all? VM not running?
    # connect_ex raises OSError.

    # HINT: If you add try/except, sock.close() needs to move to a finally block.
    # Otherwise a caught exception skips the close and leaks the descriptor.


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 3 OF 4: grab_banner
#
# Connects to a port that is already confirmed open and reads whatever
# the service sends first. Many services announce themselves unprompted —
# FTP sends a 220 response, SSH sends a version string.
# Some services send nothing. That is fine, empty string is a valid result.
#
# This function has one job: return a string. That is all.
# ─────────────────────────────────────────────────────────────────────────────


def grab_banner(target: str, port: int, timeout: float = 0.5) -> str:
    """
    Connect to an open port and read the service banner.

    Returns the decoded, stripped banner string.
    Returns empty string if no banner received.

    The 'banner' key must always be present in JSON output — even when empty.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    # connect() this time, not connect_ex().
    # We know the port is open — check_port confirmed it.
    # connect() raises an exception on failure, which is fine here.
    # Any unexpected failure will be caught below.
    sock.connect((target, port))

    # The service has accepted the connection but may not have written
    # its banner to the socket buffer yet. Give it a moment.
    # Remove this sleep and banners will be empty. Consistently.
    # You have been warned.
    time.sleep(0.1)

    # recv(1024) reads up to 1024 bytes. Most banners are much shorter.
    # decode('utf-8', errors='ignore') — some services include non-UTF-8 bytes.
    # errors='ignore' discards them silently rather than raising UnicodeDecodeError.
    # .strip() removes the \r\n that FTP and friends "helpfully" append.
    banner = sock.recv(1024)
    sock.close()

    return banner.decode("utf-8", errors="ignore").strip()

    # HINT: What if connect() fails? What if recv() times out?
    # What if the service accepts the connection and immediately resets it?
    # Any of these raise exceptions.

    # HINT: Same note about finally and sock.close() as in check_port.
    # An exception between connect() and sock.close() leaks the descriptor.


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
#
# Separated from main() because it can be tested independently,
# and because main() already has enough to do.
# ─────────────────────────────────────────────────────────────────────────────


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments and return the namespace."""

    parser = argparse.ArgumentParser(
        description="TCP connect scanner with banner grabbing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 gateway_scanner.py 172.16.19.101\n"
            "  python3 gateway_scanner.py 172.16.19.101 --ports 1-1024\n"
            "  python3 gateway_scanner.py 172.16.19.101 --ports 21,22,80\n"
            "  python3 gateway_scanner.py 172.16.19.101 "
            "--ports 1-65535 --threads 200\n"
        ),
    )

    # Positional argument — required, no flag needed.
    parser.add_argument(
        "target",
        help="Target IP address.",
    )

    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Port range or comma list. Default: 1-1024",
    )

    # type=float is not optional here.
    # Without it: args.timeout is the STRING '0.5'.
    # sock.settimeout('0.5') raises TypeError.
    # The error message points at settimeout, not argparse.
    # Debugging that for the first time is a formative experience.
    # type=float spares you that particular formation.
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout per port in seconds. Default: 0.5",
    )

    parser.add_argument(
        "--output",
        default="gateway_results.json",
        help="Output JSON file path. Default: gateway_results.json",
    )

    # Same story as timeout — type=int required.
    # ThreadPoolExecutor(max_workers='50') is not a compliment.
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Thread pool size. Default: 50",
    )

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 4 OF 4: main
#
# The coordinator. Does not scan. Does not grab banners. Does not parse ports.
# Delegates everything to the other three functions and wires the results together.
#
# ThreadPoolExecutor must be in here and not inside check_port because
# concurrency is all about coordination. check_port has only 1 job to do and by
# adding thread management to it would give it two jobs.
# Single responsibility is not just a good idea. It is why the tests work.
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    """
    Coordinate the scanner. Parse arguments, scan, write JSON.

    JSON output contract — five rules tested by the auto-grader:
      1. "target"     matches CLI argument exactly
      2. "open_ports" is always a list (even when empty)
      3. "port"       is an integer, not a string
      4. "banner"     key is always present (empty string if no banner)
      5. sorted ascending by port number
    """
    args = parse_arguments()

    # parse_port_input() on the happy path returns a sorted list of integers.
    # On the unhappy path (bad input), it raises ValueError.
    # For now: we let that propagate. The traceback is educational.
    # HINT: A try/except around this line that prints to sys.stderr and calls
    # sys.exit(1) would make the error message considerably less alarming.
    ports = parse_port_input(args.ports)

    # This list will hold the results. Open ports only.
    # Closed and filtered ports are not interesting — they stay quiet.
    open_ports: list[dict] = []

    # ThreadPoolExecutor manages a pool of worker threads.
    # max_workers controls how many run simultaneously.
    # Each worker calls check_port() once and returns a bool.
    # The executor dispatches, collects, and cleans up. We just submit and read.
    with ThreadPoolExecutor(max_workers=args.threads) as executor:

        # Submit all port checks simultaneously.
        # futures is a dict: {Future: port_number}
        # We need the port number later when future.result() returns True.
        # The dict comprehension is the clean way to keep them paired.
        futures: dict = {
            executor.submit(check_port, args.target, p, args.timeout): p for p in ports
        }

        # Collect results. This iterates in submission order.
        # future.result() blocks until that specific Future is done.
        # Thread completion order is non-deterministic — hence the sort later.
        for future, port in futures.items():
            if future.result():  # True = port is open
                banner = grab_banner(args.target, port, args.timeout)

                # Port stored as int (not str). Rule 3 depends on this.
                # Banner stored even when empty. Rule 4 depends on this.
                open_ports.append({"port": port, "banner": banner})

    # Sort by port number — ascending.
    # Thread pool completed in some order. That order is not port order.
    # This line is the difference between a deterministic artefact and a surprise.
    open_ports.sort(key=lambda x: x["port"])

    # Build the output structure.
    # Rule 1: args.target, verbatim — do not resolve, reformat, or improve it.
    # Rule 2: open_ports is already a list. If nothing was found, it is empty. Fine.
    output = {
        "target": args.target,
        "open_ports": open_ports,
    }

    # stdout: the auto-grader captures this and parses it as JSON.
    # If you print anything else to stdout, the JSON parse fails.
    # Status messages go to stderr. Data goes to stdout. Not negotiable.
    print(json.dumps(output, indent=2))

    # File: the committed artefact — the thing that goes in your repository.
    Path(args.output).write_text(json.dumps(output, indent=2))

    # Summary to stderr. Informative, does not corrupt stdout.
    print(
        f"[*] {len(open_ports)} open port(s) found on {args.target}",
        file=sys.stderr,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point guard.
#
# When Python runs this file directly: __name__ is '__main__', main() runs.
# When anything imports this module (REPL, test suite,  main() does NOT run.
#
# Without this every import triggers parse_arguments(), which calls
# argparse.parse_args(), which finds no CLI arguments, which either
# errors or scans something you did not ask it to scan.
# This is a must-have for any Python file that is intended to be both imported and run directly.
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
