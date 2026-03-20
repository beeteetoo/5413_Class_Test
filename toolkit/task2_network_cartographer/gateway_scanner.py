import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP connect scanner with banner grabbing."
    )
    parser.add_argument("target", help="Target IP address.")
    parser.add_argument(
        "--ports", default="1-1024", help="Port range or list. Default: 1-1024"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout per port in seconds. Default: 0.5",
    )
    parser.add_argument(
        "--output", default="gateway_results.json", help="Output JSON file path."
    )
    parser.add_argument(
        "--threads", type=int, default=50, help="Thread pool size. Default: 50"
    )
    return parser.parse_args()


def parse_port_input(port_str: str) -> list[int]:
    """
    Convert a port specification string into a sorted, deduplicated list.

    Accepts:
        '80'          → [80]
        '1-1024'      → [1, 2, ..., 1024]
        '21,22,80'    → [21, 22, 80]
        '1-3,8,10-12' → [1, 2, 3, 8, 10, 11, 12]

    Raises ValueError if the input is malformed or contains invalid port numbers.
    """

    ports = []  # type: list[int]

    for part in port_str.split(","):
        part.strip()

        if "-" in part:
            pieces = part.split("-", 1)
            start, end = [int(x.strip()) for x in pieces]
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))


def check_port(target: str, port: int, timeout: float = 0.5) -> bool:

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        return result == 0

    except socket.timeout:
        return False
    finally:
        sock.close()


def grab_banner(target: str, port: int, timeout: float = 0.5) -> str:
    """Connect to an open port. Return service banner or empty string."""
    banner = ""
    # Using 'with' or a try/finally ensures the socket is closed
    # and doesn't leak file descriptors.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((target, port))
            # Some services require a small delay to push the banner
            time.sleep(0.5)
            # recv will also respect the timeout set above
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except (socket.timeout, ConnectionRefusedError, OSError):
            # If it times out or the connection is refused, we just return the empty string
            pass

    return banner


def main() -> None:
    args = parse_arguments()

    # Convert port string — ValueError if invalid.
    # Your job: catch it here, print to stderr, sys.exit(1).
    ports = parse_port_input(args.ports)

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_port, args.target, p, args.timeout): p for p in ports
        }
        for future, port in futures.items():
            if future.result():
                banner = grab_banner(args.target, port, args.timeout)
                open_ports.append({"port": port, "banner": banner})

    # Sort — thread completion order is non-deterministic
    open_ports.sort(key=lambda x: x["port"])

    # Build the output structure.
    # Your job: make sure this matches the JSON contract exactly.
    output = {
        "target": args.target,
        "open_ports": open_ports,
    }

    # Write to stdout — test suite captures and parses this as JSON
    print(json.dumps(output, indent=2))

    # Write to file — the committed artefact
    Path(args.output).write_text(json.dumps(output, indent=2))

    print(f"[*] {len(open_ports)} port(s) found.", file=sys.stderr)


if __name__ == "__main__":
    main()
