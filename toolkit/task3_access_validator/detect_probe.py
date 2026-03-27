import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def load_attempts(path: str) -> list[dict]:
    """Read attempts.csv → list of dicts with parsed timestamps.
    Returns only FAIL rows — success records are not relevant to detection."""
    p = Path(path)
    if not p.exists():
        print(f"[!] Attempt log not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, "r") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["timestamp"] = datetime.fromisoformat(r["timestamp"])
    return [r for r in rows if r["result"] == "FAIL"]


def detect_guessing(
    attempts: list[dict], threshold: int = 5, window_sec: int = 60
) -> list[dict]:
    """Per (user, source): count failures in a sliding window.
    Returns a list of alert dicts."""
    alerts = []
    groups = defaultdict(list)

    for a in attempts:
        groups[(a["user"], a["source"])].append(a)

    for key, events in groups.items():
        events.sort(key=lambda e: e["timestamp"])
        for event in events:
            window_start = event["timestamp"] - timedelta(seconds=window_sec)
            count = sum(
                1
                for e in events
                if window_start <= e["timestamp"] <= event["timestamp"]
            )
            if count >= threshold:
                alerts.append(
                    {
                        "type": "GUESSING",
                        "user": key[0],
                        "source": key[1],
                        "count": count,
                        "at": event["timestamp"],
                    }
                )
                break  # one alert per (user, source) group

    return alerts


def detect_spraying(
    attempts: list[dict], threshold: int = 3, window_sec: int = 60
) -> list[dict]:
    """Per source: count distinct failed users in a sliding window.
    Returns a list of alert dicts."""
    alerts = []
    groups = defaultdict(list)

    for a in attempts:
        groups[a["source"]].append(a)

    for source, events in groups.items():
        events.sort(key=lambda e: e["timestamp"])
        for event in events:
            window_start = event["timestamp"] - timedelta(seconds=window_sec)
            window_events = [
                e
                for e in events
                if window_start <= e["timestamp"] <= event["timestamp"]
            ]
            distinct_users = len(set(e["user"] for e in window_events))
            if distinct_users >= threshold:
                alerts.append(
                    {
                        "type": "SPRAYING",
                        "source": source,
                        "distinct_users": distinct_users,
                        "at": event["timestamp"],
                    }
                )
                break

    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect credential-guessing behaviour in a brute-force attempt log."
    )
    parser.add_argument(
        "--log",
        default="attempts.csv",
        help="Path to attempt log CSV (default: attempts.csv)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failure count to trigger guessing alert (default: 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Detection window in seconds (default: 60)",
    )
    args = parser.parse_args()

    attempts = load_attempts(args.log)

    guessing_alerts = detect_guessing(
        attempts, threshold=args.threshold, window_sec=args.window
    )
    spraying_alerts = detect_spraying(attempts, threshold=3, window_sec=args.window)

    if not guessing_alerts and not spraying_alerts:
        print("[*] No anomalous patterns detected within configured thresholds.")
        return

    for alert in guessing_alerts:
        print(
            f"[ALERT] GUESSING: {alert['count']} failed attempts for user "
            f"'{alert['user']}' from {alert['source']} "
            f"in {args.window}s window "
            f"(first detected at {alert['at'].strftime('%H:%M:%S')})"
        )

    for alert in spraying_alerts:
        print(
            f"[ALERT] SPRAYING: {alert['distinct_users']} distinct users targeted "
            f"from {alert['source']} "
            f"in {args.window}s window "
            f"(first detected at {alert['at'].strftime('%H:%M:%S')})"
        )


if __name__ == "__main__":
    main()
