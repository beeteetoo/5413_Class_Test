from datetime import datetime, timedelta

# Simulated timestamps — seven failures for one account, within 3 seconds
events = [
    datetime(2024, 11, 14, 9, 0, 1),
    datetime(2024, 11, 14, 9, 0, 1),
    datetime(2024, 11, 14, 9, 0, 2),
    datetime(2024, 11, 14, 9, 0, 2),
    datetime(2024, 11, 14, 9, 0, 3),
    datetime(2024, 11, 14, 9, 0, 3),
    datetime(2024, 11, 14, 9, 0, 4),
    # Long gap — new session?
    datetime(2024, 11, 14, 9, 5, 30),
    datetime(2024, 11, 14, 9, 5, 31),
]

window_sec = 60
threshold = 5

for i, event in enumerate(events):
    window_start = event - timedelta(seconds=window_sec)
    count = sum(1 for e in events if window_start <= e <= event)
    status = "ALERT" if count >= threshold else "ok"
    print(
        f"Event {i+1} at {event.strftime('%H:%M:%S')} — "
        f"{count} in window — {status}"
    )
