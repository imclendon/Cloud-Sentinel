import json
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Detection rule configuration
THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)

# Location of our sample CloudTrail logs
LOG_FILE = (
    Path(__file__).resolve().parent.parent
    / "sample_logs"
    / "cloudtrail_events.json"
)

def detect_failed_logins(events):
    failures = defaultdict(list)

    # Step 1: Find failed AWS console logins
    for event in events:
        if event.get("eventName") != "ConsoleLogin":
            continue

        if event.get("eventSource") != "signin.amazonaws.com":
            continue

        result = (event.get("responseElements") or {}).get("ConsoleLogin")

        if result != "Failure":
            continue

        # Step 2: Extract important information
        username = (event.get("userIdentity") or {}).get(
            "userName", "unknown"
        )
        ip_address = event.get("sourceIPAddress", "unknown")

        timestamp = datetime.fromisoformat(
            event["eventTime"].replace("Z", "+00:00")
        )

        # Group failures by username and IP address
        failures[(username, ip_address)].append(timestamp)
        
    alerts = []

    # Step 3: Check each user's failed login activity
    for (username, ip_address), timestamps in failures.items():
        timestamps.sort()
        window = deque()

        for timestamp in timestamps:
            window.append(timestamp)

            # Remove events older than five minutes
            while timestamp - window[0] > TIME_WINDOW:
                window.popleft()

            # Step 4: Trigger an alert at the threshold
            if len(window) >= THRESHOLD:
                alerts.append({
                    "username": username,
                    "ip_address": ip_address,
                    "attempts": len(window),
                    "first_seen": window[0],
                    "last_seen": timestamp
                })
                break

    return alerts

def main():
    # Load our JSON file
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = detect_failed_logins(data["Records"])

    if not alerts:
        print("No suspicious login activity detected.")
        return

    for alert in alerts:
        print("\n[SECURITY ALERT] Multiple failed AWS logins")
        print(f"User: {alert['username']}")
        print(f"Source IP: {alert['ip_address']}")
        print(f"Failed attempts: {alert['attempts']}")
        print(f"First attempt: {alert['first_seen']}")
        print(f"Last attempt: {alert['last_seen']}")
        print("Status: Investigation required")

if __name__ == "__main__":
    main()
