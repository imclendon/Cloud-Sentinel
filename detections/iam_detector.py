import json
from pathlib import Path

# AWS managed policy providing administrator privileges
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"

LOG_FILE = (
    Path(__file__).resolve().parent.parent
    / "sample_logs"
    / "cloudtrail_events.json"
)

def detect_admin_policy_attachments(events):
    alerts = []

    for event in events:

        # Check that the event represents an IAM policy attachment
        if event.get("eventSource") != "iam.amazonaws.com":
            continue

        if event.get("eventName") != "AttachUserPolicy":
            continue

        # Ignore failed API requests
        if event.get("errorCode"):
            continue

        # Examine the policy being attached
        parameters = event.get("requestParameters") or {}

        if parameters.get("policyArn") != ADMIN_POLICY:
            continue

        # Identify who performed the action
        identity = event.get("userIdentity") or {}

        actor = (
            identity.get("arn")
            or identity.get("userName")
            or "Unknown"
        )

        alerts.append({
            "severity": "HIGH",
            "actor": actor,
            "target_user": parameters.get("userName", "Unknown"),
            "source_ip": event.get("sourceIPAddress", "Unknown"),
            "event_time": event.get("eventTime", "Unknown")
        })

    return alerts

def main():
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = detect_admin_policy_attachments(data["Records"])

    if not alerts:
        print("No administrator policy attachments detected.")
        return

    for alert in alerts:
        print("\n[HIGH SEVERITY ALERT] AdministratorAccess Attached")
        print(f"Actor: {alert['actor']}")
        print(f"Target user: {alert['target_user']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Timestamp: {alert['event_time']}")
        print("Status: Investigate privilege change")

if __name__ == "__main__":
    main()