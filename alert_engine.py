import json
from pathlib import Path
from detections.cloudtrail_detector import detect_failed_logins
from detections.iam_detector import detect_admin_policy_attachments

# Project paths
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample_logs" / "cloudtrail_events.json"
OUTPUT_FILE = BASE_DIR / "output" / "alerts.json"

def generate_alerts(events):
    alerts = []
    # Run Rule 1: Failed Login Detection
    login_alerts = detect_failed_logins(events)
    for alert in login_alerts:
        alerts.append({
            "rule_id": "CS-001",
            "title": "Multiple Failed AWS Logins",
            "severity": "MEDIUM",
            "user": alert["username"],
            "source_ip": alert["ip_address"],
            "timestamp": alert["last_seen"].isoformat(),
            "details": {
                "failed_attempts": alert["attempts"],
                "first_seen": alert["first_seen"].isoformat()
            }
        })
    # Run Rule 2: IAM Privilege Change Detection
    iam_alerts = detect_admin_policy_attachments(events)
    for alert in iam_alerts:
        alerts.append({
            "rule_id": "CS-002",
            "title": "AdministratorAccess Policy Attached",
            "severity": "HIGH",
            "user": alert["target_user"],
            "source_ip": alert["source_ip"],
            "timestamp": alert["event_time"],
            "details": {
                "actor": alert["actor"]
            }
        })
    return alerts

def main():
    # Load simulated CloudTrail events
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = generate_alerts(data["Records"])

    # Create output folder if it doesn't exist
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Save the structured alert report
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("\n=== CLOUD SENTINEL SECURITY REPORT ===")
    print(f"Total Alerts: {len(alerts)}")

    for alert in alerts:
        print(f"\n[{alert['severity']}] {alert['title']}")
        print(f"Rule: {alert['rule_id']}")
        print(f"User: {alert['user']}")
        print(f"Source IP: {alert['source_ip']}")

    print(f"\nReport saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()