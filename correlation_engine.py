import json
import hashlib
from datetime import datetime, timedelta, timezone
from alert_engine import generate_alerts, LOG_FILE, BASE_DIR

# Correlate events occurring within 10 minutes
CORRELATION_WINDOW = timedelta(minutes=10)

def parse_timestamp(value):
    """Convert CloudTrail timestamps into UTC datetimes."""
    timestamp = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")

    return timestamp.astimezone(timezone.utc)

def correlate_alerts(alerts):
    correlations = []

    # Separate alerts by detection rule
    login_alerts = [
        alert for alert in alerts
        if alert["rule_id"] == "CS-001"
    ]

    iam_alerts = [
        alert for alert in alerts
        if alert["rule_id"] == "CS-002"
    ]

    # Compare failed logins with IAM policy changes
    for login in login_alerts:
        for iam in iam_alerts:

            # Both alerts must involve the same target user
            if login["user"] != iam["user"]:
                continue

            login_time = parse_timestamp(login["timestamp"])
            iam_time = parse_timestamp(iam["timestamp"])

            time_difference = iam_time - login_time

            # IAM change must follow the login alert
            # and occur within our 10-minute window
            if not (
                timedelta(0)
                <= time_difference
                <= CORRELATION_WINDOW
            ):
                continue

            # Create a reproducible correlation identifier
            fingerprint = (
                f"{login['user']}|"
                f"{login['timestamp']}|"
                f"{iam['timestamp']}|"
                f"{login['source_ip']}|"
                f"{iam['source_ip']}"
            )

            correlation_hash = hashlib.sha256(
                fingerprint.encode("utf-8")
            ).hexdigest()[:12].upper()

            # Record the relationship between both alerts
            correlations.append({
                "correlation_id": f"CORR-{correlation_hash}",
                "rule_id": "CS-CORR-001",
                "priority": "HIGH",
                "status": "NEEDS_REVIEW",
                "target_user": login["user"],
                "related_rule_ids": ["CS-001", "CS-002"],
                "login_timestamp": login["timestamp"],
                "iam_timestamp": iam["timestamp"],
                "minutes_between_events": round(
                    time_difference.total_seconds() / 60, 2
                ),
                "failed_login_source_ip": login["source_ip"],
                "iam_change_source_ip": iam["source_ip"],
                "iam_actor": iam.get("details", {}).get(
                    "actor", "Unknown"
                ),
                "analysis": (
                    "Failed logins were followed by an "
                    "administrator policy attachment to the "
                    "same user. This is a temporal correlation, "
                    "not confirmation of account compromise."
                )
            })

    return correlations

def main():
    # Load our simulated AWS CloudTrail logs
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Run both existing detection rules
    alerts = generate_alerts(data["Records"])

    # Identify potentially related alerts
    correlations = correlate_alerts(alerts)

    # Save correlations to a JSON report
    output_file = BASE_DIR / "output" / "correlations.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(correlations, file, indent=4)

    print("\n=== CLOUD SENTINEL ALERT CORRELATION ===")
    print(f"Potential correlations: {len(correlations)}")

    for correlation in correlations:
        print(f"\n[REVIEW] {correlation['correlation_id']}")
        print(f"Target user: {correlation['target_user']}")
        print(
            "Time between events: "
            f"{correlation['minutes_between_events']} minutes"
        )
        print(
            "Login source IP: "
            f"{correlation['failed_login_source_ip']}"
        )
        print(
            "IAM source IP: "
            f"{correlation['iam_change_source_ip']}"
        )
        print("Status: Investigation required")

    print(f"\nReport saved to: {output_file}")

if __name__ == "__main__":
    main()