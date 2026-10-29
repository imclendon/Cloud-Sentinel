from datetime import datetime, timedelta, timezone
from pathlib import Path
from incident_reporter import render_correlation_markdown

OUTPUT_DIR = Path("output/demo_correlation_reports")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

START_TIME = datetime(
    2026, 10, 21, 14, 0, tzinfo=timezone.utc
)

def timestamp(minutes):
    return (
        START_TIME + timedelta(minutes=minutes)
    ).isoformat().replace("+00:00", "Z")

def create_demo_correlation(priority, minutes):
    return {
        "correlation_id": f"DEMO-{priority}",
        "rule_id": "CS-CORR-001",
        "priority": priority,
        "status": "DEMO_ONLY",
        "target_user": "demo-user",
        "related_rule_ids": ["CS-001", "CS-002"],
        "minutes_between_events": minutes,
        "failed_login_source_ip": "203.0.113.50",
        "iam_change_source_ip": "192.0.2.44",
        "iam_actor": "demo-admin",
        "login_timestamp": timestamp(0),
        "iam_timestamp": timestamp(minutes),
        "analysis": (
            "Synthetic demonstration of correlation report "
            "formatting. The priority was assigned for display "
            "testing, not calculated from security risk."
        )
    }

def main():
    scenarios = [
        ("HIGH", 2),
        ("MEDIUM", 5),
        ("LOW", 9)
    ]
    for priority, minutes in scenarios:
        correlation = create_demo_correlation(
            priority, minutes
        )
        report = (
            "> **DEMO ONLY:** This is not a real "
            "security finding or risk assessment.\n\n"
            + render_correlation_markdown(correlation)
        )
        output_file = OUTPUT_DIR / f"DEMO-{priority}.md"

        output_file.write_text(
            report,
            encoding="utf-8"
        )
        print(f"[{priority}] Generated {output_file}")

    print("\nAll demo reports generated successfully.")

if __name__ == "__main__":
    main()