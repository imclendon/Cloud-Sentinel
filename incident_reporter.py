
import json
import hashlib
from alert_engine import generate_alerts, LOG_FILE, BASE_DIR
from correlation_engine import correlate_alerts

# MITRE ATT&CK mappings and analyst investigation guidance
RULE_GUIDANCE = {
    "CS-001": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "steps": [
            "Review surrounding login activity for this account.",
            "Check whether a successful login followed the failures.",
            "Determine whether the source IP is recognized.",
            "Confirm whether the activity was authorized."
        ]
    },
    "CS-002": {
        "technique_id": "T1098.003",
        "technique_name": "Additional Cloud Roles",
        "url": "https://attack.mitre.org/techniques/T1098/003/",
        "steps": [
            "Identify who attached the administrator policy.",
            "Check whether the permission change was approved.",
            "Review surrounding CloudTrail activity.",
            "Escalate unauthorized changes for remediation."
        ]
    }
}

def build_incident(alert):
    rule_id = alert["rule_id"]
    guidance = RULE_GUIDANCE[rule_id]

    # Generate a repeatable ID from the alert contents
    fingerprint = json.dumps(alert, sort_keys=True)
    incident_hash = hashlib.sha256(
        fingerprint.encode("utf-8")
    ).hexdigest()[:12].upper()

    return {
        "incident_id": f"INC-{incident_hash}",
        "status": "OPEN",
        "disposition": "UNDETERMINED",
        "severity": alert["severity"],
        "title": alert["title"],
        "rule_id": rule_id,
        "event_time": alert["timestamp"],
        "user": alert["user"],
        "source_ip": alert["source_ip"],
        "mitre_attack": {
            "technique_id": guidance["technique_id"],
            "technique_name": guidance["technique_name"],
            "url": guidance["url"]
        },
        "evidence": alert["details"],
        "investigation_steps": guidance["steps"]
    }

def find_related_correlations(incident, correlations):
    """Find correlations involving this exact incident."""

    if incident["rule_id"] == "CS-001":
        timestamp_field = "login_timestamp"
        ip_field = "failed_login_source_ip"

    elif incident["rule_id"] == "CS-002":
        timestamp_field = "iam_timestamp"
        ip_field = "iam_change_source_ip"

    else:
        return []

    return [
        correlation
        for correlation in correlations
        if (
            correlation["target_user"] == incident["user"]
            and correlation[timestamp_field] == incident["event_time"]
            and correlation[ip_field] == incident["source_ip"]
        )
    ]

def render_markdown(incident, correlations=None):

    # Assign colors to severity levels
    severity_colors = {
        "HIGH": "red",
        "MEDIUM": "orange",
        "LOW": "yellow"
    }

    severity = incident["severity"].upper()
    badge_color = severity_colors.get(severity, "lightgrey")

    # Create a color-coded severity badge using Shields.io
    severity_badge = (
        f"![{severity}]"
        f"(https://img.shields.io/badge/-{severity}-{badge_color})"
    )

    # Convert recorded evidence into Markdown
    evidence_lines = "\n".join(
        f"- **{key}:** {value}"
        for key, value in incident["evidence"].items()
    )

    # Generate a checklist for the analyst
    checklist = "\n".join(
        f"- [ ] {step}"
        for step in incident["investigation_steps"]
    )

    technique = incident["mitre_attack"]

    # Find related security activity
    related = find_related_correlations(
        incident,
        correlations or []
    )

    if related:
        related_activity = "\n".join(
            f"- **[{c['correlation_id']}]"
            f"(../correlation_reports/{c['correlation_id']}.md)** "
            f"— {c['minutes_between_events']} minutes apart; "
            f"linked rules: {', '.join(c['related_rule_ids'])}; "
            f"status: {c['status']}."
            for c in related
        )
    else:
        related_activity = (
            "No matching correlated activity detected "
            "by the current correlation rules."
        )

    # Generate formatted Markdown report
    return f"""# {incident['incident_id']}: {incident['title']}

**Severity:** {severity_badge}  
**Status:** {incident['status']}  
**Disposition:** {incident['disposition']}  
**Detection Rule:** {incident['rule_id']}

---

## Event Information

- **Event Time (UTC):** {incident['event_time']}
- **User:** {incident['user']}
- **Source IP:** {incident['source_ip']}

## MITRE ATT&CK Mapping

Potential technique:  
[{technique['technique_id']} - {technique['technique_name']}]({technique['url']})

## Evidence

{evidence_lines}
{related_activity}

## Investigation Checklist

{checklist}

## Analyst Assessment

Pending investigation. This finding was automatically generated
from simulated security logs. Malicious activity has not been confirmed.
"""

def render_correlation_markdown(correlation):
    """Generate a consolidated investigation report."""

    # Assign colors based on correlation priority
    priority_colors = {
        "HIGH": "red",
        "MEDIUM": "orange",
        "LOW": "yellow"
    }

    priority = correlation["priority"].upper()
    badge_color = priority_colors.get(priority, "lightgrey")

    # Generate color-coded priority badge
    priority_badge = (
        f"![{priority}]"
        f"(https://img.shields.io/badge/-{priority}-{badge_color})"
    )
    return f"""# {correlation['correlation_id']}: Correlated Security Activity

**Priority:** {priority_badge}  
**Status:** {correlation['status']}  
**Target User:** {correlation['target_user']}  
**Correlation Rule:** {correlation['rule_id']}

---

## Security Event Timeline

### Event 1: Suspicious Authentication

- **Timestamp:** {correlation['login_timestamp']}
- **Detection Rule:** CS-001
- **Source IP:** {correlation['failed_login_source_ip']}
- **Activity:** Multiple failed AWS console login attempts.

### Event 2: IAM Privilege Change

- **Timestamp:** {correlation['iam_timestamp']}
- **Detection Rule:** CS-002
- **Actor:** {correlation['iam_actor']}
- **Source IP:** {correlation['iam_change_source_ip']}
- **Activity:** AdministratorAccess policy attached to the target user.

## Correlation Analysis

**Time Between Events:** {correlation['minutes_between_events']} minutes

{correlation['analysis']}

## Investigation Checklist

- [ ] Review authentication events surrounding both timestamps.
- [ ] Determine whether a successful login followed the failures.
- [ ] Verify that the IAM permission change was authorized.
- [ ] Investigate the IAM actor and source IP address.
- [ ] Review additional CloudTrail events for suspicious activity.
- [ ] Document the evidence and final investigation disposition.

## Analyst Assessment

**Status: Pending Investigation**

These simulated events are correlated by target account and
event timing. The correlation does not establish that the
same actor performed both actions or that an account was compromised.
"""

def main():
    # Read CloudTrail events and run existing detection rules
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = generate_alerts(data["Records"])
    incidents = [build_incident(alert) for alert in alerts]
    correlations = correlate_alerts(alerts)

    # Create report directories
    output_dir = BASE_DIR / "output"
    reports_dir = output_dir / "incident_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    correlation_reports_dir = output_dir / "correlation_reports"
    correlation_reports_dir.mkdir(parents=True, exist_ok=True)

    # Export structured JSON cases
    json_path = output_dir / "incidents.json"

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4)

    # Export individual Markdown reports
    for incident in incidents:
        report_path = (
            reports_dir / f"{incident['incident_id']}.md"
        )

        report_path.write_text(
            render_markdown(incident, correlations),
            encoding="utf-8"
        )

    # Export correlations as JSON
    correlation_json = output_dir / "correlations.json"

    with open(correlation_json, "w", encoding="utf-8") as file:
        json.dump(correlations, file, indent=4)

    # Export consolidated Markdown correlation reports
    for correlation in correlations:
        report_path = (
            correlation_reports_dir
            / f"{correlation['correlation_id']}.md"
        )

        report_path.write_text(
            render_correlation_markdown(correlation),
            encoding="utf-8"
        )

    print(f"Correlated investigations: {len(correlations)}")

    print("\n=== CLOUD SENTINEL INCIDENT REPORTS ===")
    print(f"Investigations generated: {len(incidents)}")

    for incident in incidents:
        print(
            f"[{incident['severity']}] "
            f"{incident['incident_id']} - {incident['title']}"
        )

    print(f"\nReports saved to: {reports_dir}")

if __name__ == "__main__":
    main()