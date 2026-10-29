# Cloud Sentinel

### AWS Threat Detection, Alert Correlation & Incident Response Automation

Cloud Sentinel is a Python-based cybersecurity project designed to simulate real-world Security Operations Center (SOC) workflows using AWS CloudTrail event data.

This project automates suspicious activity detection, security alert correlation, incident reporting, and preliminary investigation workflows. I'm developing it as a hands-on cloud security portfolio project, with future expansion into AWS infrastructure security and GRC compliance assessments.

**Project Status:** Active Development | Local Security Monitoring & Incident Response

## Project Objectives

- Detect suspicious authentication and IAM activity within AWS CloudTrail logs.
- Correlate security events using account identifiers and event timestamps.
- Generate structured alerts with severity classifications.
- Automate incident reports with evidence and investigation checklists.
- Map security findings to MITRE ATT&CK techniques.
- Expand into AWS infrastructure monitoring, security assessments, and compliance reporting.

## Current Features

### 1. AWS CloudTrail Threat Detection

**Detection Rule CS-001 — Suspicious Login Activity**

- Analyzes CloudTrail `ConsoleLogin` events.
- Detects three or more failed login attempts within a five-minute window.
- Groups activity by username and source IP address.
- Generates a MEDIUM-severity alert for investigation.

**Detection Rule CS-002 — IAM Privilege Changes**

- Monitors `AttachUserPolicy` events.
- Identifies attachments of the AWS-managed `AdministratorAccess` policy.
- Extracts the actor, target user, IP address, and event timestamp.
- Generates a HIGH-severity alert when the specified privilege change is detected.

### 2. Centralized Security Alert Engine

**File:** `alert_engine.py`

- Executes multiple detection rules against simulated CloudTrail events.
- Normalizes findings into a consistent alert format.
- Assigns unique detection rule identifiers and severity levels.
- Exports structured security alerts to `output/alerts.json`.

### 3. Automated Incident Reporting

**File:** `incident_reporter.py`

- Automatically generates incident reports from detected security alerts.
- Assigns reproducible incident IDs and initial investigation statuses.
- Includes relevant evidence, MITRE ATT&CK mappings, and investigation checklists.
- Produces structured JSON reports and formatted Markdown investigation documents.
- Displays color-coded severity badges for HIGH, MEDIUM, and LOW levels.

### 4. Security Alert Correlation

**File:** `correlation_engine.py`

- Identifies potentially related security alerts affecting the same account.
- Correlates failed login activity followed by IAM privilege changes within a configurable ten-minute window.
- Generates correlation identifiers and records relationships between findings.
- Exports correlated findings to `output/correlations.json`.
- Supports consolidated Markdown investigation reports linked from individual incidents.

**Current limitation:** The implemented correlation rule assigns HIGH priority to matching findings. Additional risk-based priority classifications are planned.

### 5. Correlation Priority Demonstration

**File:** `demo_correlation_priorities.py`

A separate demonstration generates HIGH, MEDIUM, and LOW reports to validate Markdown severity badge formatting.

These priorities are illustrative and are not calculated from real security risk.

### 6. Automated Testing

The project uses Python's built-in `unittest` framework.

Current verified coverage includes:

- Failed-login detection thresholds and time windows.
- IAM policy attachment detection.
- Failed API requests and non-administrative IAM activity.
- Correlation matching by target user.
- Event ordering and correlation time-window boundaries.
- Reproducible correlation identifiers.

**Current test results:** 14 passing unit tests covering detection and correlation logic.

Dedicated automated tests for the new incident-report integration remain planned.

## Technologies

| Technology | Purpose |
|---|---|
| Python | Security automation and detection logic |
| JSON | CloudTrail event data and generated findings |
| AWS CloudTrail | Cloud activity event format |
| AWS IAM | Identity and privilege-change analysis |
| MITRE ATT&CK | Security technique classification |
| Markdown | Incident and investigation reporting |
| Git & GitHub | Version control and documentation |
| Terraform | Planned AWS infrastructure deployment |
| NIST CSF 2.0 / CIS | Planned compliance and risk assessments |

## Project Structure

```text
cloud-sentinel/
├── detections/
│   ├── __init__.py
│   ├── cloudtrail_detector.py
│   └── iam_detector.py
├── sample_logs/
│   └── cloudtrail_events.json
├── tests/
│   ├── test_cloudtrail_detector.py
│   ├── test_iam_detector.py
│   └── test_correlation_engine.py
├── alert_engine.py
├── correlation_engine.py
├── incident_reporter.py
├── demo_correlation_priorities.py
├── README.md
└── .gitignore
```

Generated reports are stored locally in the `output/` directory, which is excluded from Git tracking.

## Getting Started

### Requirements

- Python 3
- Git
- VS Code or another code editor

The current local detection and reporting tools use the Python standard library and do not require AWS credentials.

### Running Cloud Sentinel

Run the centralized security alert engine:

```bash
python3 alert_engine.py
```

Generate individual incident and correlation reports:

```bash
python3 incident_reporter.py
```

Run the standalone correlation engine:

```bash
python3 correlation_engine.py
```

Generate severity badge demonstration reports:

```bash
python3 demo_correlation_priorities.py
```

Run automated tests:

```bash
python3 -m unittest discover -s tests -v
```

### Generated Reports

The application generates the following files locally:

```text
output/
├── alerts.json
├── incidents.json
├── correlations.json
├── incident_reports/
├── correlation_reports/
└── demo_correlation_reports/
```

Markdown reports can be viewed in VS Code using the Markdown preview shortcut: `Command + Shift + V`.

## Development Roadmap

### Phase 1 — Security Detection & Incident Response

- [x] Configure local Python development environment.
- [x] Create simulated AWS CloudTrail logs.
- [x] Develop failed-login detection.
- [x] Develop IAM AdministratorAccess detection.
- [x] Implement centralized security alerts.
- [x] Generate automated Markdown incident reports.
- [x] Add MITRE ATT&CK mappings.
- [x] Implement color-coded severity badges.
- [x] Develop security alert correlation.
- [x] Add correlated investigation reports.
- [x] Demonstrate HIGH, MEDIUM, and LOW report formatting.
- [x] Validate detection and correlation logic with 14 automated tests.
- [ ] Add automated tests for incident reporting and report integration.
- [ ] Publish sanitized sample investigation reports.

### Phase 2 — AWS Cloud Security Infrastructure

- [ ] Configure a secure AWS lab environment.
- [ ] Implement Terraform infrastructure provisioning.
- [ ] Analyze real CloudTrail events from an authorized test account.
- [ ] Expand threat detection coverage.
- [ ] Introduce additional cloud security monitoring controls.

### Phase 3 — Governance, Risk & Compliance

- [ ] Perform cloud security configuration assessments.
- [ ] Map security controls to NIST CSF 2.0 and applicable CIS benchmarks.
- [ ] Create a security risk register.
- [ ] Document remediation recommendations.
- [ ] Produce a final cloud security assessment report.

### Phase 4 — Portfolio Enhancements

- [ ] Add architecture diagrams and sanitized screenshots.
- [ ] Expand automated testing coverage.
- [ ] Implement CI testing with GitHub Actions.
- [ ] Finalize project documentation.

## Security Considerations

Cloud Sentinel currently analyzes **simulated AWS CloudTrail events** rather than live production data.

- No real attacks or malicious payloads are executed.
- Detection results indicate activity requiring investigation, not confirmed compromise.
- Correlation is based on selected event attributes and timing; it does not establish causation.
- Generated reports are excluded from Git to reduce the risk of exposing future sensitive security data.
- Actual AWS deployment and compliance auditing are planned future features.

## Career Applications

**SOC Analyst:** Threat detection, log analysis, event correlation, incident triage, and investigation documentation.

**Cloud Security Engineer:** AWS IAM security, cloud activity monitoring, security automation, and planned infrastructure-as-code deployment.

**GRC Analyst:** Security control documentation, evidence collection, and planned compliance and risk assessments.

---

*Cloud Sentinel is an ongoing cybersecurity portfolio project focused on developing practical security engineering and incident-response skills.*