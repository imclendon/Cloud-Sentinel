# Cloud Sentinel
### AWS Threat Detection, Security Monitoring & Compliance Automation

Cloud Sentinel is a Python-based cloud security project designed to simulate real-world Security Operations Center (SOC) workflows within an AWS environment.

The project focuses on detecting suspicious cloud activity, analyzing AWS CloudTrail events, automating security investigations, and eventually evaluating cloud configurations against industry security frameworks.

**Project Status:** Active Development — Phase 1: Threat Detection

## Project Objectives

- Develop automated threat detection rules for AWS CloudTrail events.
- Identify suspicious authentication attempts and IAM privilege changes.
- Reduce false positives through event correlation and automated testing.
- Generate structured security alerts and incident investigation reports.
- Deploy and secure AWS infrastructure using Terraform.
- Evaluate cloud security controls using NIST CSF 2.0 and CIS benchmarks.

## Current Features

### 1. Suspicious Login Detection
**File:** `detections/cloudtrail_detector.py`

Analyzes simulated AWS CloudTrail authentication events to identify potentially suspicious login activity.

**Detection Logic:**
- Filters AWS `ConsoleLogin` events for failed authentication attempts.
- Groups events by username and source IP address.
- Uses a five-minute sliding time window to correlate events.
- Generates a security alert when three or more failed attempts occur within the configured window.

### 2. IAM Privilege Change Detection
**File:** `detections/iam_detector.py`

Monitors simulated AWS IAM activity for administrator policy attachments that could indicate unauthorized privilege changes.

**Detection Logic:**
- Identifies `AttachUserPolicy` events.
- Detects attachments of the AWS-managed `AdministratorAccess` policy.
- Excludes API requests reporting an error.
- Extracts the actor, target user, source IP, and timestamp.
- Generates a high-severity alert for analyst investigation.

### 3. Automated Detection Testing

Python's built-in `unittest` framework is used to validate detection behavior.

Verified login detection scenarios include:
- Three failed logins within the detection window.
- Fewer than three failed logins.
- Login attempts outside the detection window.
- Login attempts originating from different IP addresses.

## Technologies

| Technology | Purpose |
|---|---|
| Python | Security event parsing, correlation, and detection |
| JSON | CloudTrail event data and security findings |
| AWS CloudTrail | Cloud activity logging format |
| Git & GitHub | Version control and project documentation |
| Terraform | Planned AWS infrastructure provisioning |
| AWS IAM | Identity and access management analysis |
| NIST CSF 2.0 / CIS | Planned security assessments and compliance mapping |

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
│   └── test_cloudtrail_detector.py
├── .gitignore
└── README.md
```

Additional tests, infrastructure configuration, and incident-response documentation will be added as development progresses.

## Getting Started

**Requirements:** Python 3 and a terminal.

1. Open the Cloud Sentinel project directory.
2. Run the failed-login detector:

```bash
python3 detections/cloudtrail_detector.py
```

3. Run the IAM privilege-change detector:

```bash
python3 detections/iam_detector.py
```

4. Run the automated tests:

```bash
python3 -m unittest discover -s tests -v
```

The current detection scripts use only the Python standard library and do not require AWS credentials.

## Example Security Alert

```text
[HIGH SEVERITY ALERT] AdministratorAccess Attached
Actor: arn:aws:iam::111122223333:user/lab-admin
Target user: lab-user
Source IP: 192.0.2.44
Timestamp: 2026-10-21T14:04:00Z
Status: Investigate privilege change
```

## Development Roadmap

- [x] Establish local development environment.
- [x] Implement failed-login detection.
- [x] Implement IAM administrator policy attachment detection.
- [x] Validate failed-login detection with automated tests.
- [ ] Expand IAM detection test coverage.
- [ ] Integrate detection rules into a centralized alert engine.
- [ ] Generate JSON security alerts and incident reports.
- [ ] Configure an AWS test environment and monitoring.
- [ ] Deploy infrastructure using Terraform.
- [ ] Perform cloud security configuration assessments.
- [ ] Map security findings to NIST CSF 2.0 and CIS controls.
- [ ] Produce a final risk assessment and incident-response portfolio.

## Security and Limitations

Cloud Sentinel currently operates against **synthetic CloudTrail events** for safe, repeatable testing. It does not perform attacks or modify live AWS resources.

Detection rules identify activities that warrant investigation; alerts alone do not establish malicious intent. Current rules cover selected event patterns rather than comprehensive threat detection.

Future development will expand event coverage, improve alert context, and integrate cloud-based security monitoring.

## Career Focus

This project is designed to demonstrate practical skills relevant to:

**SOC Analyst:** Log analysis, threat detection, event correlation, incident triage.

**Cloud Security Engineer:** AWS IAM monitoring, cloud infrastructure security, automation.

**GRC Analyst:** Security control assessment, risk documentation, compliance mapping.