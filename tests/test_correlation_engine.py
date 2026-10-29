import unittest
from correlation_engine import correlate_alerts

# Helper function to simulate a failed-login alert
def create_login_alert(
    user="lab-user",
    timestamp="2026-10-21T14:02:00Z"
):
    return {
        "rule_id": "CS-001",
        "title": "Multiple Failed AWS Logins",
        "severity": "MEDIUM",
        "user": user,
        "source_ip": "203.0.113.50",
        "timestamp": timestamp,
        "details": {"failed_attempts": 3}
    }

# Helper function to simulate an IAM privilege-change alert
def create_iam_alert(
    user="lab-user",
    timestamp="2026-10-21T14:04:00Z"
):
    return {
        "rule_id": "CS-002",
        "title": "AdministratorAccess Policy Attached",
        "severity": "HIGH",
        "user": user,
        "source_ip": "192.0.2.44",
        "timestamp": timestamp,
        "details": {"actor": "lab-admin"}
    }

class TestCorrelationEngine(unittest.TestCase):

    # Test 1: Related activity should correlate
    def test_valid_correlation(self):
        alerts = [
            create_login_alert(),
            create_iam_alert()
        ]

        results = correlate_alerts(alerts)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["priority"], "HIGH")
        self.assertEqual(
            results[0]["minutes_between_events"], 2.0
        )

    # Test 2: Different target users should not correlate
    def test_different_users(self):
        alerts = [
            create_login_alert(user="user-a"),
            create_iam_alert(user="user-b")
        ]

        results = correlate_alerts(alerts)

        self.assertEqual(len(results), 0)

    # Test 3: Activity outside 10 minutes should not correlate
    def test_outside_time_window(self):
        alerts = [
            create_login_alert(),
            create_iam_alert(
                timestamp="2026-10-21T14:13:00Z"
            )
        ]

        results = correlate_alerts(alerts)

        self.assertEqual(len(results), 0)

    # Test 4: IAM change before failed logins should not match
    def test_wrong_event_order(self):
        alerts = [
            create_login_alert(),
            create_iam_alert(
                timestamp="2026-10-21T14:01:00Z"
            )
        ]

        results = correlate_alerts(alerts)

        self.assertEqual(len(results), 0)

    # Test 5: Exactly 10 minutes should still correlate
    def test_time_window_boundary(self):
        alerts = [
            create_login_alert(),
            create_iam_alert(
                timestamp="2026-10-21T14:12:00Z"
            )
        ]

        results = correlate_alerts(alerts)

        self.assertEqual(len(results), 1)

    # Test 6: Identical events produce the same correlation ID
    def test_repeatable_correlation_id(self):
        alerts = [
            create_login_alert(),
            create_iam_alert()
        ]

        first = correlate_alerts(alerts)
        second = correlate_alerts(alerts)

        self.assertEqual(
            first[0]["correlation_id"],
            second[0]["correlation_id"]
        )

if __name__ == "__main__":
    unittest.main()