import unittest
from datetime import datetime, timedelta, timezone
from detections.cloudtrail_detector import detect_failed_logins

# Starting timestamp for our simulated events
START_TIME = datetime(2026, 10, 21, 14, 0, tzinfo=timezone.utc)

def create_login_event(minutes, ip="203.0.113.50", result="Failure"):
    timestamp = START_TIME + timedelta(minutes=minutes)

    return {
        "eventTime": timestamp.isoformat(),
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": ip,
        "userIdentity": {
            "userName": "lab-user"
        },
        "responseElements": {
            "ConsoleLogin": result
        }
    }

class TestCloudTrailDetector(unittest.TestCase):

    # Test 1: Three failed logins should trigger an alert
    def test_three_failed_logins(self):
        events = [
            create_login_event(0),
            create_login_event(1),
            create_login_event(2)
        ]

        alerts = detect_failed_logins(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attempts"], 3)

    # Test 2: Two failures should NOT trigger an alert
    def test_two_failed_logins(self):
        events = [
            create_login_event(0),
            create_login_event(1)
        ]

        alerts = detect_failed_logins(events)

        self.assertEqual(len(alerts), 0)

    # Test 3: Failures outside five minutes should not alert
    def test_outside_time_window(self):
        events = [
            create_login_event(0),
            create_login_event(3),
            create_login_event(6)
        ]

        alerts = detect_failed_logins(events)

        self.assertEqual(len(alerts), 0)

    # Test 4: Different IP addresses should not be combined
    def test_different_ips(self):
        events = [
            create_login_event(0, "203.0.113.50"),
            create_login_event(1, "192.0.2.10"),
            create_login_event(2, "203.0.113.50")
        ]

        alerts = detect_failed_logins(events)

        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()