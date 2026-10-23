import unittest
from detections.iam_detector import detect_admin_policy_attachments

ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"

# Helper function to create simulated CloudTrail events
def create_iam_event(
    policy=ADMIN_POLICY,
    event_name="AttachUserPolicy",
    error_code=None
):
    event = {
        "eventTime": "2026-10-21T14:04:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": event_name,
        "sourceIPAddress": "192.0.2.44",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "lab-admin"
        },
        "requestParameters": {
            "userName": "lab-user",
            "policyArn": policy
        },
        "responseElements": None
    }
    if error_code:
        event["errorCode"] = error_code
    return event

class TestIAMDetector(unittest.TestCase):

    # Test 1: AdministratorAccess attached successfully
    def test_admin_policy_attachment(self):
        events = [create_iam_event()]

        alerts = detect_admin_policy_attachments(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["target_user"], "lab-user")

    # Test 2: A non-administrator policy is attached
    def test_normal_policy_attachment(self):
        events = [
            create_iam_event(
                policy="arn:aws:iam::aws:policy/ReadOnlyAccess"
            )
        ]
        alerts = detect_admin_policy_attachments(events)
        self.assertEqual(len(alerts), 0)

    # Test 3: AdministratorAccess attachment fails
    def test_failed_admin_attachment(self):
        events = [
            create_iam_event(error_code="AccessDenied")
        ]
        alerts = detect_admin_policy_attachments(events)
        self.assertEqual(len(alerts), 0)

    # Test 4: A different IAM action occurs
    def test_unrelated_iam_event(self):
        events = [
            create_iam_event(event_name="ListUsers")
        ]
        alerts = detect_admin_policy_attachments(events)
        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()