from django.test import TestCase, Client
from django.utils.timezone import now
from .models import ThreatLog
from .services import log_threat

class ThreatLogModelTest(TestCase):
    """Test cases for the ThreatLog model."""

    def setUp(self):
        """Set up a sample threat log."""
        self.threat = ThreatLog.objects.create(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.2",
            threat_type="DDoS Attack",
            severity="high",
            timestamp=now(),
            description="Test threat log"
        )

    def test_threat_log_creation(self):
        """Test if the threat log is created correctly."""
        self.assertEqual(self.threat.source_ip, "192.168.1.1")
        self.assertEqual(self.threat.threat_type, "DDoS Attack")
        self.assertEqual(self.threat.severity, "high")

    def test_str_representation(self):
        """Test the string representation of the model."""
        self.assertEqual(str(self.threat), "DDoS Attack - high [192.168.1.1 → 10.0.0.2]")

class ThreatMonitoringViewsTest(TestCase):
    """Test cases for threat monitoring views."""

    def setUp(self):
        """Set up test client and sample threat logs."""
        self.client = Client()
        ThreatLog.objects.create(
            source_ip="10.0.0.1",
            destination_ip="192.168.1.10",
            threat_type="SQL Injection",
            severity="medium",
            timestamp=now(),
            description="Sample log"
        )

    def test_dashboard_view(self):
        """Test if the dashboard page loads correctly."""
        response = self.client.get("/threat_monitoring/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "threat_monitoring/dashboard.html")

    def test_logs_view(self):
        """Test if the logs page loads correctly."""
        response = self.client.get("/threat_monitoring/logs/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "threat_monitoring/logs.html")

class ThreatLogServiceTest(TestCase):
    """Test cases for threat logging service."""

    def test_log_threat(self):
        """Test if threats are correctly logged using the service."""
        threat = log_threat(
            source_ip="192.168.1.50",
            destination_ip="10.0.0.5",
            threat_type="Brute Force Attack",
            description="Automated brute force attack detected"
        )

        self.assertIsInstance(threat, ThreatLog)
        self.assertEqual(threat.threat_type, "Brute Force Attack")
        self.assertEqual(threat.source_ip, "192.168.1.50")
