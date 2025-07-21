from django.test import TestCase
from django.contrib.auth.models import User
from .models import ThreatLog

class ThreatLogTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.log = ThreatLog.objects.create(user=self.user, ip_address="192.168.1.1", threat_type="DDoS", confidence_score=0.9)

    def test_threat_log_creation(self):
        self.assertEqual(self.log.ip_address, "192.168.1.1")
        self.assertEqual(self.log.threat_type, "DDoS")
