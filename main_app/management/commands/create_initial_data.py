from django.core.management.base import BaseCommand
from main_app.models import ThreatCategory, ThreatLog
from threat_monitoring.models import ThreatLog as MonitoringLog
from dark_web_monitoring.models import DarkWebAlert
from django.utils.timezone import now
from datetime import timedelta

class Command(BaseCommand):
    help = 'Creates initial data for testing'

    def handle(self, *args, **kwargs):
        # Create threat categories
        categories = [
            ('Malware', 'Malicious software threats'),
            ('Phishing', 'Phishing and social engineering attacks'),
            ('DDoS', 'Distributed Denial of Service attacks'),
            ('Data Exfiltration', 'Unauthorized data transfer'),
        ]
        
        for name, description in categories:
            ThreatCategory.objects.get_or_create(
                name=name,
                defaults={'description': description}
            )

        # Create main app threat logs
        malware = ThreatCategory.objects.get(name='Malware')
        phishing = ThreatCategory.objects.get(name='Phishing')
        
        ThreatLog.objects.get_or_create(
            ip_address='192.168.1.100',
            threat_type=malware,
            defaults={
                'confidence_score': 0.95,
                'status': 'active'
            }
        )
        
        ThreatLog.objects.get_or_create(
            ip_address='10.0.0.50',
            threat_type=phishing,
            defaults={
                'confidence_score': 0.85,
                'status': 'pending'
            }
        )

        # Create threat monitoring logs
        MonitoringLog.objects.get_or_create(
            source_ip='192.168.1.100',
            destination_ip='10.0.0.1',
            threat_type='Malware',
            defaults={
                'severity': 'high',
                'ai_risk_score': 85.5,
                'description': 'Suspicious file transfer detected'
            }
        )

        # Create dark web alerts
        DarkWebAlert.objects.get_or_create(
            alert_type='credentials_leak',
            source='Dark Web Forum',
            defaults={
                'affected_data': 'Email credentials',
                'severity': 'high'
            }
        )

        self.stdout.write(self.style.SUCCESS('Successfully created initial data')) 