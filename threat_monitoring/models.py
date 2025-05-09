from django.db import models
from django.utils.timezone import now
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import timedelta

class ThreatLog(models.Model):
    """
    Stores detected cyber threats with enhanced monitoring capabilities.
    """
    THREAT_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    THREAT_TYPES = [
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('ddos', 'DDoS'),
        ('brute_force', 'Brute Force'),
        ('exploit', 'Exploit'),
        ('data_exfiltration', 'Data Exfiltration'),
        ('unauthorized_access', 'Unauthorized Access'),
        ('other', 'Other')
    ]

    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('contained', 'Contained'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive')
    ]

    # Basic threat information
    source_ip = models.GenericIPAddressField()
    source_location = models.JSONField(default=dict)
    destination_ip = models.GenericIPAddressField()
    destination_location = models.JSONField(default=dict)
    threat_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20)
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.TextField()
    
    # Enhanced threat analysis
    ai_risk_score = models.FloatField(default=0.0)
    confidence_score = models.FloatField(default=0.0)
    status = models.CharField(max_length=20, default='new')
    is_verified = models.BooleanField(default=False)
    verification_source = models.CharField(max_length=255, blank=True, null=True)
    
    # Additional metadata
    protocol = models.CharField(max_length=20, default='Unknown')
    port = models.IntegerField(default=0)
    packet_count = models.IntegerField(default=1)
    duration = models.DurationField(default=timedelta(seconds=0))
    affected_system = models.CharField(max_length=255, blank=True, null=True)
    mitigation_action = models.TextField(blank=True, null=True)
    
    # Timeline tracking
    first_seen = models.DateTimeField(default=now)
    last_seen = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.threat_type} from {self.source_ip}"
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Threat Log'
        verbose_name_plural = 'Threat Logs'
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['destination_ip']),
            models.Index(fields=['threat_type']),
            models.Index(fields=['severity']),
        ]
    
    def get_severity_color(self):
        """Returns Bootstrap color class based on severity"""
        colors = {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'dark'
        }
        return colors.get(self.severity, 'secondary')
    
    def get_status_color(self):
        """Returns Bootstrap color class based on status"""
        colors = {
            'new': 'primary',
            'investigating': 'warning',
            'contained': 'info',
            'resolved': 'success',
            'false_positive': 'secondary'
        }
        return colors.get(self.status, 'secondary')
    
    def get_threat_type_icon(self):
        """Returns Font Awesome icon class based on threat type"""
        icons = {
            'malware': 'fa-virus',
            'phishing': 'fa-fish',
            'ddos': 'fa-network-wired',
            'brute_force': 'fa-hammer',
            'exploit': 'fa-bug',
            'data_exfiltration': 'fa-database',
            'unauthorized_access': 'fa-user-lock',
            'other': 'fa-exclamation-triangle'
        }
        return icons.get(self.threat_type, 'fa-question-circle')
    
    def mark_as_resolved(self):
        """Marks the threat as resolved"""
        self.status = 'resolved'
        self.resolved_at = now()
        self.save()
    
    def update_status(self, new_status):
        """Updates the threat status"""
        if new_status in dict(self.STATUS_CHOICES):
            self.status = new_status
            if new_status == 'resolved':
                self.resolved_at = now()
            self.save()
            return True
        return False

class WebsiteTrafficAnalysis(models.Model):
    website_url = models.URLField(max_length=500)
    analysis_date = models.DateTimeField(default=now)
    total_requests = models.IntegerField(default=0)
    unique_visitors = models.IntegerField(default=0)
    bot_traffic_percentage = models.FloatField(default=0.0)
    suspicious_ips = models.JSONField(default=dict)
    traffic_sources = models.JSONField(default=dict)
    country_traffic = models.JSONField(default=dict, null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('analyzing', 'Analyzing'),
            ('completed', 'Completed'),
            ('failed', 'Failed')
        ],
        default='pending'
    )
    results = models.JSONField(default=dict)

    def __str__(self):
        return f"Analysis for {self.website_url} on {self.analysis_date}"

    class Meta:
        ordering = ['-analysis_date']
