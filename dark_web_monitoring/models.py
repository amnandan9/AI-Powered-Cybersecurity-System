from django.db import models
from django.utils.timezone import now

class DarkWebAlert(models.Model):
    """
    Stores dark web threat intelligence alerts with enhanced threat information.
    """
    title = models.CharField(max_length=255, default='Untitled Alert')
    description = models.TextField(default='No description available')
    source = models.CharField(max_length=255, default='Unknown Source')
    timestamp = models.DateTimeField(default=now)
    risk_level = models.CharField(max_length=10, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ], default='medium')
    
    # New fields for enhanced threat intelligence
    threat_type = models.CharField(max_length=50, choices=[
        ('data_breach', 'Data Breach'),
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('ransomware', 'Ransomware'),
        ('exploit', 'Exploit'),
        ('credentials', 'Stolen Credentials'),
        ('other', 'Other')
    ], default='other')
    
    confidence_score = models.IntegerField(default=50)  # 0-100 scale
    affected_domain = models.URLField(max_length=255, blank=True, null=True)
    affected_organization = models.CharField(max_length=255, blank=True, null=True)
    keywords = models.TextField(blank=True, null=True)  # Comma-separated keywords
    status = models.CharField(max_length=20, choices=[
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive')
    ], default='new')
    
    # Metadata
    last_updated = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)
    verification_source = models.CharField(max_length=255, blank=True, null=True)
    
    def __str__(self):
        return f"{self.title} - {self.source} [{self.timestamp}]"
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Dark Web Alert'
        verbose_name_plural = 'Dark Web Alerts'
        
    def get_risk_color(self):
        """Returns Bootstrap color class based on risk level"""
        colors = {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'dark'
        }
        return colors.get(self.risk_level, 'secondary')
    
    def get_status_color(self):
        """Returns Bootstrap color class based on status"""
        colors = {
            'new': 'primary',
            'investigating': 'warning',
            'resolved': 'success',
            'false_positive': 'secondary'
        }
        return colors.get(self.status, 'secondary')
