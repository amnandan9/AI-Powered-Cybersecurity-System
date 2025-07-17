from django.db import models

# Categories of cyber threats
class ThreatCategory(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

# Logs of detected cyber threats
class ThreatLog(models.Model):
    ip_address = models.GenericIPAddressField()
    threat_type = models.ForeignKey(ThreatCategory, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    confidence_score = models.FloatField()
    status = models.CharField(max_length=20, default='pending')
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.threat_type} detected at {self.ip_address} with {self.confidence_score*100:.2f}% confidence"

class URLThreat(models.Model):
    url = models.URLField(max_length=500)
    threat_type = models.ForeignKey(ThreatCategory, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    confidence_score = models.FloatField()
    status = models.CharField(max_length=20, default='pending')
    description = models.TextField(blank=True, null=True)
    
    # URL-specific threat details
    has_ads = models.BooleanField(default=False)
    has_malware = models.BooleanField(default=False)
    has_phishing = models.BooleanField(default=False)
    has_redirects = models.BooleanField(default=False)
    redirect_chain = models.TextField(blank=True, null=True)
    is_approved = models.BooleanField(default=False)
    risk_level = models.CharField(max_length=20, default='low')
    
    def __str__(self):
        return f"{self.threat_type} detected at {self.url} with {self.confidence_score*100:.2f}% confidence"
