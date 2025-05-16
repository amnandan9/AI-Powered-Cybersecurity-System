import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime, timedelta
from .models import DarkWebAlert
import random

def fetch_dark_web_alerts():
    """
    Simulates fetching dark web alerts from various sources.
    In a real implementation, this would connect to dark web APIs or monitoring services.
    """
    # Sample threat types and keywords
    threat_types = [
        'data_breach',
        'malware',
        'phishing',
        'ransomware',
        'exploit',
        'credentials'
    ]
    
    # Sample organizations and domains
    organizations = [
        'TechCorp',
        'FinanceInc',
        'HealthCare Systems',
        'EduNetwork',
        'RetailChain'
    ]
    
    domains = [
        'example.com',
        'techcorp.com',
        'financeinc.com',
        'healthcare.com',
        'edunetwork.edu'
    ]
    
    # Generate sample alerts
    for _ in range(3):  # Create 3 new alerts
        threat_type = random.choice(threat_types)
        risk_level = random.choice(['low', 'medium', 'high', 'critical'])
        confidence = random.randint(50, 100)
        
        alert = DarkWebAlert.objects.create(
            title=f"Potential {threat_type.replace('_', ' ').title()} Activity Detected",
            description=f"Monitoring systems have detected suspicious activity related to {threat_type.replace('_', ' ')}. "
                       f"Initial analysis suggests {risk_level} risk level with {confidence}% confidence.",
            source=f"Dark Web Forum #{random.randint(1000, 9999)}",
            risk_level=risk_level,
            threat_type=threat_type,
            confidence_score=confidence,
            affected_domain=f"https://{random.choice(domains)}",
            affected_organization=random.choice(organizations),
            keywords=f"{threat_type}, {random.choice(['credentials', 'data', 'access'])}",
            status='new'
        )
        alert.save()

def analyze_alert(alert_id):
    """
    Analyzes a specific alert and updates its status and confidence score.
    """
    try:
        alert = DarkWebAlert.objects.get(id=alert_id)
        
        # Simulate analysis process
        if alert.confidence_score > 80:
            alert.is_verified = True
            alert.verification_source = "Automated Analysis System"
            alert.status = 'investigating'
        else:
            alert.status = 'new'
            
        alert.save()
        return True
    except DarkWebAlert.DoesNotExist:
        return False

def get_alerts_by_risk_level(risk_level):
    """
    Returns alerts filtered by risk level.
    """
    return DarkWebAlert.objects.filter(risk_level=risk_level).order_by('-timestamp')

def get_alerts_by_threat_type(threat_type):
    """
    Returns alerts filtered by threat type.
    """
    return DarkWebAlert.objects.filter(threat_type=threat_type).order_by('-timestamp')

def get_recent_alerts(hours=24):
    """
    Returns alerts from the last specified hours.
    """
    time_threshold = datetime.now() - timedelta(hours=hours)
    return DarkWebAlert.objects.filter(timestamp__gte=time_threshold).order_by('-timestamp')

def update_alert_status(alert_id, new_status):
    """
    Updates the status of a specific alert.
    """
    try:
        alert = DarkWebAlert.objects.get(id=alert_id)
        alert.status = new_status
        alert.save()
        return True
    except DarkWebAlert.DoesNotExist:
        return False
