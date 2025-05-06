import pandas as pd
import ipaddress
from datetime import datetime

def convert_ip(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0  # Default to 0 if invalid

def predict_threat(ip_address):
    """
    Predicts threat type and confidence score for a given IP address.
    This is a simplified version for testing that doesn't require model files.
    Returns a tuple of (threat_type, confidence_score)
    """
    try:
        # Convert IP to integer for basic analysis
        ip_int = convert_ip(ip_address)
        
        # Simple rule-based prediction for testing
        if ip_int == 0:  # Invalid IP
            return "Invalid IP", 0.9
        elif ip_int < 3232235776:  # Less than 192.168.0.0
            return "External Threat", 0.85
        else:
            return "Internal Threat", 0.75

    except Exception as e:
        print(f"Prediction error: {str(e)}")
        return "Unknown", 0.5  # Default fallback values

# Test code (runs only if script is executed directly)
if __name__ == "__main__":
    test_ip = "192.168.1.10"
    threat_type, confidence = predict_threat(test_ip)
    print(f"Test IP: {test_ip}")
    print(f"Detected Threat: {threat_type}")
    print(f"Confidence Score: {confidence:.2f}")
