import pandas as pd
import numpy as np
import ipaddress
from sklearn.preprocessing import LabelEncoder

def ip_to_int(ip):
    """Convert IP address string to an integer if it's not already an integer."""
    if isinstance(ip, str):  # Ensure only string IPs are converted
        return int(ipaddress.IPv4Address(ip))
    return ip  # If already an integer, return as is

def preprocess_log_data(log_data):
    """
    Cleans and transforms raw security log data for AI-based predictions.
    
    Args:
        log_data (pd.DataFrame): Raw log data containing network activity.
    
    Returns:
        pd.DataFrame: Processed data ready for AI predictions.
    """
    # Ensure required columns exist
    required_columns = ["timestamp", "src_ip", "dst_ip", "protocol", "bytes"]
    for col in required_columns:
        if col not in log_data.columns:
            raise ValueError(f"Missing required column: {col}")

    # Convert timestamp to integer (Unix timestamp)
    log_data["timestamp"] = pd.to_numeric(log_data["timestamp"], errors="coerce").fillna(0).astype(int)

    # Convert IP addresses only if they are in string format
    log_data["src_ip"] = log_data["src_ip"].apply(ip_to_int)
    log_data["dst_ip"] = log_data["dst_ip"].apply(ip_to_int)

    # Convert categorical features (protocol)
    encoder = LabelEncoder()
    log_data["protocol"] = encoder.fit_transform(log_data["protocol"])

    return log_data

# Test Run
if __name__ == "__main__":
    sample_data = pd.DataFrame({
        "timestamp": [1742733001, 1742733075, 1742733300],
        "src_ip": ["192.168.1.10", "192.168.1.12", "10.0.0.5"],
        "dst_ip": ["8.8.8.8", "8.8.4.4", "192.168.1.1"],
        "protocol": ["TCP", "UDP", "ICMP"],
        "bytes": [500, 300, 2000]
    })
    
    print("✅ Processed Sample Data:\n", preprocess_log_data(sample_data))
