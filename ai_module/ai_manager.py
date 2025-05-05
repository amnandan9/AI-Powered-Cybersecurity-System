import sys
import os
import joblib 
import numpy as np
import pandas as pd

# Ensure ai_module is found in the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.preprocess import preprocess_log_data
from utils.postprocess import format_prediction

# Load trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "model.pkl")
model = joblib.load(MODEL_PATH)

def convert_ip_to_int(ip):
    """Converts an IP address string into an integer."""
    if isinstance(ip, int):  
        return ip  # Already converted, return as is
    
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def predict_threat(log_entry):
    """
    Predicts the threat type from a log entry.

    Args:
        log_entry (dict): A dictionary containing log details.

    Returns:
        dict: A structured response with prediction and probabilities.
    """
    try:
        # Ensure log_entry is in DataFrame format
        log_df = pd.DataFrame([log_entry])

        # 🔹 Convert timestamp to a numeric Unix timestamp (int)
        log_df["timestamp"] = pd.to_numeric(log_df["timestamp"], errors="coerce").fillna(0).astype(int)

        # 🔹 Convert IP addresses to integers
        log_df["src_ip"] = log_df["src_ip"].apply(convert_ip_to_int)
        log_df["dst_ip"] = log_df["dst_ip"].apply(convert_ip_to_int)

        # Preprocess the input log
        processed_data = preprocess_log_data(log_df)

        # Make a prediction
        prediction = model.predict(processed_data)
        probabilities = model.predict_proba(processed_data)

        # Interpret the prediction
        result = format_prediction(probabilities[0])  

        return result
    except Exception as e:
        return {"error": f"Prediction failed: {str(e)}"}

if __name__ == "__main__":
    # Example test case
    test_log = {
        "timestamp": 1742733950,  # Unix timestamp
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "protocol": "TCP",
        "bytes": 5000
    }

    prediction_result = predict_threat(test_log)
    print("\n🔍 AI Threat Analysis:")
    print(prediction_result)
