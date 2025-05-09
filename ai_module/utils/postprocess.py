import numpy as np

# Threat categories mapping
THREAT_CATEGORIES = ["DDoS", "Malware", "Normal", "Phishing", "Unauthorized Access"]

def format_prediction(prediction_probs):
    """
    Converts model prediction probabilities into a structured report.
    
    Args:
        prediction_probs (np.ndarray): Array of probabilities from the AI model.
    
    Returns:
        dict: Readable report with categorized threat probabilities.
    """
    threat_report = {THREAT_CATEGORIES[i]: float(prediction_probs[i]) for i in range(len(THREAT_CATEGORIES))}
    
    # Determine the highest threat category
    detected_threat = THREAT_CATEGORIES[np.argmax(prediction_probs)]
    
    return {
        "Detected Threat": detected_threat,
        "Probability Scores": threat_report
    }

# Test Run
if __name__ == "__main__":
    sample_prediction = np.array([0.05, 0.1, 0.7, 0.05, 0.1])
    print("🔍 Threat Report:\n", format_prediction(sample_prediction))
