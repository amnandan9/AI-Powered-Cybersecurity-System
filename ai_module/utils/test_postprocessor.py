import numpy as np
from postprocess import format_prediction

# ✅ Sample prediction probabilities from AI model
sample_prediction = np.array([0.05, 0.1, 0.7, 0.05, 0.1])

# Run postprocessing
try:
    threat_report = format_prediction(sample_prediction)
    print("🔍 Threat Report:\n", threat_report)
except Exception as e:
    print("❌ Error in postprocessor:", str(e))
