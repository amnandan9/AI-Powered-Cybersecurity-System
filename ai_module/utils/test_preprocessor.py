import pandas as pd
from preprocess import preprocess_log_data

# ✅ Sample raw log data (before preprocessing)
sample_data = pd.DataFrame({
    "timestamp": [1742733001, 1742733075, 1742733300],
    "src_ip": ["192.168.1.10", "192.168.1.12", "10.0.0.5"],
    "dst_ip": ["8.8.8.8", "8.8.4.4", "192.168.1.1"],
    "protocol": ["TCP", "UDP", "ICMP"],
    "bytes": [500, 300, 2000]
})

# Run preprocessing
try:
    processed_data = preprocess_log_data(sample_data)
    print("✅ Preprocessed Data:\n", processed_data)
except Exception as e:
    print("❌ Error in preprocessor:", str(e))
