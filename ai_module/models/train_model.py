import pandas as pd
import xgboost as xgb
import pickle
import ipaddress
import json
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Load dataset
df = pd.read_csv(r"C:\Users\Maria Kevin\OneDrive\Desktop\New folder\cyber_threat_detection\ai_module\dataset\log_data.csv")

# Convert timestamp safely
try:
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce').astype('int64') // 10**9
except Exception as e:
    print("❌ Error converting timestamp:", e)

# Convert IP addresses safely
def convert_ip(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0  # Default to 0 if invalid

df['src_ip'] = df['src_ip'].apply(convert_ip)
df['dst_ip'] = df['dst_ip'].apply(convert_ip)

# Encode protocol if it exists
if 'protocol' in df.columns:
    protocol_encoder = LabelEncoder()
    df['protocol'] = protocol_encoder.fit_transform(df['protocol'])
    
    # Save protocol mapping
    protocol_mapping = {label: idx for idx, label in enumerate(protocol_encoder.classes_)}
    with open("ai_module/models/protocol_mapping.json", 'w') as f:
        json.dump(protocol_mapping, f)
else:
    print("⚠️ Warning: 'protocol' column missing, skipping encoding.")

# Ensure threat_type column exists
if 'threat_type' in df.columns:
    label_encoder = LabelEncoder()
    df['threat_type'] = label_encoder.fit_transform(df['threat_type'])

    # Save label mapping
    with open("ai_module/models/label_encoder.pkl", 'wb') as f:
        pickle.dump(label_encoder, f)
    
    threat_mapping = {idx: label for idx, label in enumerate(label_encoder.classes_)}
    with open("ai_module/models/threat_mapping.json", 'w') as f:
        json.dump(threat_mapping, f)

    # Separate features and target
    X = df.drop(columns=['threat_type'])
    y = df['threat_type']
else:
    print("❌ 'threat_type' column missing!")
    exit()

# Debugging: Print dataset insights
print("\n✅ Processed Data Sample:\n", df.head())
print("✅ Unique Threat Labels:", y.unique())
print("✅ Train-Test Split Sizes (Before SMOTE):", len(X), "-> Train:", int(len(X) * 0.8), ", Test:", int(len(X) * 0.2))

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Handle class imbalance only if dataset is large enough
if y_train.nunique() > 1 and len(X_train) > 2:  # Adjusted threshold
    from imblearn.over_sampling import SMOTE
    k_neighbors = min(1, max(len(X_train) - 1, 1))  # Avoid SMOTE errors in small datasets
    smote = SMOTE(random_state=42, k_neighbors=k_neighbors)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    print("✅ Applied SMOTE. New Training Set Size:", len(X_train))
else:
    print("⚠️ Skipping SMOTE due to insufficient data.")

# Train XGBoost model
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n✅ Model Accuracy: {accuracy * 100:.2f}%")

# Debugging: Print sample predictions
print("\n🔍 Sample Predictions vs. Actual Values:")
print("Predictions:", y_pred[:5])
print("Actual:", y_test[:5].values)

# Save model
with open("ai_module/models/model.pkl", 'wb') as f:
    pickle.dump(model, f)

print("✅ Model saved as 'ai_module/models/model.pkl'.")

# Save protocol encoder if available
if 'protocol' in df.columns:
    with open("ai_module/models/protocol_encoder.pkl", 'wb') as f:
        pickle.dump(protocol_encoder, f)
