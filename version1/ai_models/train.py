# train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
import joblib

print("📥 Loading sampled dataset...")

# Load feature dataset (no header)
X = pd.read_csv("ARP_MitM_dataset.csv", header=None)

# Load labels (index and label, with header)
labels_df = pd.read_csv("ARP_MitM_labels.csv")
y = labels_df["x"]  # Extract 'x' column which has 0 or 1

# Make sure X and y are aligned in length
X = X.iloc[:len(y)]

# Split into train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
print("🧠 Training Random Forest...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate
print("📊 Classification Report:")
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "arp_ids_model.pkl")
print("✅ Saved as arp_ids_model.pkl")
