import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score,classification_report

# Load traffic dataset
data = pd.read_csv("../data/traffic.csv")

# Features used by the AI
features = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "packets_per_second",
    "bytes_per_second",
    "destination_port_count",
    "connection_count",
    "protocol"
]

X = data[features]
y = data["label"]

# Convert labels into numbers
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# Split data into training and testing
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.3,
    random_state=42,
    stratify=y_encoded
)

# Create Random Forest model
model = RandomForestClassifier(
    n_estimators=150,
    random_state=42
)

# Train the model
model.fit(X_train, y_train)

# Test the model
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("AI model trained successfully!")
print("Accuracy:",round( accuracy*100,2),"%")

# Save the trained model
joblib.dump(model, "../models/threat_model.pkl")
joblib.dump(encoder, "../models/label_encoder.pkl")

print("Model saved successfully!")