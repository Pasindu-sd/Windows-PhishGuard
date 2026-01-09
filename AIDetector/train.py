import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from features import extract_features
import joblib
import os

# Load dataset (CORRECT WAY)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(BASE_DIR, "urls_dataset.csv")

data = pd.read_csv(csv_path)

# Extract features from URLs
X = data["url"].apply(extract_features).tolist()

# Convert labels to numbers
y = (
    data["label"]
    .str.strip()
    .str.lower()
    .map({"legitimate": 0, "phishing": 1})
)

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Evaluate model
accuracy = model.score(X_test, y_test)
print(f"Test Accuracy: {accuracy * 100:.2f}%")

# Save model
model_path = os.path.join(BASE_DIR, "model.pkl")
joblib.dump(model, model_path)

print("✅ AI is trained and saved successfully")
