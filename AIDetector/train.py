import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from features import extract_features
import joblib

# Load dataset
data = pd.read_csv("urls.csv")

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

# Train model (XGBoost replacement)
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Evaluate model
accuracy = model.score(X_test, y_test)
print(f"Test Accuracy: {accuracy * 100:.2f}%")

# Save model
joblib.dump(model, "model.pkl")

print("✅ AI is trained and saved (Python 3.14 compatible)")
