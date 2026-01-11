import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from features import extract_features
import joblib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(BASE_DIR, "urls.csv")

data = pd.read_csv(csv_path)

X = data["url"].apply(extract_features).tolist()
y = (
    data["label"]
    .str.strip()
    .str.lower()
    .map({"legitimate": 0, "phishing": 1})
)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print(f"Test Accuracy: {accuracy * 100:.2f}%")

model_path = os.path.join(BASE_DIR, "model.pkl")
joblib.dump(model, model_path)

print("AI is trained and saved successfully")
