import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from features import extract_features
import joblib

data = pd.read_csv("urls.csv")

X = data["url"].apply(extract_features).tolist()
y = data["label"].str.strip().str.lower().map({"legitimate": 0,"phishing": 1})

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, eval_metric='logloss')

model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print("Test Accuracy: {:.2f}%".format(accuracy * 100))

joblib.dump(model, "model.pkl")

print("AI is trained and saved!")