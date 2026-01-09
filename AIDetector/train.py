import pandas as pd
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

# Example dataset (replace later)
data = {
    "url_length": [10, 55, 72, 20, 90],
    "has_https": [1, 0, 0, 1, 0],
    "has_login": [0, 1, 1, 0, 1],
    "label": [0, 1, 1, 0, 1]
}

df = pd.DataFrame(data)

X = df.drop("label", axis=1)
y = df["label"]

model = LogisticRegression()
model.fit(X, y)

with open("url_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained & saved (Python 3.14 compatible)")
