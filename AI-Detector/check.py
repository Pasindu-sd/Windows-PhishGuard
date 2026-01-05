import joblib
from features import extract_features

model = joblib.load("model.pkl")

while True:
    url = input("Enter URL (or 'exit' to quit): ")
    if url.lower() == "exit":
        break

    features = extract_features(url)
    result = model.predict([features])[0]
    prob = model.predict_proba([features])[0][1]
    if result == 1:
        print(f"PHISHING URL - Risk: {prob*100:.2f}%")
    else:
        print(f"SAFE URL - Risk: {prob*100:.2f}%")
