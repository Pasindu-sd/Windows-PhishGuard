import pickle
import os
from AI_Detector.features import extract_features 

MODEL_PATH = os.path.join("AI_Detector", "model.pkl")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

def ml_predict_url(url):
    features = extract_features(url)
    pred = model.predict([features])[0]
    proba = model.predict_proba([features])[0][1]  

    return {
        "label": "PHISHING" if pred == 1 else "SAFE",
        "score": float(proba),
    }

def original_rule_based_check(url):
    if "@" in url or "login" in url:
        return "PHISHING"
    return "SAFE"

def detect_url(url):
    result_rule = original_rule_based_check(url)

    result_ml = ml_predict_url(url)

    print(f"[Rule] Result: {result_rule}")
    print(f"[ML] Result: {result_ml['label']} ({result_ml['score']*100:.1f}%)")

    if result_rule == "PHISHING" or result_ml["label"] == "PHISHING":
        return "PHISHING"
    return "SAFE"

if __name__ == "__main__":
    test_urls = [
        "http://example.com/login",
        "https://safe-website.com",
        "http://phishingsite.com/@login"
    ]

    for url in test_urls:
        result = detect_url(url)
        print(f"URL: {url} --> {result}\n")