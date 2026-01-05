import pickle
import os
from AI-Detector.features import extract_features  # feature extractor import

# model.pkl path set කරගන්න
MODEL_PATH = os.path.join("AI-Detector", "model.pkl")

# ML Model එක load කිරීම
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# ML prediction function
def ml_predict_url(url):
    """
    URL එකට ML prediction ලබා දෙයි
    Returns: {"label": "PHISHING" or "SAFE", "score": probability}
    """
    features = extract_features(url)  # AI-Detector/features.py function
    pred = model.predict([features])[0]
    proba = model.predict_proba([features])[0][1]  # phishing probability

    return {
        "label": "PHISHING" if pred == 1 else "SAFE",
        "score": float(proba),
    }

# original rule-based detection function (ඔයාගේ existing logic)
def original_rule_based_check(url):
    # Example simple rule
    if "@" in url or "login" in url:
        return "PHISHING"
    return "SAFE"

# combined detection
def detect_url(url):
    # rule-based check
    result_rule = original_rule_based_check(url)

    # ML model check
    result_ml = ml_predict_url(url)

    # print results
    print(f"[Rule] Result: {result_rule}")
    print(f"[ML] Result: {result_ml['label']} ({result_ml['score']*100:.1f}%)")

    # combine decision
    if result_rule == "PHISHING" or result_ml["label"] == "PHISHING":
        return "PHISHING"
    return "SAFE"

# Example usage
if __name__ == "__main__":
    test_urls = [
        "http://example.com/login",
        "https://safe-website.com",
        "http://phishingsite.com/@login"
    ]

    for url in test_urls:
        result = detect_url(url)
        print(f"URL: {url} --> {result}\n")
