import joblib
import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from AIDetector.features import extract_features

# ============================================
# Constants
# ============================================
MODEL_PATH = os.path.join("AIDetector", "model.pkl")

# Rule-based detection patterns
PHISHING_INDICATORS = {
    '@': "URL contains @ symbol",
    'login': "Login keyword detected"
}

SAFE_PROTOCOLS = ['https://']

# Global variable for dynamic rule updates (used by main.py)
suspicious_patterns = list(PHISHING_INDICATORS.keys())


# ============================================
# Helper Functions
# ============================================
def _check_phishing_indicators(url):
    """Check URL against rule-based indicators.
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if phishing indicators found
    """
    url_lower = url.lower()
    return any(indicator in url_lower for indicator in PHISHING_INDICATORS.keys())


def _load_ml_model():
    """Load trained ML model for URL classification.
    
    Returns:
        object: Loaded ML model
        
    Raises:
        FileNotFoundError: If model file not found
    """
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"ML model not found at {MODEL_PATH}")
    
    return joblib.load(MODEL_PATH)


def _ml_predict_url(url, model):
    """Predict URL safety using ML model.
    
    Args:
        url (str): URL to analyze
        model: Trained ML model
        
    Returns:
        dict: Prediction result with label and confidence score
    """
    features = extract_features(url)
    pred = model.predict([features])[0]
    proba = model.predict_proba([features])[0][1]
    
    return {
        "label": "PHISHING" if pred == 1 else "SAFE",
        "score": float(proba),
    }


# ============================================
# Main Detection Function
# ============================================
def detect_url(url):
    """Detect phishing URLs using hybrid approach (rules + ML).
    
    This function combines:
    1. Rule-based detection: Checks for common phishing patterns
    2. ML-based detection: Uses trained model for classification
    
    Args:
        url (str): URL to analyze
        
    Returns:
        str: Classification result
            - "SAFE": URL appears legitimate
            - "PHISHING": URL detected as phishing
    """
    # Rule-based check
    result_rule = "PHISHING" if _check_phishing_indicators(url) else "SAFE"
    
    # ML-based check
    try:
        model = _load_ml_model()
        result_ml = _ml_predict_url(url, model)
    except (FileNotFoundError, Exception) as e:
        print(f"ML model error: {e}, using rule-based detection only")
        result_ml = {"label": "SAFE", "score": 0.0}
    
    # Log results for debugging
    print(f"[Rule-Based] Result: {result_rule}")
    print(f"[ML-Based] Result: {result_ml['label']} ({result_ml['score']*100:.1f}%)")
    
    # Final verdict: If either detects phishing, mark as phishing
    if result_rule == "PHISHING" or result_ml["label"] == "PHISHING":
        return "PHISHING"
    
    return "SAFE"
