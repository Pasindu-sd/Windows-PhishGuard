import joblib
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from AIDetector.features import extract_features

# ============================================
# Constants
# ============================================
MODEL_PATH = os.path.join("AIDetector", "model.pkl")
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_CACHE_TTL_SECONDS = 300

# Rule-based detection patterns
PHISHING_INDICATORS = {
    '@': "URL contains @ symbol",
    'login': "Login keyword detected"
}

SAFE_PROTOCOLS = ['https://']

# Global variable for dynamic rule updates (used by main.py)
suspicious_patterns = list(PHISHING_INDICATORS.keys())
safe_browsing_cache = {}


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
    return any(indicator in url_lower for indicator in suspicious_patterns)


def _normalize_url(url):
    """Normalize URL for scanning.

    Args:
        url (str): Raw URL input

    Returns:
        str: URL with protocol for API checks
    """
    normalized = (url or "").strip()
    if normalized and not normalized.startswith(("http://", "https://")):
        return f"https://{normalized}"
    return normalized


def _get_safe_browsing_api_key():
    """Read Google Safe Browsing API key from environment variables."""
    return (
        os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
        or os.environ.get("SAFE_BROWSING_API_KEY")
        or ""
    ).strip()


def _get_cached_safe_browsing_result(url):
    """Return cached Safe Browsing result if still valid."""
    record = safe_browsing_cache.get(url)
    if not record:
        return None

    if time.time() - record["ts"] > SAFE_BROWSING_CACHE_TTL_SECONDS:
        safe_browsing_cache.pop(url, None)
        return None

    return record["result"]


def _set_cached_safe_browsing_result(url, result):
    """Store Safe Browsing result in a short-lived cache."""
    safe_browsing_cache[url] = {
        "ts": time.time(),
        "result": result,
    }


def _check_google_safe_browsing(url):
    """Check URL reputation using Google Safe Browsing API.

    Returns a dictionary with status flags. If API key is unavailable
    or the request fails, malicious will remain False and source will
    indicate why.
    """
    normalized_url = _normalize_url(url)
    api_key = _get_safe_browsing_api_key()

    default_result = {
        "malicious": False,
        "threat_types": [],
        "source": "safe_browsing_unavailable",
    }

    if not normalized_url:
        return default_result

    cached = _get_cached_safe_browsing_result(normalized_url)
    if cached is not None:
        return cached

    if not api_key:
        _set_cached_safe_browsing_result(normalized_url, default_result)
        return default_result

    payload = {
        "client": {
            "clientId": "windows-phishguard",
            "clientVersion": "1.1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalized_url}],
        },
    }

    try:
        response = requests.post(
            f"{GOOGLE_SAFE_BROWSING_URL}?key={api_key}",
            json=payload,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json() if response.content else {}

        matches = data.get("matches", [])
        result = {
            "malicious": bool(matches),
            "threat_types": sorted(
                {item.get("threatType", "UNKNOWN") for item in matches}
            ),
            "source": "google_safe_browsing",
        }
        _set_cached_safe_browsing_result(normalized_url, result)
        return result

    except requests.RequestException as error:
        fallback = {
            "malicious": False,
            "threat_types": [],
            "source": f"safe_browsing_error: {error}",
        }
        _set_cached_safe_browsing_result(normalized_url, fallback)
        return fallback


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
    # Google Safe Browsing check first for real-time reputation verdict.
    safe_browsing_result = _check_google_safe_browsing(url)
    if safe_browsing_result["malicious"]:
        threat_types = ", ".join(safe_browsing_result["threat_types"]) or "UNKNOWN"
        print(f"[Google Safe Browsing] Threat detected: {threat_types}")
        return "PHISHING"

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
    print(f"[Safe Browsing] Source: {safe_browsing_result['source']}")
    
    # Final verdict: If either detects phishing, mark as phishing
    if result_rule == "PHISHING" or result_ml["label"] == "PHISHING":
        return "PHISHING"
    
    return "SAFE"
