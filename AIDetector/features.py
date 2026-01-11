import re

# ============================================
# Feature Extraction Constants
# ============================================
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'bank', 'secure']
SHORTENED_URL_SERVICES = ['bit.ly', 'tinyurl']
IP_PATTERN = r'\d+\.\d+\.\d+\.\d+'


def extract_features(url):
    """Extract 9 features from URL for ML classification.
    
    Features extracted:
    1. URL length: Phishing URLs often have unusual lengths
    2. Number of dots: Domain complexity indicator
    3. Number of dashes: Often used to disguise URLs
    4. @ symbol: Used in phishing to hide real domain
    5. HTTPS protocol: Legitimate sites use HTTPS
    6. IP address: Phishing often uses IP instead of domain
    7. Suspicious keywords: Common phishing words
    8. Query parameters: Phishing may have unusual params
    9. Shortened URLs: Often used to hide malicious URLs
    
    Args:
        url (str): URL to analyze
        
    Returns:
        list: Feature vector of 9 numeric values
    """
    url_lower = url.lower()
    
    features = [
        len(url),                                          # Feature 1: URL length
        url.count('.'),                                    # Feature 2: Number of dots
        url.count('-'),                                    # Feature 3: Number of dashes
        url.count('@'),                                    # Feature 4: @ symbol presence
        1 if url.startswith("https") else 0,              # Feature 5: HTTPS indicator
        1 if re.search(IP_PATTERN, url) else 0,           # Feature 6: IP address detection
        1 if any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS) else 0,  # Feature 7: Suspicious keywords
        url.count('?'),                                    # Feature 8: Query parameters
        1 if any(service in url_lower for service in SHORTENED_URL_SERVICES) else 0  # Feature 9: Shortened URL
    ]
    
    return features
