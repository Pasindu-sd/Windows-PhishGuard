import re
from fuzzywuzzy import fuzz

URL_PATTERN = r'https?://[^\s]+'

STRONG_KEYWORDS = [
    "verify your account",
    "account suspended",
    "click here immediately",
    "confirm your password"
]

SOFT_KEYWORDS = [
    "bank", "paypal", "password", "login"
]

URGENT_WORDS = ['urgent', 'immediately', 'alert', 'verify now']

SUSPICIOUS_DOMAINS = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']

SAFE_DOMAINS = [
    "google.com", "github.com", "microsoft.com",
    "amazon.com", "paypal.com"
]

FUZZY_MATCH_THRESHOLD = 80
SCORE_KEYWORD = 2
SCORE_LINK = 2
SCORE_THRESHOLD_LOW = 1
SCORE_THRESHOLD_MEDIUM = 5


def _is_safe_domain(url):
    return any(url.startswith("https://" + d) or d in url for d in SAFE_DOMAINS)

def _extract_urls(text):
    try:
        return re.findall(URL_PATTERN, text)
    except re.error:
        return []

def _check_keywords(content):
    content = content.lower()
    score = 0

    for word in STRONG_KEYWORDS:
        if fuzz.partial_ratio(word, content) > FUZZY_MATCH_THRESHOLD:
            score += 3

    soft_hits = sum(1 for w in SOFT_KEYWORDS if w in content)
    if soft_hits >= 2:
        score += 2

    return score

def _check_suspicious_domains(text):
    text_lower = text.lower()
    return any(domain in text_lower for domain in SUSPICIOUS_DOMAINS)

def _check_prize_scam(content):
    content_lower = content.lower()
    return 'won' in content_lower and 'prize' in content_lower

def _urgency_with_link(content):
    content_lower = content.lower()
    urls = _extract_urls(content_lower)
    if urls and any(word in content_lower for word in URGENT_WORDS):
        return 3
    return 0


def check_phishing(email_content):
    if not email_content or not isinstance(email_content, str):
        return "safe email"

    score = 0

    score += _check_keywords(email_content)

    urls = _extract_urls(email_content)
    for url in urls:
        if _is_safe_domain(url):
            score -= 2  
        else:
            score += SCORE_LINK 

    score += _urgency_with_link(email_content)

    if _check_suspicious_domains(email_content):
        score += SCORE_KEYWORD

    if _check_prize_scam(email_content):
        score += SCORE_KEYWORD

    if score < 0:
        score = 0

    if score <= SCORE_THRESHOLD_LOW:
        return "safe email"
    elif score <= SCORE_THRESHOLD_MEDIUM:
        return "suspicious email"
    else:
        return "dangerous email"

"""
if __name__ == "__main__":
    subject = input("Enter email subject: ").strip()
    message = input("Enter email message: ").strip()
    full_content = f"{subject}\n{message}"
    result = check_phishing(full_content)
    print("Email analysis result:", result)
"""
