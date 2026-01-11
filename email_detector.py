import re
from fuzzywuzzy import fuzz

URL_PATTERN = r'https?://[^\s]+'
SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify your account', 'password', 'bank', 'paypal',
    'click here', 'limited time', 'winner', 'prize', 'account suspended'
]
URGENT_WORDS = ['urgent', 'immediately', 'alert', 'verify now']
SUSPICIOUS_DOMAINS = ['.tk', '.ml']

FUZZY_MATCH_THRESHOLD = 80
SCORE_KEYWORD = 1
SCORE_LINK = 1
SCORE_THRESHOLD = 2

suspicious_keywords = SUSPICIOUS_KEYWORDS


def _extract_urls(text):
    """Extract URLs from text.
    
    Args:
        text (str): Text to search for URLs
        
    Returns:
        list: Found URLs
    """
    try:
        return re.findall(URL_PATTERN, text)
    except re.error:
        return []


def _check_keywords(content):
    """Check content for suspicious keywords using fuzzy matching.
    
    Args:
        content (str): Text to check
        
    Returns:
        int: Number of keyword matches found
    """
    score = 0
    content_lower = content.lower()
    
    for keyword in suspicious_keywords:
        if fuzz.partial_ratio(keyword, content_lower) > FUZZY_MATCH_THRESHOLD:
            score += SCORE_KEYWORD
    
    return score


def _check_suspicious_domains(text):
    """Check for suspicious domain patterns.
    
    Args:
        text (str): Text to check
        
    Returns:
        bool: True if suspicious domain found
    """
    text_lower = text.lower()
    return any(domain in text_lower for domain in SUSPICIOUS_DOMAINS)


def _check_prize_scam(content):
    """Detect common 'You won a prize' phishing scam.
    
    Args:
        content (str): Email content
        
    Returns:
        bool: True if prize scam pattern detected
    """
    content_lower = content.lower()
    return 'won' in content_lower and 'prize' in content_lower


def check_phishing(email_content):
    """Detect phishing in email content.
    
    This function analyzes email content for common phishing indicators:
    - Suspicious keywords (urgent, verify account, etc.)
    - URLs in content
    - Suspicious domain patterns (.tk, .ml)
    - Prize/prize scam patterns
    
    Args:
        email_content (str): Email content to analyze
        
    Returns:
        str: Risk assessment
            - "safe email": No threats detected
            - "A suspicious email": Minor threats (score 1-2)
            - "A dangerous email!": Multiple threats (score 3+)
    """
    if not email_content or not isinstance(email_content, str):
        return "safe email"
    
    score = 0
    
    score += _check_keywords(email_content)
    
    urls = _extract_urls(email_content)
    if urls:
        score += len(urls) * SCORE_LINK
    
    if _check_suspicious_domains(email_content):
        score += SCORE_KEYWORD
    
    if _check_prize_scam(email_content):
        score += SCORE_KEYWORD
    
    if score == 0:
        return "safe email"
    elif score <= SCORE_THRESHOLD:
        return "A suspicious email"
    else:
        return "A dangerous email!"


if __name__ == "__main__":
    try:
        email_subject = input("Enter email subject: ").strip()
        email_message = input("Enter email message: ").strip()
        
        full_content = f"{email_subject}\n{email_message}"
        result = check_phishing(full_content)
        
        print(f"\nAnalysis Result: {result}")

    except KeyboardInterrupt:
        print("\nProgram stopped by user.")
    except (EOFError, RuntimeError) as e:
        print(f"Unexpected error: {e}")