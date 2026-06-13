import re
from email.utils import parseaddr
from fuzzywuzzy import fuzz

# URL detection pattern
URL_PATTERN = r'https?://[^\s]+'

# Keywords for phishing detection
STRONG_KEYWORDS = [
    "verify your account",
    "account suspended",
    "click here immediately",
    "confirm your password"
]

# Allows runtime update from phishing_rules.json in main.py
suspicious_keywords = list(STRONG_KEYWORDS)

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
SCORE_STRONG_KEYWORD = 3
SCORE_SOFT_KEYWORD = 2
SCORE_LINK = 2
SCORE_URGENCY_LINK = 3
SCORE_SUSPICIOUS_DOMAIN = 2
SCORE_PRIZE_SCAM = 2

SCORE_THRESHOLD_LOW = 1
SCORE_THRESHOLD_MEDIUM = 5

SPOOF_SCORE_DOMAIN_MISMATCH = 4
SPOOF_SCORE_AUTH_FAIL = 5
SPOOF_SCORE_IMPERSONATION = 3
SPOOF_SCORE_REPLYTO_MISMATCH = 2

TRUSTED_BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "github": "github.com",
    "bank": "",
}

# Helper: check if URL is safe
def _is_safe_domain(url):
    return any(url.startswith("https://" + d) or d in url for d in SAFE_DOMAINS)

# Helper: extract URLs from text
def _extract_urls(text):
    try:
        return re.findall(URL_PATTERN, text)
    except re.error:
        return []

# Helper: keyword scoring
def _check_keywords(content):
    content = content.lower()
    score = 0
    for word in suspicious_keywords:
        if fuzz.partial_ratio(word, content) > FUZZY_MATCH_THRESHOLD:
            score += SCORE_STRONG_KEYWORD
    soft_hits = sum(1 for w in SOFT_KEYWORDS if w in content)
    if soft_hits >= 2:
        score += SCORE_SOFT_KEYWORD
    return score

# Helper: suspicious domain scoring
def _check_suspicious_domains(text):
    text_lower = text.lower()
    return any(domain in text_lower for domain in SUSPICIOUS_DOMAINS)

# Helper: prize scam scoring
def _check_prize_scam(content):
    content_lower = content.lower()
    return 'won' in content_lower and 'prize' in content_lower

# Helper: urgency + link scoring
def _urgency_with_link(content):
    content_lower = content.lower()
    urls = _extract_urls(content_lower)
    if urls and any(word in content_lower for word in URGENT_WORDS):
        return SCORE_URGENCY_LINK
    return 0


def _extract_domain_from_address(address_value):
    """Extract sender domain from header values like Name <user@example.com>."""
    _, address = parseaddr(address_value or "")
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].lower().strip()


def _extract_domain_from_received_line(received_line):
    """Extract domain from first Received header line if possible."""
    if not received_line:
        return ""

    match = re.search(r"from\s+([a-zA-Z0-9.-]+)", received_line, flags=re.IGNORECASE)
    if not match:
        return ""

    domain = match.group(1).lower().strip(";)")
    return domain


def _shared_root_domain(domain_a, domain_b):
    """Return True if domains share same 2-label root (lightweight heuristic)."""
    if not domain_a or not domain_b:
        return False

    parts_a = domain_a.split(".")
    parts_b = domain_b.split(".")
    if len(parts_a) < 2 or len(parts_b) < 2:
        return domain_a == domain_b

    root_a = ".".join(parts_a[-2:])
    root_b = ".".join(parts_b[-2:])
    return root_a == root_b


def analyze_email_headers(header_data):
    """Analyze email headers for spoofing indicators.

    Args:
        header_data (dict | str): Header map or raw header text.

    Returns:
        dict: {score, severity, reasons}
    """
    if isinstance(header_data, str):
        headers = {}
        for line in header_data.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
    elif isinstance(header_data, dict):
        headers = {str(k): str(v) for k, v in header_data.items()}
    else:
        return {"score": 0, "severity": "safe", "reasons": []}

    score = 0
    reasons = []

    from_domain = _extract_domain_from_address(headers.get("From", ""))
    reply_to_domain = _extract_domain_from_address(headers.get("Reply-To", ""))
    return_path_domain = _extract_domain_from_address(headers.get("Return-Path", ""))

    auth_results = headers.get("Authentication-Results", "").lower()
    received_domain = _extract_domain_from_received_line(headers.get("Received", ""))

    if from_domain and return_path_domain and not _shared_root_domain(from_domain, return_path_domain):
        score += SPOOF_SCORE_DOMAIN_MISMATCH
        reasons.append("From and Return-Path domains do not match")

    if from_domain and received_domain and not _shared_root_domain(from_domain, received_domain):
        score += SPOOF_SCORE_REPLYTO_MISMATCH
        reasons.append("From domain does not match Received path")

    if reply_to_domain and from_domain and not _shared_root_domain(reply_to_domain, from_domain):
        score += SPOOF_SCORE_REPLYTO_MISMATCH
        reasons.append("Reply-To domain differs from sender domain")

    if auth_results:
        has_auth_failure = any(flag in auth_results for flag in ["spf=fail", "dkim=fail", "dmarc=fail"])
        if has_auth_failure:
            score += SPOOF_SCORE_AUTH_FAIL
            reasons.append("SPF/DKIM/DMARC authentication failure found")

    from_header = headers.get("From", "").lower()
    if from_domain:
        for brand, expected_domain in TRUSTED_BRAND_DOMAINS.items():
            if brand in from_header and expected_domain and expected_domain not in from_domain:
                score += SPOOF_SCORE_IMPERSONATION
                reasons.append(f"Possible {brand.title()} impersonation in From header")
                break

    if score == 0:
        severity = "safe"
    elif score <= 3:
        severity = "suspicious"
    else:
        severity = "dangerous"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons,
    }

# Main phishing check
def check_phishing(email_content, headers=None):
    if not email_content or not isinstance(email_content, str):
        return "safe"

    score = 0
    score += _check_keywords(email_content)

    urls = _extract_urls(email_content)
    for url in urls:
        if _is_safe_domain(url):
            score -= 1  # slight deduction for known safe URLs
        else:
            score += SCORE_LINK

    score += _urgency_with_link(email_content)

    if _check_suspicious_domains(email_content):
        score += SCORE_SUSPICIOUS_DOMAIN

    if _check_prize_scam(email_content):
        score += SCORE_PRIZE_SCAM

    header_result = analyze_email_headers(headers or {})
    score += header_result["score"]

    if score < 0:
        score = 0

    if score <= SCORE_THRESHOLD_LOW and header_result["severity"] == "safe":
        return "safe"
    elif score <= SCORE_THRESHOLD_MEDIUM:
        return "suspicious"
    else:
        return "dangerous"

"""
# Usage example:
if __name__ == "__main__":
    subject = input("Enter email subject: ").strip()
    message = input("Enter email message: ").strip()
    full_content = f"{subject}\n{message}"
    result = check_phishing(full_content)
    print("Email result:", result)
"""
