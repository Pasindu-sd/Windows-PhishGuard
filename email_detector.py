import re
from fuzzywuzzy import fuzz

SCORE_KEYWORD_MATCH = 1
SCORE_THRESHOLD_SUSPICIOUS = 2
FUZZY_MATCH_THRESHOLD = 80
UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000  # 24 hours

def check_phishing(email_content):
    suspicious_keywords = ['urgent', 'verify your account', 'password', 'bank', 'paypal', 'click here', 'limited time', 'winner', 'prize', 'account suspended']
    
    suspicious_links = re.findall(r'http[s]?://[^\s]+', email_content)
    
    score = 0
    
    for keyword in suspicious_keywords:
        if fuzz.partial_ratio(keyword.lower(), email_content.lower()) > FUZZY_MATCH_THRESHOLD:
            score += SCORE_KEYWORD_MATCH
    
    if suspicious_links:
        score += len(suspicious_links)
    
    if score == 0:
        return "safe email"
    elif score <= SCORE_THRESHOLD_SUSPICIOUS:
        return "A suspicious email"
    else:
        return "A dangerous email!"

if __name__ == "__main__":
    try:
        email_subject = input("Enter email subject: ").strip()
        email_message = input("Enter email message: ").strip()

        print(check_phishing(email_message))

    except KeyboardInterrupt:
        print("\nProgram stopped by user.")
    except (EOFError, RuntimeError) as e:
        print(f"Unexpected error: {e}")