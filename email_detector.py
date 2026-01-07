import re
from fuzzywuzzy import fuzz

# Trusted sender domains (update with real trusted domains)
trusted_domains = ["paypal.com", "bank.com", "yourcompany.com"]

def calculate_score(subject, message, sender=None):
    score = 0
    
    # --- Suspicious Keywords ---
    keywords = ['urgent', 'verify your account', 'password', 'bank', 'paypal',
                'click here', 'limited time', 'winner', 'prize', 'account suspended']
    
    for kw in keywords:
        if fuzz.partial_ratio(kw.lower(), message.lower()) > 80:
            score += 1

    # --- URLs Analysis ---
    urls = re.findall(r'https?://[^\s]+', message)
    score += len(urls)  # +1 per URL
    for url in urls:
        if not url.startswith("https") or any(tld in url for tld in [".tk", ".ml"]):
            score += 1  # extra point for suspicious URL
    
    # --- Subject Urgent Words ---
    urgent_words = ["urgent", "immediately", "alert", "verify now"]
    for word in urgent_words:
        if word.lower() in subject.lower():
            score += 1

    # --- Sender Domain Check ---
    if sender:
        domain = sender.split("@")[-1]
        if domain not in trusted_domains:
            score += 2

    return score, urls

def check_email(subject, message, sender=None):
    try:
        score, urls = calculate_score(subject, message, sender)
        
        print(f"\nSubject: {subject}")
        print(f"Sender: {sender if sender else 'Unknown'}")
        print(f"Message: {message}\n")
        
        if urls:
            print("Found URLs in message:")
            for u in urls:
                print("  -", u)
        
        # --- Decision based on score ---
        if score >= 5:
            result = "⚠️ Dangerous Email!"
        elif score >= 3:
            result = "⚠️ Suspicious Email"
        else:
            result = "✅ Safe Email"
        
        print(f"\nResult: {result} (Score: {score})")
        return result

    except Exception as e:
        print(f"\nError occurred: {e}")
        return "Error"

# --- Run Example ---
if __name__ == "__main__":
    try:
        subject = input("Enter email subject: ").strip()
        message = input("Enter email message: ").strip()
        sender = input("Enter sender email (optional): ").strip() or None

        check_email(subject, message, sender)

    except KeyboardInterrupt:
        print("\nProgram stopped by user.")
