import re
from fuzzywuzzy import fuzz

def check_phishing(email_content):
    suspicious_keywords = ['urgent', 'verify your account', 'password', 'bank', 'paypal', 'click here', 'limited time', 'winner', 'prize', 'account suspended']
    
    suspicious_links = re.findall(r'http[s]?://[^\s]+', email_content)
    
    score = 0
    
    for keyword in suspicious_keywords:
        if fuzz.partial_ratio(keyword.lower(), email_content.lower()) > 80:
            score += 1
    
    if suspicious_links:
        score += len(suspicious_links)
    
    if score == 0:
        return "safe email"
    elif score <= 2:
        return "A suspicious email"
    else:
        return "A dangerous email!"

def check_email(subject, message):
    try:
        print(f"\n Subject: {subject}")
        print(f"Message: {message} \n")
        problem = []
        
        subject_lower = subject.lower() if subject else ""
        message_lower = message.lower() if message else ""

        urgent_words = ["urgent", "immediately", "alert", "verify now"]
        for word in urgent_words:
            if word in subject_lower:
                problem.append(f"Urgent Word: {word}")

        if "password" in message_lower:
            problem.append("Asking for password")

        if ".tk" in message_lower or ".ml" in message_lower:
            problem.append("Suspicious website link")

        if "won" in message_lower and "prize" in message_lower:
            problem.append("'You won a prize' - common scam")

        try:
            urls = re.findall(r'https?://[^\s]+', message)
            if urls:
                print("Found URLs in message:")
                for u in urls:
                    print("   -", u)
                problem.append(f"{len(urls)} URL(s) detected in message")
        except re.error:
            print("Regex error while searching URLs")

        if problem:
            print("\nPotential Issues Found:")
            for prob in problem:
                print(f" - {prob}")
        else:
            print("Email looks safe!")

        return problem

    except (AttributeError, TypeError, ValueError) as e:
        print(f"\nError occurred while checking email: {e}")
        return []


if __name__ == "__main__":
    try:
        email_subject = input("Enter email subject: ").strip()
        email_message = input("Enter email message: ").strip()

        check_email(email_subject, email_message)

    except KeyboardInterrupt:
        print("\nProgram stopped by user.")
    except (EOFError, RuntimeError) as e:
        print(f"Unexpected error: {e}")