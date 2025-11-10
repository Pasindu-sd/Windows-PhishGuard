import re

def check_email(subject, message):
    try:
        print(f"\n Subject: {subject}")
        print(f"Message: {message} \n")
        problem = []
        
        # Convert to lowercase safely
        subject_lower = subject.lower() if subject else ""
        message_lower = message.lower() if message else ""

        # Check for urgent words
        urgent_words = ["urgent", "immediately", "alert", "verify now"]
        for word in urgent_words:
            if word in subject_lower:
                problem.append(f"Urgent Word: {word}")

        # Check for password requests
        if "password" in message_lower:
            problem.append("Asking for password")

        # Check for suspicious domain extensions
        if ".tk" in message_lower or ".ml" in message_lower:
            problem.append("Suspicious website link")

        # Common prize scam words
        if "won" in message_lower and "prize" in message_lower:
            problem.append("'You won a prize' - common scam")

        # Extract all URLs from the message safely
        try:
            urls = re.findall(r'https?://[^\s]+', message)
            if urls:
                print("Found URLs in message:")
                for u in urls:
                    print("   -", u)
                problem.append(f"{len(urls)} URL(s) detected in message")
        except re.error:
            print("Regex error while searching URLs")

        # Final report
        if problem:
            print("\nPotential Issues Found:")
            for prob in problem:
                print(f" - {prob}")
        else:
            print("Email looks safe!")

        return problem

    except Exception as e:
        print(f"\nError occurred while checking email: {e}")
        return []


if __name__ == "__main__":
    try:
        email_subject = input("Enter email subject: ").strip()
        email_message = input("Enter email message: ").strip()

        check_email(email_subject, email_message)

    except KeyboardInterrupt:
        print("\nProgram stopped by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")