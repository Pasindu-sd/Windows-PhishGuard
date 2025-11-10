# detectors/email_detector.py
"""
Simple email phishing heuristics module.
Provides:
 - analyze_email_text(subject: str, message: str) -> dict
 - check_email_cli() : small CLI to test quickly
"""

import re
from typing import List, Dict

# simple keyword lists (you can expand)
URGENT_WORDS = ["urgent", "immediately", "alert", "verify now"]
SUSPICIOUS_EXTS = [".tk", ".ml", ".ga", ".cf", ".gq"]  # common free/takeover TLDs (example)
PRIZE_KEYWORDS = ["won", "prize", "congratulations", "congrats", "you've won"]

URL_REGEX = re.compile(
    r'https?://[^\s\'"<>]+', re.IGNORECASE
)

def _safe_lower(s: str) -> str:
    return s.lower() if s else ""

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return URL_REGEX.findall(text)

def analyze_email_text(subject: str, message: str) -> Dict:
    """
    Analyze subject + message and return structured result:
    {
      "score": float (0.0 - 1.0),
      "flags": [str],
      "explain": str,
      "evidence": {"urls": [...], "matched_keywords": [...]}
    }
    """
    try:
        subject_l = _safe_lower(subject)
        message_l = _safe_lower(message)

        flags = []
        matched_keywords = []

        score = 0.0

        # Urgent words in subject
        for w in URGENT_WORDS:
            if w in subject_l:
                flags.append(f"urgent_subject:{w}")
                matched_keywords.append(w)
                score += 0.15

        # Password request in message
        if "password" in message_l:
            flags.append("asks_for_password")
            matched_keywords.append("password")
            score += 0.25

        # Suspicious domain extensions in message (simple heuristic)
        for ext in SUSPICIOUS_EXTS:
            if ext in message_l:
                flags.append(f"suspicious_ext:{ext}")
                matched_keywords.append(ext)
                score += 0.1

        # Prize scam pattern (both words present)
        for pk in PRIZE_KEYWORDS:
            if pk in message_l:
                matched_keywords.append(pk)
        # if at least one prize word + 'won' present -> raise
        if "won" in message_l and any(k in message_l for k in PRIZE_KEYWORDS):
            flags.append("prize_scam_pattern")
            score += 0.2

        # Extract URLs
        urls = extract_urls(message)
        if urls:
            flags.append(f"has_urls:{len(urls)}")
            score += 0.15
            # optionally check each url host for suspicious TLDs / shorteners, more heuristics
            # keep evidence
        # cap score
        score = min(1.0, score)

        explain = []
        if flags:
            explain.append(f"Flags: {', '.join(flags)}")
        else:
            explain.append("No obvious heuristic flags found.")

        explain.append(f"Matched keywords: {', '.join(matched_keywords)}" if matched_keywords else "")
        explain_text = " | ".join([e for e in explain if e])

        return {
            "score": score,
            "flags": flags,
            "explain": explain_text,
            "evidence": {
                "urls": urls,
                "subject": subject or "",
            }
        }

    except Exception as e:
        # never crash the caller; return safe default
        return {
            "score": 0.0,
            "flags": ["error_analyzing"],
            "explain": f"Error during analysis: {e}",
            "evidence": {}
        }

# backward-compatible wrapper for your original function name
def check_email(subject: str, message: str) -> List[str]:
    """
    Returns list of textual problem descriptions (for quick CLI compatibility).
    """
    result = analyze_email_text(subject, message)
    # convert flags -> human readable list
    problems = []
    if result.get("flags"):
        for f in result["flags"]:
            problems.append(f)
    return problems


# small CLI helper for quick manual testing
def check_email_cli():
    try:
        subject = input("Enter subject: ").strip()
        message = input("Enter message: ").strip()
        res = analyze_email_text(subject, message)
        print("\n=== Analysis ===")
        print("Score:", res["score"])
        print("Flags:", res["flags"])
        print("Explain:", res["explain"])
        if res["evidence"]["urls"]:
            print("URLs found:")
            for u in res["evidence"]["urls"]:
                print(" -", u)
    except KeyboardInterrupt:
        print("\nStopped by user.")


if __name__ == "__main__":
    check_email_cli()
