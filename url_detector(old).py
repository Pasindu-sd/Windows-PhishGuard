import pickle
import re
import socket
import ssl
import datetime
import requests
import argparse
from datetime import datetime, timezone
from AI_Detector.features import extract_features

def check_url(url):
    
    suspicious_patterns = [
        r'bit\.ly', r'tinyurl\.com', r'goo\.gl',  # Short URLs
        r'login', r'verify', r'account',          # Suspicious words
        r'\d+\.\d+\.\d+\.\d+',                    # IP addresses
    ]
    
    score = 0
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            score += 1
    
    if len(url) > 75:
        score += 1
    
    if '@' in url:
        score += 2
    
    if score == 0:
        return "safe URL"
    elif score <= 2:
        return "A suspicious URL"
    else:
        return "A dangerous URL!"

def get_domain(url):
    url = url.lower().strip()
    url = re.sub(r"^https?://", "", url)
    domain = url.split('/')[0].split(':')[0]
    return domain

def has_ssl_cert(domain, timeout=5):
    """Try to fetch SSL certificate from port 443.
       Returns certificate 'notAfter' string if found, else None."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, 443))
            cert = s.getpeercert()
        not_after = cert.get("notAfter")
        if not_after:
            return not_after
    except Exception:
        return None

def simple_check(url):
    print(f"Analyzing: {url}")
    issues = []

    if len(url) > 75:
        issues.append("URL too long")
    if url.count('-') > 3:
        issues.append("Many hyphens")
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        issues.append("Contains raw IP address")
    fake_brands = ['paypal', 'facebook', 'google', 'microsoft', 'bank', 'apple', 'amazon']
    for b in fake_brands:
        if b in url.lower() and '-' in url:
            issues.append(f"Suspicious brand pattern: {b}")

    domain = get_domain(url)
    print(f"Extracted Domain: {domain}")
    
    try:
        ip = socket.gethostbyname(domain)
        print("Resolved IP:", ip)
        if ip.startswith(("10.","172.","192.168.")):
            issues.append("Resolves to private IP")
    except socket.gaierror:
        issues.append("DNS resolution failed (invalid or dead domain)")
    except Exception as e:
        issues.append(f"DNS error: {e}")

    cert_expiry = has_ssl_cert(domain)
    if cert_expiry:
        print("SSL certificate found")
        print("   Expires on:", cert_expiry)
        try:
            expiry_dt = datetime.strptime(cert_expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry_dt - datetime.now(timezone.utc)).days
            if days_left < 0:
                issues.append("SSL certificate expired")
            elif days_left < 30:
                issues.append("SSL certificate expires soon (<30 days)")
        except Exception:
            pass
    else:
        issues.append("No SSL certificate or failed to fetch it")
    
    try:
        r = requests.head(url, timeout=5, allow_redirects=True)
        if r.status_code >= 400:
            issues.append(f"HTTP returned error status: {r.status_code}")
        elif 'login' in r.url or 'verify' in r.url:
            issues.append("Redirects to suspicious login/verify page")
    except requests.exceptions.SSLError:
        issues.append("SSL/TLS error while connecting")
    except requests.exceptions.RequestException:
        issues.append("Could not connect to website")
        
    if issues:
        print("\nPossible Problems Found:")
        for it in issues:
            print(" -", it)
    else:
        print("\nNo suspicious signs detected (basic checks only)")

    return issues


def main():
    parser = argparse.ArgumentParser(description="Simple URL Phishing Detector by Pasindu")
    parser.add_argument("url", nargs="?", help="Enter a URL to analyze (e.g., https://example.com)")
    args = parser.parse_args()

    if not args.url:
        url = input("Enter URL: ").strip()
    else:
        url = args.url.strip()

    simple_check(url)


if __name__ == "__main__":
    main()