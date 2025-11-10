# detectors/url_detector.py
"""
Simple URL phishing heuristics module.
Provides:
 - analyze_url(url: str) -> dict
 - simple_check_cli() : small CLI to test quickly
"""
import re
import socket
import ssl
from datetime import datetime, timezone
import requests
from typing import List, Dict, Optional

URL_REGEX = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
FAKE_BRANDS = ['paypal', 'facebook', 'google', 'microsoft', 'bank', 'apple', 'amazon']
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq']  # example list

def get_domain(url: str) -> str:
    if not url:
        return ""
    u = url.lower().strip()
    u = re.sub(r"^https?://", "", u)
    domain = u.split('/')[0].split(':')[0]
    return domain

def has_ssl_cert(domain: str, timeout: int = 5) -> Optional[str]:
    """Return certificate notAfter string if available, else None"""
    if not domain:
        return None
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, 443))
            cert = s.getpeercert()
        return cert.get("notAfter")
    except Exception:
        return None

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return URL_REGEX.findall(text)

def analyze_url(url: str) -> Dict:
    """
    Analyze a single URL and return structured dict:
    {
      "url": str,
      "domain": str,
      "score": 0.0-1.0,
      "flags": [...],
      "explain": "human readable",
      "evidence": {...}
    }
    """
    flags: List[str] = []
    evidence: Dict = {"resolved_ip": None, "cert_notAfter": None}
    score = 0.0

    if not url:
        return {"url": url, "domain": "", "score": 0.0, "flags": ["invalid_url"], "explain": "Empty URL", "evidence": evidence}

    # basic heuristics
    if len(url) > 75:
        flags.append("url_too_long")
        score += 0.1
    if url.count('-') > 3:
        flags.append("many_hyphens")
        score += 0.05
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        flags.append("contains_ip")
        score += 0.1
    # fake brand + hyphen pattern
    for b in FAKE_BRANDS:
        if b in url.lower() and '-' in url:
            flags.append(f"suspicious_brand_pattern:{b}")
            score += 0.1

    # suspicious tld in url
    for tld in SUSPICIOUS_TLDS:
        if tld in url.lower():
            flags.append(f"suspicious_tld:{tld}")
            score += 0.08

    domain = get_domain(url)
    # DNS resolution
    try:
        ip = socket.gethostbyname(domain) if domain else None
        evidence["resolved_ip"] = ip
        if ip and (ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168.")):
            flags.append("resolves_to_private_ip")
            score += 0.2
    except socket.gaierror:
        flags.append("dns_resolution_failed")
        score += 0.2
    except Exception as e:
        flags.append(f"dns_error:{str(e)}")

    # SSL certificate
    cert_expiry = None
    try:
        cert_expiry = has_ssl_cert(domain)
        evidence["cert_notAfter"] = cert_expiry
        if cert_expiry:
            # try parse e.g. "Jun  1 12:00:00 2025 GMT"
            try:
                expiry_dt = datetime.strptime(cert_expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry_dt - datetime.now(timezone.utc)).days
                if days_left < 0:
                    flags.append("ssl_expired")
                    score += 0.2
                elif days_left < 30:
                    flags.append("ssl_expires_soon")
                    score += 0.1
            except Exception:
                # if parse fails, do not crash; keep cert string for evidence
                pass
        else:
            flags.append("no_ssl_or_fetch_failed")
            score += 0.15
    except Exception:
        flags.append("ssl_check_error")

    # HTTP HEAD check (status + redirect)
    try:
        r = requests.head(url, timeout=6, allow_redirects=True)
        if r.status_code >= 400:
            flags.append(f"http_error_status:{r.status_code}")
            score += 0.1
        # suspicious redirect URL detection
        final_url = r.url.lower() if r.url else ""
        if 'login' in final_url or 'verify' in final_url:
            flags.append("redirects_to_login_or_verify")
            score += 0.15
        evidence["final_url"] = final_url
        evidence["http_status"] = r.status_code
    except requests.exceptions.SSLError:
        flags.append("requests_ssl_error")
        score += 0.1
    except requests.exceptions.RequestException:
        flags.append("http_request_failed")
        score += 0.1

    # cap score
    score = min(1.0, score)

    explain = " | ".join(flags) if flags else "No obvious heuristic flags found."

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "flags": flags,
        "explain": explain,
        "evidence": evidence
    }

# small CLI for manual testing
def simple_check_cli():
    try:
        import argparse
        parser = argparse.ArgumentParser(description="Simple URL Phishing Detector (CLI)")
        parser.add_argument("url", nargs="?", help="URL to analyze")
        args = parser.parse_args()
        if args.url:
            u = args.url
        else:
            u = input("Enter URL: ").strip()
        res = analyze_url(u)
        print("\n=== Analysis ===")
        print("URL:", res["url"])
        print("Domain:", res["domain"])
        print("Score:", res["score"])
        print("Flags:", res["flags"])
        print("Evidence:", res["evidence"])
    except KeyboardInterrupt:
        print("\nStopped by user.")

if __name__ == "__main__":
    simple_check_cli()
