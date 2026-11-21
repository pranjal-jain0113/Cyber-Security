"""Module 1 - URL Heuristic Analyzer.

Pure static string analysis. Each check returns a Finding (or nothing) so the
risk engine can show *why* a URL was flagged.
"""
import re
from typing import List

import config
from analyzers.models import Finding, ParsedURL

M = "heuristics"


def check_ip_address(p: ParsedURL) -> List[Finding]:
    if p.is_ip:
        return [Finding(M, "ip_address", "IP address used instead of a domain",
                        "Legitimate brands use registered domain names. Attackers often "
                        "host phishing pages on raw IPs to avoid domain registration.",
                        25, "high")]
    return []


def check_at_symbol(p: ParsedURL) -> List[Finding]:
    if p.userinfo or "@" in p.path or "@" in p.query:
        return [Finding(M, "at_symbol", "'@' symbol in URL",
                        "Browsers ignore everything before '@' in the address, so "
                        "'http://google.com@evil.com' actually opens evil.com.",
                        20, "high")]
    return []


def check_subdomains(p: ParsedURL) -> List[Finding]:
    n = len(p.subdomain_labels)
    if n > config.MAX_SAFE_SUBDOMAINS:
        return [Finding(M, "excessive_subdomains", f"Excessive subdomains ({n})",
                        "Long subdomain chains (e.g. secure.login.bank.evil.com) are used "
                        "to push a trusted-looking name to the left and hide the real domain.",
                        10 + min(10, (n - config.MAX_SAFE_SUBDOMAINS) * 5), "medium")]
    return []


def check_keywords(p: ParsedURL) -> List[Finding]:
    haystack = f"{p.host}{p.path}?{p.query}".lower()
    hits = sorted({k for k in config.SUSPICIOUS_KEYWORDS if k in haystack})
    if not hits:
        return []
    pts = min(25, 8 + 5 * len(hits))
    return [Finding(M, "suspicious_keywords",
                    f"Suspicious keywords: {', '.join(hits)}",
                    "Phishing links commonly use urgency or account-related words to "
                    "trick users into entering credentials or OTPs.",
                    pts, "medium" if len(hits) < 3 else "high")]


def check_shortener(p: ParsedURL) -> List[Finding]:
    if p.registered_domain in config.URL_SHORTENERS:
        return [Finding(M, "url_shortener", f"URL shortener ({p.registered_domain})",
                        "Shorteners hide the real destination. The final target cannot "
                        "be verified without visiting it, which PhishGuard never does.",
                        15, "medium")]
    return []


def check_no_https(p: ParsedURL) -> List[Finding]:
    if p.scheme != "https":
        return [Finding(M, "no_https", "Connection is not HTTPS",
                        "Credentials sent over plain HTTP can be intercepted. Banks and "
                        "major brands always use HTTPS.", 10, "medium")]
    return []


def check_length(p: ParsedURL) -> List[Finding]:
    if len(p.normalized) > config.LONG_URL_THRESHOLD:
        return [Finding(M, "long_url", f"Very long URL ({len(p.normalized)} chars)",
                        "Long URLs can bury the real domain or hide malicious parameters.",
                        5, "low")]
    return []


def check_punycode(p: ParsedURL) -> List[Finding]:
    if any(label.startswith("xn--") for label in p.host.split(".")):
        return [Finding(M, "punycode", "Punycode / internationalised domain",
                        "'xn--' domains can show look-alike Unicode characters "
                        "(homograph attack), e.g. a Cyrillic 'a' that looks like Latin 'a'.",
                        20, "high")]
    return []


def check_hyphens(p: ParsedURL) -> List[Finding]:
    n = p.domain.count("-")
    if n > config.MAX_SAFE_HYPHENS:
        return [Finding(M, "many_hyphens", f"Many hyphens in domain ({n})",
                        "Domains like 'secure-sbi-login-update.com' are typical of "
                        "throwaway phishing registrations.", 8, "low")]
    return []


def check_risky_tld(p: ParsedURL) -> List[Finding]:
    tld = p.suffix.rsplit(".", 1)[-1] if p.suffix else ""
    if tld in config.RISKY_TLDS:
        return [Finding(M, "risky_tld", f"Frequently abused TLD (.{tld})",
                        "Cheap/free TLDs are over-represented in phishing campaigns. "
                        "This is a weak signal on its own.", 8, "low")]
    return []


def check_port(p: ParsedURL) -> List[Finding]:
    if p.port and p.port not in (80, 443):
        return [Finding(M, "odd_port", f"Non-standard port ({p.port})",
                        "Legitimate sites rarely serve login pages on unusual ports.",
                        8, "low")]
    return []


def check_embedded_url(p: ParsedURL) -> List[Finding]:
    tail = f"{p.path}?{p.query}".lower()
    if re.search(r"https?(://|%3a%2f%2f)", tail):
        return [Finding(M, "embedded_url", "Another URL embedded in the path/query",
                        "Open-redirect style links ('?url=http://...') are used to "
                        "launder malicious destinations behind a trusted domain.",
                        12, "medium")]
    return []


_CHECKS = [
    check_ip_address, check_at_symbol, check_subdomains, check_keywords,
    check_shortener, check_no_https, check_length, check_punycode,
    check_hyphens, check_risky_tld, check_port, check_embedded_url,
]


def analyze_heuristics(parsed: ParsedURL) -> List[Finding]:
    """Run every heuristic check and return the flags raised."""
    findings: List[Finding] = []
    for check in _CHECKS:
        findings.extend(check(parsed))
    return findings
