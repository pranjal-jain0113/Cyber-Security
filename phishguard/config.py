"""Central configuration: weights, keyword lists, thresholds.
Keeping these in one place makes the scoring explainable in a viva."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
BRANDS_FILE = BASE_DIR / "data" / "brands.json"

MAX_URL_LENGTH = 2048          # reject absurd input early

# ---- Heuristic thresholds -------------------------------------------------
LONG_URL_THRESHOLD = 75
MAX_SAFE_SUBDOMAINS = 2        # more than this => "excessive subdomains"
MAX_SAFE_HYPHENS = 2           # hyphens in registered-domain label

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "log-in", "verify", "verification", "update-kyc", "kyc",
    "secure", "account", "banking", "netbanking", "upi", "otp", "password",
    "passwd", "confirm", "suspend", "unlock", "wallet", "reward", "refund",
    "billing", "invoice", "validate", "authenticate", "credential",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "shorturl.at", "tiny.cc", "buff.ly", "rebrand.ly", "t.ly",
    "bl.ink", "s.id", "v.gd",
}

# TLDs heavily abused for throwaway phishing domains (not proof, just signal)
RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work",
    "support", "zip", "mov", "icu", "buzz", "rest", "country", "cam",
}

# ---- Typosquatting thresholds --------------------------------------------
# Max allowed edit distance by brand-name length (short brands must match
# exactly, otherwise "sbi" would "match" half the dictionary).
def max_edit_distance(brand_len: int) -> int:
    if brand_len <= 4:
        return 0
    if brand_len <= 7:
        return 1
    return 2
