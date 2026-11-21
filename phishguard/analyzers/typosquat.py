"""Module 2 - Typosquatting & Brand Impersonation Detector.

Uses Levenshtein edit distance (implemented from scratch, no dependency) plus
look-alike character normalisation (g00gle -> google, rnicrosoft -> microsoft).
"""
import json
import re
from functools import lru_cache
from typing import Dict, List, Set

import config
from analyzers.models import Finding, ParsedURL

M = "typosquat"

# Characters attackers swap in to imitate letters.
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                       "7": "t", "8": "b", "$": "s", "@": "a", "!": "i"})
# Common Cyrillic/Greek look-alikes -> Latin (for decoded IDN hosts)
_CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
                              "х": "x", "у": "y", "і": "i", "ѕ": "s", "ο": "o",
                              "ν": "v", "ρ": "p"})
_MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d")]


def levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming edit distance (insert/delete/substitute)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1,            # deletion
                           cur[j - 1] + 1,         # insertion
                           prev[j - 1] + (ca != cb)))  # substitution
        prev = cur
    return prev[-1]


@lru_cache(maxsize=1)
def load_brands() -> Dict[str, List[str]]:
    with open(config.BRANDS_FILE, encoding="utf-8") as f:
        return json.load(f)


def _variants(token: str) -> Set[str]:
    """Return the token plus de-obfuscated forms to compare against brands."""
    t = token.translate(_CONFUSABLES)
    out = {t, t.translate(_LEET)}
    for src, dst in _MULTI:
        out |= {v.replace(src, dst) for v in list(out)}
    return out


def _decode_host(host: str) -> str:
    """Decode punycode labels so homograph domains are compared as Unicode."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def _tokens(label: str) -> Set[str]:
    """Whole label + each hyphen/underscore-separated chunk (len >= 3)."""
    chunks = {c for c in re.split(r"[-_.]", label) if len(c) >= 3}
    return chunks | {label}


def analyze_typosquat(parsed: ParsedURL) -> List[Finding]:
    if parsed.is_ip:
        return []

    brands = load_brands()
    official: Set[str] = {d for doms in brands.values() for d in doms}
    reg = parsed.registered_domain
    if reg in official:
        return []                                   # genuine brand domain

    decoded_host = _decode_host(parsed.host)
    # Re-split decoded host so Unicode look-alikes are checked as text.
    label = parsed.domain
    if decoded_host != parsed.host:
        label = decoded_host.rsplit(".", 2)[-2] if "." in decoded_host else decoded_host

    findings: Dict[str, Finding] = {}

    def add(brand: str, f: Finding) -> None:
        # keep only the strongest finding per brand
        if brand not in findings or f.points > findings[brand].points:
            findings[brand] = f

    # 1) Typosquat / look-alike on the registered-domain label and its chunks
    for token in _tokens(label):
        for brand in brands:
            limit = config.max_edit_distance(len(brand))
            for v in _variants(token):
                d = levenshtein(v, brand)
                if d > limit:
                    continue
                if token == brand and d == 0:
                    continue                      # handled by brand-in-domain below
                if v == brand and token != brand:
                    add(brand, Finding(
                        M, "lookalike_chars", f"Look-alike of '{brand}': '{token}'",
                        f"'{token}' swaps characters (e.g. 0 for o, 1 for l, rn for m) "
                        f"to imitate '{brand}'. Genuine domains: "
                        f"{', '.join(brands[brand][:2])}.", 35, "high"))
                elif 0 < d <= limit:
                    add(brand, Finding(
                        M, "typosquat", f"Typosquatting of '{brand}': '{token}'",
                        f"'{token}' is {d} edit(s) away from '{brand}'. Attackers "
                        f"register near-identical spellings hoping for typing mistakes. "
                        f"Genuine domains: {', '.join(brands[brand][:2])}.",
                        30, "high"))

    # 2) Brand name used but domain is NOT the official one
    #    (google.com.evil.xyz, sbi-login.in, secure-hdfcbank.top)
    sub_text = parsed.subdomain.lower()
    for brand in brands:
        if brand in findings:
            continue
        in_label = any(c == brand for c in re.split(r"[-_]", parsed.domain))
        in_label = in_label or (len(brand) >= 5 and brand in parsed.domain)
        in_sub = any(l == brand or (len(brand) >= 5 and brand in l)
                     for l in sub_text.split(".") if l)
        if in_label or in_sub:
            where = "subdomain" if in_sub and not in_label else "domain name"
            add(brand, Finding(
                M, "brand_impersonation",
                f"Brand '{brand}' used in {where} of an unofficial site",
                f"The site is '{reg}', which is not an official {brand} domain "
                f"({', '.join(brands[brand][:2])}). Attackers embed a trusted "
                f"brand name to appear legitimate.", 30, "high"))

    return list(findings.values())
