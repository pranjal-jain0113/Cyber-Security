"""Quick CLI demo for Step 1 (no Flask needed): python demo_step1.py <url> [url ...]"""
import sys
from analyzers.url_utils import parse_url
from analyzers.heuristics import analyze_heuristics
from analyzers.typosquat import analyze_typosquat

SAMPLES = ["https://www.google.com", "http://g00gle-login.com/verify",
           "http://sbi-kyc-update.in/login", "http://192.168.0.5/@secure",
           "https://bit.ly/3xYz", "https://google.com.account-verify.xyz"]

for url in (sys.argv[1:] or SAMPLES):
    try:
        p = parse_url(url)
    except ValueError as e:
        print(f"\n{url}\n  invalid: {e}"); continue
    findings = analyze_heuristics(p) + analyze_typosquat(p)
    print(f"\n{url}  ->  raw points: {sum(f.points for f in findings)}")
    for f in findings:
        print(f"  [{f.severity:<6}] +{f.points:<3} {f.title}")
    if not findings:
        print("  no flags")
