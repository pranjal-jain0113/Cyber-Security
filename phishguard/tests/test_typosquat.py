from analyzers.url_utils import parse_url
from analyzers.typosquat import analyze_typosquat, levenshtein


def kinds(url):
    return {(f.check, f.title.split("'")[1]) for f in analyze_typosquat(parse_url(url))}


def test_levenshtein_basics():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3
    assert levenshtein("google", "google") == 0
    assert levenshtein("gogle", "google") == 1


def test_official_domains_not_flagged():
    for u in ("https://www.google.com", "https://netbanking.hdfcbank.com",
              "https://www.amazon.in", "https://onlinesbi.sbi", "https://accounts.google.com"):
        assert analyze_typosquat(parse_url(u)) == [], u


def test_leet_lookalike():
    r = kinds("http://g00gle-login.com")
    assert ("lookalike_chars", "google") in r


def test_edit_distance_typo():
    assert ("typosquat", "amazon") in kinds("https://amazom.com")
    assert ("typosquat", "paypal") in kinds("https://paypall.com")


def test_rn_for_m():
    assert ("lookalike_chars", "microsoft") in kinds("https://rnicrosoft.com")


def test_brand_in_unofficial_domain_or_subdomain():
    assert ("brand_impersonation", "sbi") in kinds("http://sbi-kyc-update.in")
    assert ("brand_impersonation", "google") in kinds("https://google.com.evil-site.xyz")
    assert ("brand_impersonation", "hdfcbank") in kinds("https://secure-hdfcbank.top")


def test_short_brand_requires_exact_match():
    # 'sbi' must not match unrelated 3-letter words like 'sri' / 'sky'
    assert analyze_typosquat(parse_url("https://sri-lanka-tours.com")) == []


def test_unrelated_domain_clean():
    assert analyze_typosquat(parse_url("https://wikipedia.org")) == []


def test_ip_skipped():
    assert analyze_typosquat(parse_url("http://10.0.0.1/")) == []
