from analyzers.url_utils import parse_url
from analyzers.heuristics import analyze_heuristics


def checks(url):
    return {f.check for f in analyze_heuristics(parse_url(url))}


def test_safe_url_has_no_flags():
    assert checks("https://www.google.com/") == set()
    assert checks("https://www.onlinesbi.sbi/") == set()


def test_ip_address_variants():
    for u in ("http://192.168.1.10/login", "http://3232235777/", "http://0xC0A80001/",
              "http://[2001:db8::1]/"):
        assert "ip_address" in checks(u), u


def test_at_symbol():
    assert "at_symbol" in checks("http://google.com@evil.com/")


def test_excessive_subdomains():
    assert "excessive_subdomains" in checks("https://a.b.c.d.example.com/")
    assert "excessive_subdomains" not in checks("https://mail.example.com/")


def test_keywords():
    assert "suspicious_keywords" in checks("http://example.com/update-kyc/verify")
    f = [x for x in analyze_heuristics(parse_url("http://example.com/login"))
         if x.check == "suspicious_keywords"]
    assert f and "login" in f[0].title


def test_shortener():
    assert "url_shortener" in checks("https://bit.ly/3abcXYZ")
    assert "url_shortener" not in checks("https://example.com/")


def test_no_https_port_embedded_url():
    assert "no_https" in checks("http://example.com")
    assert "odd_port" in checks("https://example.com:8443/")
    assert "embedded_url" in checks("https://example.com/r?url=http://evil.com")


def test_punycode_and_tld():
    assert "punycode" in checks("https://xn--gogle-5qa.com/")
    assert "risky_tld" in checks("https://free-gift.xyz/")


def test_invalid_input_rejected():
    for bad in ("", "   ", "ftp://example.com", "http://exa mple.com", "javascript:alert(1)"):
        try:
            parse_url(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_scheme_added_when_missing():
    p = parse_url("example.com/path")
    assert p.scheme == "http" and p.host == "example.com"
