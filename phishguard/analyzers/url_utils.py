"""Safe, static URL parsing.

SECURITY NOTE: this module only manipulates strings. It never opens a socket,
follows a redirect or fetches the page, so analysing a malicious link cannot
infect or fingerprint the analyst's machine.
"""
import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

import config
from analyzers.models import ParsedURL

# Offline extractor: uses the suffix list bundled with the package and never
# downloads anything at runtime (suffix_list_urls=() disables network fetch).
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_CTRL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")


def _host_is_ip(host: str) -> bool:
    """True for dotted IPv4, IPv6, and obfuscated forms (decimal/hex/octal)."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"\d{8,10}", h) or re.fullmatch(r"0x[0-9a-fA-F]{6,8}", h):
        return True
    parts = h.split(".")
    if len(parts) == 4 and all(
        re.fullmatch(r"(0x[0-9a-fA-F]+|0[0-7]*|\d+)", p) for p in parts
    ):
        return True
    return False


def parse_url(raw: str) -> ParsedURL:
    """Validate and decompose a user-supplied URL. Raises ValueError if unusable."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("URL is empty.")
    raw = raw.strip()
    if len(raw) > config.MAX_URL_LENGTH:
        raise ValueError("URL is too long to analyse.")
    if _CTRL_OR_SPACE.search(raw):
        raise ValueError("URL contains spaces or control characters.")

    has_scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw)
    candidate = raw if has_scheme else "http://" + raw
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported.")

    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("URL has no hostname.")

    netloc = parts.netloc
    userinfo = netloc.rsplit("@", 1)[0] if "@" in netloc else ""

    is_ip = _host_is_ip(host)
    if is_ip:
        subdomain, domain, suffix = "", host, ""
    else:
        ext = _extract(host)
        subdomain, domain, suffix = ext.subdomain, ext.domain, ext.suffix

    return ParsedURL(
        raw=raw, normalized=candidate, scheme=parts.scheme.lower(),
        host=host, port=port, path=parts.path, query=parts.query,
        userinfo=userinfo, subdomain=subdomain, domain=domain,
        suffix=suffix, is_ip=is_ip,
    )
