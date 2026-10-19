"""URL -> numbers. Static analysis only: we NEVER visit the link."""
import math
import re
from collections import Counter
from urllib.parse import urlparse

from .config import BRANDS, KEYWORDS, SHORTENERS, SUSPICIOUS_TLDS

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "nic"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "n_dots", "n_hyphens_host", "n_digits",
    "digit_ratio", "n_special", "n_slashes", "has_ip", "has_at", "is_https", "n_subdomains",
    "tld_suspicious", "n_keywords", "is_shortener", "has_punycode", "host_entropy",
    "brand_in_subdomain", "brand_in_path", "brand_in_domain_extra", "lookalike_brand",
    "digits_in_name", "odd_port", "path_depth", "n_params", "name_len", "double_slash_path",
]


def normalize(url):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return url


def split_host(host):
    """-> (subdomain, registered_domain, tld). Small heuristic, no extra library needed."""
    host = (host or "").lower().strip(".")
    if re.fullmatch(r"[\d.]+", host) or ":" in host:
        return "", host, ""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[:-3]), ".".join(parts[-3:]), parts[-1]
    if len(parts) >= 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:]), parts[-1]
    return "", host, ""


def parse(url):
    url = normalize(url)
    try:
        p = urlparse(url)
        host = p.hostname or ""
        try:
            port = p.port
        except ValueError:
            port = -1
    except ValueError:
        p, host, port = urlparse("http://invalid"), "", -1
    sub, reg, tld = split_host(host)
    name = reg.split(".")[0] if reg else ""
    return {"url": url, "scheme": p.scheme, "host": host, "sub": sub, "reg": reg, "tld": tld,
            "name": name, "path": p.path or "", "query": p.query or "", "port": port,
            "netloc": p.netloc or ""}


def registered_domain(url):
    return parse(url)["reg"]


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def levenshtein(a, b):
    if abs(len(a) - len(b)) > 2:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_hits(parsed):
    """Brand names used in places where they should not be."""
    name, sub, path = parsed["name"], parsed["sub"], parsed["path"].lower()
    in_sub = int(any(b in sub for b in BRANDS))
    in_path = int(any(b in path for b in BRANDS) and name not in BRANDS)
    extra = int(any(b in name and name != b for b in BRANDS))  # secure-paypal-login.com
    leet = name.translate(LEET).replace("vv", "w").replace("rn", "m")
    look = int(name not in BRANDS and any(len(b) >= 5 and levenshtein(leet, b) <= 1 for b in BRANDS))
    return in_sub, in_path, extra, look


def extract(url):
    p = parse(url)
    full = p["url"].lower()
    host, name = p["host"], p["name"]
    in_sub, in_path, extra, look = _brand_hits(p)
    n_digits = sum(ch.isdigit() for ch in full)
    return {
        "url_len": len(full),
        "host_len": len(host),
        "path_len": len(p["path"]),
        "query_len": len(p["query"]),
        "n_dots": host.count("."),
        "n_hyphens_host": host.count("-"),
        "n_digits": n_digits,
        "digit_ratio": n_digits / max(len(full), 1),
        "n_special": sum(full.count(c) for c in "@%=&?_~#"),
        "n_slashes": full.count("/"),
        "has_ip": int(bool(re.fullmatch(r"[\d.]+", host)) or ":" in host),
        "has_at": int("@" in p["netloc"]),
        "is_https": int(p["scheme"] == "https"),
        "n_subdomains": len([s for s in p["sub"].split(".") if s]),
        "tld_suspicious": int(p["tld"] in SUSPICIOUS_TLDS),
        "n_keywords": sum(k in full for k in KEYWORDS),
        "is_shortener": int(p["reg"] in SHORTENERS),
        "has_punycode": int("xn--" in host),
        "host_entropy": entropy(host),
        "brand_in_subdomain": in_sub,
        "brand_in_path": in_path,
        "brand_in_domain_extra": extra,
        "lookalike_brand": look,
        "digits_in_name": sum(ch.isdigit() for ch in name),
        "odd_port": int(p["port"] not in (None, 80, 443)),
        "path_depth": len([x for x in p["path"].split("/") if x]),
        "n_params": len([x for x in p["query"].split("&") if x]),
        "name_len": len(name),
        "double_slash_path": int("//" in p["path"]),
    }


def red_flags(url, f=None):
    """Human-readable reasons. Used for explanations (the model gives the score)."""
    f = f or extract(url)
    p = parse(url)
    why = []
    if f["has_ip"]:
        why.append("uses a raw IP address instead of a domain name")
    if f["has_at"]:
        why.append("contains '@' - everything before it is ignored by the browser, a common trick")
    if f["has_punycode"]:
        why.append("punycode (xn--) domain, possible look-alike characters")
    if f["lookalike_brand"]:
        why.append(f"domain '{p['name']}' looks like a misspelled well-known brand")
    if f["brand_in_subdomain"]:
        why.append("a brand name appears in the subdomain, but the real domain is different")
    if f["brand_in_domain_extra"]:
        why.append("brand name is mixed into an unrelated domain name")
    if f["brand_in_path"]:
        why.append("a brand name appears in the path of an unrelated domain")
    if f["tld_suspicious"]:
        why.append(f"uses '.{p['tld']}', a TLD often abused by attackers")
    if f["is_shortener"]:
        why.append("link shortener hides the real destination")
    if f["n_keywords"] >= 2:
        why.append(f"{f['n_keywords']} sensitive words (login, verify, account...) in the URL")
    if f["n_hyphens_host"] >= 3:
        why.append("many hyphens in the domain name")
    if f["n_subdomains"] >= 3:
        why.append("unusually many subdomains")
    nm = p["name"]
    if len(nm) >= 8 and "-" not in nm and (sum(c in "aeiou" for c in nm) / len(nm) < 0.25 or f["digits_in_name"] >= 3):
        why.append("domain name looks random (few vowels or many digits)")
    if f["odd_port"]:
        why.append("non-standard port number")
    if not f["is_https"]:
        why.append("not using HTTPS (weak signal: many phishing sites use HTTPS too)")
    if f["url_len"] > 100:
        why.append("very long URL")
    return why
