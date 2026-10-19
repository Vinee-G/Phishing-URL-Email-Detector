"""Run:  python tests/test_sanity.py   (or: python -m pytest)"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector.predict import Detector
from detector.url_features import extract, parse
from detector.email_features import parse_email

d = Detector()


def test_parsing():
    p = parse("http://paypal.com@evil.tk/login")
    assert p["host"] == "evil.tk" and extract("http://paypal.com@evil.tk/login")["has_at"] == 1
    assert parse("https://www.bbc.co.uk/news")["reg"] == "bbc.co.uk"


def test_features():
    assert extract("http://185.23.44.12/login.php")["has_ip"] == 1
    assert extract("https://paypa1.com/login")["lookalike_brand"] == 1
    assert extract("https://paypal.com.secure-verify.tk/x")["brand_in_subdomain"] == 1
    assert extract("https://www.google.com/")["lookalike_brand"] == 0


def test_url_verdicts():
    assert d.check_url("https://github.com/python/cpython")["verdict"] == "Likely safe"
    assert d.check_url("http://paypa1.com.secure-login-verify.tk/signin.php")["verdict"] != "Likely safe"
    if d.url is not None:  # these need the trained model
        assert d.check_url("http://paypal.com@evil.tk/login")["verdict"] == "Likely phishing"
        assert d.check_url("https://microsoft.com/login")["verdict"] == "Likely safe"


def test_email_headers_and_links():
    raw = ('From: "PayPal Support" <help@gmail.com>\nReply-To: x@other.ru\nSubject: Action required\n'
           'Content-Type: text/html\n\n<p>Verify now: <a href="http://evil.tk/x">https://paypal.com/login</a></p>')
    e = parse_email(raw)
    assert e["link_mismatches"] == 1 and len(e["header_flags"]) >= 2
    if d.email is not None and d.url is not None:
        assert d.check_email(raw)["verdict"] != "Likely safe"


def test_bad_input():
    assert "error" in d.check_url("")
    assert "error" in d.check_email("   ")
    d.check_url("http://[broken")  # must not crash


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
