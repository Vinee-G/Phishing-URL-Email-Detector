"""Lists and settings you can edit."""

# Brands attackers like to imitate (add your own, e.g. local banks)
BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix", "instagram",
    "whatsapp", "linkedin", "dropbox", "coinbase", "binance", "chase", "wellsfargo",
    "bankofamerica", "office365", "outlook", "dhl", "fedex", "sbi", "hdfcbank", "icicibank",
    "paytm", "flipkart", "phonepe",
]

# TLDs that are abused more often than average. NOT proof of phishing by themselves.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support", "zip",
    "country", "buzz", "rest", "loan", "icu", "cam", "monster",
}

KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm", "banking",
    "password", "wallet", "suspend", "unlock", "billing", "invoice", "payment", "alert",
    "recover", "authenticate", "validate", "webscr", "support",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "buff.ly",
}

FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "aol.com"}

# Verdict thresholds on the 0-1 phishing probability
SUSPICIOUS_AT = 0.35
PHISHING_AT = 0.65

# Exact registered domains of well-known brands. A URL on one of these gets a lower score
# (a login page on microsoft.com is normal). Extend this list, or load the free Tranco top list.
OFFICIAL_DOMAINS = {
    "google.com", "microsoft.com", "live.com", "office.com", "microsoftonline.com", "apple.com",
    "amazon.com", "amazon.in", "paypal.com", "facebook.com", "instagram.com", "whatsapp.com",
    "netflix.com", "linkedin.com", "dropbox.com", "github.com", "youtube.com", "wikipedia.org",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "onlinesbi.sbi", "paytm.com", "flipkart.com",
    "phonepe.com", "coinbase.com", "binance.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "dhl.com", "fedex.com", "irctc.co.in", "python.org", "mozilla.org", "zoom.us",
}
# Subdomains where ANYONE can host content, so the allowlist must not apply there
USER_CONTENT_SUBS = {"sites", "docs", "forms", "drive", "storage", "script", "pages", "gist", "raw", "user-images"}
OFFICIAL_SCORE_CAP = 0.2
