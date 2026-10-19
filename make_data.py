"""Creates SYNTHETIC practice data so the project runs on any laptop with no downloads.

  python make_data.py   ->  data/urls.csv (url,label)   data/emails.csv (subject,body,label)
  label: 1 = phishing, 0 = legitimate

IMPORTANT: synthetic data is easier than real life. Use it to build and test the pipeline,
then retrain on real data (see README, Step 8) before you quote any accuracy number.
"""
import random
import string
import pandas as pd

WORDS = ["green", "blue", "city", "travel", "food", "tech", "daily", "global", "smart", "home", "garden",
         "music", "photo", "book", "design", "health", "sports", "news", "cloud", "data", "shop", "learn",
         "career", "studio", "market", "energy", "coffee", "river", "mountain", "pixel", "craft", "urban"]
LEGIT_DOMAINS = ["google.com", "microsoft.com", "github.com", "wikipedia.org", "amazon.in", "flipkart.com",
                 "bbc.co.uk", "nytimes.com", "stackoverflow.com", "python.org", "linkedin.com", "youtube.com",
                 "apple.com", "netflix.com", "paypal.com", "hdfcbank.com", "sbi.co.in", "irctc.co.in",
                 "medium.com", "reddit.com", "coursera.org", "nptel.ac.in", "mozilla.org", "abc.xyz",
                 "dropbox.com", "instagram.com", "facebook.com", "whatsapp.com", "office.com", "zoom.us"]
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix", "instagram", "dropbox",
          "linkedin", "hdfcbank", "paytm", "flipkart", "coinbase", "outlook", "whatsapp"]
BAD_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "icu", "buzz", "cam"]
OK_TLDS = ["com", "net", "org", "in", "co", "info", "online", "site"]
KW = ["login", "signin", "verify", "secure", "account", "update", "confirm", "billing", "support"]
SUBS = ["www.", "mail.", "blog.", "docs.", "accounts.", "m.", "help.", ""]
PAGES = ["index.html", "login.php", "signin.html", "verify.php", "update.html", "confirm.aspx", "secure.php"]


def rnd(rng, n, alphabet=string.ascii_lowercase + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(n))


def word(rng):
    return rng.choice(WORDS)


def leet(rng, b):
    swaps = {"o": "0", "l": "1", "e": "3", "a": "4"}
    cands = [i for i, c in enumerate(b) if c in swaps]
    if rng.random() < 0.3 or not cands:
        return b.replace("m", "rn", 1) if "m" in b else b[:-1] + b[-1] * 2
    i = rng.choice(cands)
    return b[:i] + swaps[b[i]] + b[i + 1:]


def legit_url(rng):
    d = rng.choice(LEGIT_DOMAINS)
    if rng.random() < 0.12:  # small independent site, looks ordinary
        d = f"{word(rng)}{rng.choice(['', '-'])}{word(rng)}.{rng.choice(OK_TLDS)}"
    host = rng.choice(SUBS) + d
    scheme = "https" if rng.random() < 0.93 else "http"
    kind = rng.random()
    if kind < 0.2:
        path = ""
    elif kind < 0.4:
        path = f"/{word(rng)}/{word(rng)}-{word(rng)}-{rng.randint(1, 999)}"
    elif kind < 0.55:
        path = f"/search?q={word(rng)}&page={rng.randint(1, 30)}"
    elif kind < 0.7:
        path = f"/{rng.choice(['login', 'signin', 'account', 'settings/security'])}"  # real login pages exist!
    elif kind < 0.85:
        path = f"/dp/{rnd(rng, 10).upper()}?ref={rnd(rng, 8)}&utm_source={word(rng)}&utm_medium=email"
    else:
        path = f"/articles/2026/{rng.randint(1, 12)}/{word(rng)}-{word(rng)}-{word(rng)}-{word(rng)}"
    r = rng.random()
    if r < 0.06:
        return f"https://{rng.choice(['bit.ly', 'tinyurl.com', 't.co'])}/{rnd(rng, 7)}"
    if r < 0.10:   # legit but brand name appears in the path of another site
        return f"https://{rng.choice(['github.com', 'medium.com', 'reddit.com', 'stackoverflow.com'])}/{rng.choice(BRANDS)}/{word(rng)}-{word(rng)}"
    if r < 0.14:   # legit CDN / random-looking host
        return f"https://{rnd(rng, rng.randint(9, 14))}.{rng.choice(['cloudfront.net', 'azurewebsites.net', 'web.app'])}/{word(rng)}/index.html"
    if r < 0.18:   # internal or lab address
        return f"http://192.168.{rng.randint(0, 5)}.{rng.randint(2, 250)}/{rng.choice(['admin', 'login', 'dashboard'])}"
    if r < 0.22:   # small site with hyphens, odd TLD, login keywords
        return f"https://{word(rng)}-{word(rng)}-{word(rng)}.{rng.choice(BAD_TLDS + OK_TLDS)}/{rng.choice(KW)}"
    return f"{scheme}://{host}{path}"


def phishing_url(rng):
    b = rng.choice(BRANDS)
    tld = rng.choice(BAD_TLDS if rng.random() < 0.55 else OK_TLDS)
    page = rng.choice(PAGES)
    kind = rng.random()
    scheme = "https" if rng.random() < 0.55 else "http"  # phishing uses HTTPS a lot now
    if kind < 0.10:    # brand in subdomain of attacker domain
        return f"{scheme}://{b}.com.{rng.choice(KW)}-{word(rng)}.{tld}/{page}"
    if kind < 0.20:    # typosquat
        return f"{scheme}://{rng.choice(['', 'www.'])}{leet(rng, b)}.{rng.choice(['com', 'net', tld])}/{rng.choice(KW)}/{page}"
    if kind < 0.30:    # keyword stuffed domain
        return f"{scheme}://{rng.choice(KW)}-{b}-{rng.choice(KW)}.{tld}/{page}"
    if kind < 0.36:    # raw IP
        ip = ".".join(str(rng.randint(1, 250)) for _ in range(4))
        return f"http://{ip}/{b}/{page}"
    if kind < 0.39:    # @ trick
        return f"http://{b}.com@{rnd(rng, 8)}.{tld}/{rng.choice(KW)}"
    if kind < 0.45:    # shortener
        return f"https://{rng.choice(['bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy'])}/{rnd(rng, 7)}"
    if kind < 0.55:    # random-looking domain
        return f"{scheme}://{rnd(rng, rng.randint(9, 16))}.{tld}/wp-includes/{rng.choice(KW)}/{page}"
    if kind < 0.75:    # hacked small site hosting a fake page (hard case)
        return f"{scheme}://{word(rng)}{word(rng)}.{rng.choice(OK_TLDS)}/wp-content/uploads/{b}/{page}"
    if kind < 0.78:    # punycode
        return f"https://xn--{rnd(rng, 6)}-{rnd(rng, 3)}.com/{b}/{page}"
    if kind < 0.90:    # looks ordinary (hard)
        return f"https://{word(rng)}-{word(rng)}.{rng.choice(OK_TLDS)}/{rng.choice(KW)}"
    # compromised legit-looking host, innocent path
    return f"https://{rng.choice(SUBS)}{word(rng)}{word(rng)}.{rng.choice(['com', 'in', 'org'])}/{word(rng)}/{page}"


# ---------- emails ----------
SHARED = ["Thank you for your time.", "Please let us know if you have any questions.", "Best regards,",
          "Kind regards,", "Have a great day.", "This is an automated message, please do not reply."]
PHISH = [
    "Your account has been suspended due to unusual activity.",
    "We detected a suspicious sign-in attempt, verify your identity immediately.",
    "Your password will expire in 24 hours, confirm it now to keep access.",
    "You have won a prize! Claim your reward before it expires.",
    "Your payment failed. Update your billing information to avoid cancellation.",
    "Action required: your mailbox is almost full, click the link to upgrade.",
    "Dear customer, we could not deliver your parcel, confirm your address.",
    "Final notice: unpaid invoice attached, open to avoid legal action.",
    "Security alert: log in now to unlock your account.",
]
PHISH_SUBTLE = ["Please review the shared document at the link below.",
                "The updated payroll schedule is ready for you to view.",
                "A new voice message is waiting for you, listen here."]
LEGIT = [
    "Reminder: team meeting tomorrow at 10 AM in the conference room.",
    "Here is the project update for this week, the report is attached.",
    "Your order has shipped and should arrive in three to five days.",
    "Thanks for registering for the workshop, the schedule is below.",
    "Attached are the lecture notes from today's class.",
    "Your interview is scheduled for Monday, please confirm if the time works.",
    "This month's newsletter covers new features and upcoming events.",
    "Thanks for your payment, your receipt is attached for your records.",
    "Could you review the draft and share your comments by Friday?",
]
LEGIT_HARD = ["Urgent: server maintenance tonight, please save your work.",
              "You requested a password reset, use the link below within one hour.",
              "We noticed a new sign-in to your account from a new device. If this was you, no action is needed.",
              "Your invoice is attached, payment is due at the end of the month."]
NAMES = ["Alex", "Priya", "Sam", "Ravi", "Maria", "John", "Anita", "Kumar"]


def phishing_email(rng):
    sents = [rng.choice(SHARED)] if rng.random() < 0.7 else []
    body_s = rng.sample(PHISH, rng.randint(1, 3)) if rng.random() > 0.40 else [rng.choice(PHISH_SUBTLE)]
    link = phishing_url(rng)
    greet = rng.choice(["Dear customer,", "Dear user,", f"Hello {rng.choice(NAMES)},", "Hello,", "Hi,"])
    subj = rng.choice(["Action required", "Security alert", "Account notice", "Your invoice", "Document shared with you",
                       "Verify your account", "Payment problem", "You have a new message"])
    body = greet + " " + " ".join(body_s) + f" {link} " + " ".join(sents)
    return subj, body


def legit_email(rng):
    body_s = rng.sample(LEGIT, rng.randint(1, 3))
    if rng.random() < 0.40:
        body_s.append(rng.choice(LEGIT_HARD))
    link = legit_url(rng) if rng.random() < 0.6 else ""
    greet = rng.choice([f"Hi {rng.choice(NAMES)},", f"Hello {rng.choice(NAMES)},", "Hello team,", "Hi all,"])
    subj = rng.choice(["Meeting reminder", "Weekly update", "Order confirmation", "Workshop details", "Class notes",
                       "Interview schedule", "Newsletter", "Receipt", "Draft review", "Server maintenance"])
    body = greet + " " + " ".join(body_s) + (f" {link} " if link else " ") + " ".join(rng.sample(SHARED, 2))
    return subj, body


def main(n_urls=4000, n_emails=1500, seed=42):
    rng = random.Random(seed)
    rows = [(legit_url(rng), 0) for _ in range(n_urls)] + [(phishing_url(rng), 1) for _ in range(n_urls)]
    rows = [(u, 1 - l if rng.random() < 0.03 else l) for u, l in rows]  # 3% wrong labels, like real data
    rng.shuffle(rows)
    pd.DataFrame(rows, columns=["url", "label"]).drop_duplicates("url").to_csv("data/urls.csv", index=False)
    er = []
    for _ in range(n_emails):
        er.append((*legit_email(rng), 0))
        er.append((*phishing_email(rng), 1))
    er = [(a, b, 1 - l if rng.random() < 0.03 else l) for a, b, l in er]
    rng.shuffle(er)
    pd.DataFrame(er, columns=["subject", "body", "label"]).to_csv("data/emails.csv", index=False)
    print("data/urls.csv and data/emails.csv created")


if __name__ == "__main__":
    main()
