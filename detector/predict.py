"""Loads the trained models and produces a verdict + reasons for a URL or an email."""
import os
import re
import numpy as np
import pandas as pd
import joblib

from .config import OFFICIAL_DOMAINS, OFFICIAL_SCORE_CAP, PHISHING_AT, SUSPICIOUS_AT, USER_CONTENT_SUBS
from .email_features import clean_text, parse_email
from .url_features import extract, parse, red_flags

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
URL_MODEL = os.path.join(HERE, "model", "url_model.joblib")
EMAIL_MODEL = os.path.join(HERE, "model", "email_model.joblib")


def verdict(score):
    if score >= PHISHING_AT:
        return "Likely phishing"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Likely safe"  # never "safe": static checks cannot prove a link is harmless


class Detector:
    def __init__(self):
        self.url = joblib.load(URL_MODEL) if os.path.exists(URL_MODEL) else None
        self.email = joblib.load(EMAIL_MODEL) if os.path.exists(EMAIL_MODEL) else None

    # ---------------- URL ----------------
    def url_score(self, url):
        f = extract(url)
        flags = red_flags(url, f)
        if self.url is None:  # fallback so the tool still works before training
            score = min(1.0, 0.18 * len([x for x in flags if "weak signal" not in x]))
        else:
            X = pd.DataFrame([f])[self.url["features"]]
            score = float(self.url["model"].predict_proba(X)[0, 1])
        p = parse(url)
        userinfo = p["netloc"].rsplit("@", 1)[0] if "@" in p["netloc"] else ""
        if re.fullmatch(r"[\w.\-]+\.[a-z]{2,}", userinfo.lower()):
            score = max(score, 0.75)  # "paypal.com@evil.tk": the real host is what comes AFTER the @
        sub_first = p["sub"].split(".")[-1] if p["sub"] else ""
        if p["reg"] in OFFICIAL_DOMAINS and not f["has_at"] and sub_first not in USER_CONTENT_SUBS:
            score = min(score, OFFICIAL_SCORE_CAP)
            flags = flags + ["official domain of a well-known brand (note: attackers can still abuse some of its user-content pages)"]
        elif score >= SUSPICIOUS_AT and not [x for x in flags if "weak signal" not in x]:
            flags = flags + ["overall URL pattern statistically resembles phishing URLs in the training data"]
        return score, flags

    def check_url(self, url):
        url = (url or "").strip()
        if not url or len(url) > 2000:
            return {"error": "Please enter a URL (max 2000 characters)."}
        score, flags = self.url_score(url)
        return {"type": "url", "input": url, "score": round(score, 3), "verdict": verdict(score),
                "reasons": flags or ["no obvious red flags in the URL structure"],
                "model": "rules only (train the model first)" if self.url is None else self.url["name"]}

    # ---------------- Email ----------------
    def text_score(self, text):
        if self.email is None:
            return 0.0, []
        clean = clean_text(text)
        vec, clf = self.email[0], self.email[1]
        x = vec.transform([clean])
        p = float(clf.predict_proba(x)[0, 1])
        names = np.array(vec.get_feature_names_out())
        contrib = x.toarray()[0] * clf.coef_[0]
        top = [names[i] for i in np.argsort(-contrib)[:12]
               if contrib[i] > 0 and "urltoken" not in names[i] and "num" not in names[i].split()][:5]
        return p, (top if p >= SUSPICIOUS_AT else [])

    def check_email(self, raw):
        if not (raw or "").strip():
            return {"error": "Please paste an email or upload a .eml file."}
        if len(raw) > 500_000:
            return {"error": "Email is too large (max 500 KB)."}
        e = parse_email(raw)
        text = f"{e['subject']} {e['body']}"
        p_text, words = self.text_score(text)
        url_results = []
        for u in e["urls"]:
            s, fl = self.url_score(u)
            url_results.append({"url": u, "score": round(s, 3), "reasons": fl[:4]})
        p_url = max([r["score"] for r in url_results], default=0.0)
        bonus = min(0.2, 0.07 * len(e["header_flags"]))
        score = min(1.0, max(p_text, 0.8 * p_url) + bonus)

        reasons = []
        if words:
            reasons.append("wording typical of phishing: " + ", ".join(f"'{w}'" for w in words))
        reasons += e["header_flags"]
        for r in sorted(url_results, key=lambda r: -r["score"])[:3]:
            if r["score"] >= SUSPICIOUS_AT:
                reasons.append(f"risky link ({int(r['score'] * 100)}%): {r['url'][:80]}")
        return {"type": "email", "score": round(score, 3), "verdict": verdict(score),
                "text_score": round(p_text, 3), "link_score": round(p_url, 3),
                "reasons": reasons or ["no obvious red flags found"], "links_found": len(e["urls"]),
                "subject": e["subject"][:120]}
