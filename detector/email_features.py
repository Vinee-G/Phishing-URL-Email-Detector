"""Email -> clean text, links, and header red flags."""
import re
from email import message_from_string, policy
from html.parser import HTMLParser

from .config import BRANDS, FREE_MAIL
from .url_features import registered_domain

URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'()\[\]]+""", re.I)


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text, self.links, self._href, self._buf = [], [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((" ".join(self._buf).strip(), self._href))
            self._href = None


def _html_to_text(html):
    p = _HTMLText()
    try:
        p.feed(html)
    except Exception:
        pass
    return " ".join(p.text), p.links


def _domain_of(addr):
    m = re.search(r"@([\w.\-]+)", addr or "")
    return m.group(1).lower() if m else ""


def parse_email(raw):
    """raw: str or bytes (.eml or pasted text). Returns a dict with subject, body, urls, header flags."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "ignore")
    msg = message_from_string(raw, policy=policy.default)
    has_headers = bool(msg.get("From") or msg.get("Subject"))
    subject = str(msg.get("Subject", "") or "")
    from_h, reply_h = str(msg.get("From", "") or ""), str(msg.get("Reply-To", "") or "")
    auth = str(msg.get("Authentication-Results", "") or "").lower()

    body, links = "", []
    if has_headers:
        part = msg.get_body(preferencelist=("html", "plain"))
        content = part.get_content() if part else ""
        if part is not None and part.get_content_type() == "text/html":
            body, links = _html_to_text(content)
        else:
            body = content
    else:
        body = raw
        if "<a " in raw.lower() or "<html" in raw.lower():
            body, links = _html_to_text(raw)

    urls = list(dict.fromkeys(URL_RE.findall(body) + [h for _, h in links if h and h.lower().startswith(("http", "www"))]))

    flags = []
    fd, rd = _domain_of(from_h), _domain_of(reply_h)
    if fd and rd and fd != rd:
        flags.append(f"Reply-To domain ({rd}) differs from From domain ({fd})")
    name_part = from_h.split("<")[0].lower()
    if fd and any(b in name_part for b in BRANDS) and not any(b in fd for b in BRANDS):
        flags.append("sender display name uses a brand, but the address is from another domain")
    if fd in FREE_MAIL and any(b in name_part for b in BRANDS):
        flags.append("brand name sent from a free mail provider")
    for key in ("spf", "dkim", "dmarc"):
        if re.search(rf"{key}=(fail|softfail|none)", auth):
            flags.append(f"{key.upper()} check did not pass")
    mismatches = []
    for text, href in links:
        t = URL_RE.search(text or "")
        if t and href and registered_domain(t.group(0)) != registered_domain(href):
            mismatches.append((text, href))
            flags.append(f"link text shows {registered_domain(t.group(0))} but goes to {registered_domain(href)}")
    return {"subject": subject, "from": from_h, "body": body, "urls": urls[:20],
            "header_flags": flags, "has_headers": has_headers, "link_mismatches": len(mismatches)}


def clean_text(text):
    """Used for the text model: lowercase, URLs -> 'urltoken', tags removed."""
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = URL_RE.sub(" urltoken ", text)
    text = re.sub(r"\d+", " num ", text)
    return re.sub(r"\s+", " ", text).lower().strip()
