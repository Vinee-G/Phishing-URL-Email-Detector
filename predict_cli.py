"""Command line.
  python predict_cli.py url "http://paypa1.com.secure-login.tk/verify"
  python predict_cli.py email path/to/message.eml
"""
import sys
from detector.predict import Detector

if len(sys.argv) < 3 or sys.argv[1] not in ("url", "email"):
    sys.exit(__doc__)
d = Detector()
if sys.argv[1] == "url":
    r = d.check_url(sys.argv[2])
else:
    with open(sys.argv[2], "rb") as f:
        r = d.check_email(f.read().decode("utf-8", "ignore"))
if "error" in r:
    sys.exit(r["error"])
print(f"{r['verdict']}  (phishing probability {r['score']:.0%})")
for why in r["reasons"]:
    print(" -", why)
