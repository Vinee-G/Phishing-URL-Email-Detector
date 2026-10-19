"""Web page + JSON API.   python app.py   then open http://127.0.0.1:5000"""
from flask import Flask, jsonify, render_template, request
from detector.predict import Detector

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_000_000  # 1 MB request limit
det = Detector()


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/url")
def api_url():
    data = request.get_json(silent=True) or {}
    out = det.check_url(str(data.get("url", "")))
    return jsonify(out), (400 if "error" in out else 200)


@app.post("/api/email")
def api_email():
    data = request.get_json(silent=True) or {}
    out = det.check_email(str(data.get("text", "")))
    return jsonify(out), (400 if "error" in out else 200)


@app.get("/health")
def health():
    return jsonify({"url_model": det.url is not None, "email_model": det.email is not None})


if __name__ == "__main__":
    # 127.0.0.1 = only your own computer can reach it. Keep debug off.
    app.run(host="127.0.0.1", port=5000, debug=False)
