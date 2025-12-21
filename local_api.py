from flask import Flask, request, jsonify
import email_detector
import url_detector

app = Flask(__name__)

@app.route("/check_email", methods=["POST"])
def check_email():
    content = request.json.get("content", "")
    result = email_detector.check_phishing(content)
    return jsonify({"result": result})

@app.route("/check_url", methods=["POST"])
def check_url():
    url = request.json.get("url", "")
    result = url_detector.check_url(url)
    return jsonify({"result": result})

if __name__ == "__main__":
    print("PhishGuard API running on http://127.0.0.1:5000")
    app.run(port=5000)
