from flask import Flask, request, jsonify
import url_detector

app = Flask(__name__)

@app.route("/check_url", methods=["POST"])
def check_url_api():
    data = request.json
    url = data.get("url")
    result = url_detector.check_url(url)
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(port=5000)
