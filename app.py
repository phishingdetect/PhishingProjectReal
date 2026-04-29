import os
import os

os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"


import sys
import subprocess
import importlib.util
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

BASE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(BASE_DIR)

URL_DIR = os.path.join(PROJECT_ROOT, "url")
SMS_DIR = os.path.join(PROJECT_ROOT, "spam-Detection")
SMS_FILE = os.path.join(SMS_DIR, "sms_prediction.py")

OCR_PYTHON = os.path.join(PROJECT_ROOT, ".venv1", "Scripts", "python.exe")
OCR_SCRIPT = os.path.join(PROJECT_ROOT, "ocr_bridge.py")

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

sys.path.append(PROJECT_ROOT)
sys.path.append(URL_DIR)

from email_prediction import predict_email
from url.predict import predict_url
from url.extract import extract_urls

def load_sms_module():
    old_cwd = os.getcwd()
    os.chdir(SMS_DIR)

    spec = importlib.util.spec_from_file_location("sms_prediction", SMS_FILE)
    sms_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sms_module)

    os.chdir(old_cwd)
    return sms_module


sms_module = load_sms_module()

app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, "templates"),
    static_folder=os.path.join(PROJECT_ROOT, "static")
)
CORS(app)

def to_float(value):
    try:
        return float(value)
    except Exception:
        return 0.0


def analyze_url_logic(url):
    result = predict_url(url)

    if "Phishing" in str(result):
        final_decision = "Phishing URL"
        risk_level = "High"
    else:
        final_decision = "Safe URL"
        risk_level = "Low"

    return {
        "input_url": url,
        "url_prediction": str(result),
        "final_decision": final_decision,
        "risk_level": risk_level
    }
import re

def normalize_ocr_text_for_urls(text):
    if not text:
        return text

    fixed = text

    # Fix common OCR mistakes in protocol
    fixed = fixed.replace("bttp", "http")
    fixed = fixed.replace("Bttp", "http")
    fixed = fixed.replace("hxxp", "http")
    fixed = fixed.replace("hxxps", "https")

    fixed = fixed.replace("http Il", "http://")
    fixed = fixed.replace("https Il", "https://")
    fixed = fixed.replace("http I/", "http://")
    fixed = fixed.replace("https I/", "https://")
    fixed = fixed.replace("http //", "http://")
    fixed = fixed.replace("https //", "https://")

    # Fix common OCR mistakes in www
    fixed = fixed.replace("Iww", "www")
    fixed = fixed.replace("lww", "www")
    fixed = fixed.replace("Www", "www")
    fixed = fixed.replace("wwtrusted", "www.trusted")

    # Fix spaced domains
    fixed = fixed.replace(" dot ", ".")
    fixed = fixed.replace(" .com", ".com")
    fixed = fixed.replace(" com ", ".com ")
    fixed = fixed.replace(" com/", ".com/")
    fixed = fixed.replace(" comgeneral", ".com/general")
    fixed = fixed.replace(".comgeneral", ".com/general")

    # Fix cases like trustedbank comgeneral...
    fixed = re.sub(
        r"\b([A-Za-z0-9-]+)\s+com([A-Za-z0-9_/.-]+)",
        r"\1.com/\2",
        fixed,
        flags=re.IGNORECASE
    )

    # Fix cases like http://wwwtrustedbank.com -> http://www.trustedbank.com
    fixed = re.sub(
        r"(https?://)www([A-Za-z0-9-]+\.)",
        r"\1www.\2",
        fixed,
        flags=re.IGNORECASE
    )

    # Fix missing dot before asp/php/html
    fixed = re.sub(
        r"([A-Za-z0-9_-])(asp|php|html)(\s|$)",
        r"\1.\2 ",
        fixed,
        flags=re.IGNORECASE
    )

    # Fix cases like infoaspOnce -> info.asp Once
    fixed = re.sub(
        r"([A-Za-z0-9_-])asp(Once|If|Thank|This|We|Member|Please|Failure)",
        r"\1.asp \2",
        fixed,
        flags=re.IGNORECASE
    )

    # Put space after common file endings if OCR glued next sentence
    fixed = re.sub(
        r"(\.(asp|php|html|htm|aspx))([A-Z][a-z]+)",
        r"\1 \3",
        fixed,
        flags=re.IGNORECASE
    )

    # If domain appears without protocol, add http://
    fixed = re.sub(
        r"(?<!://)\b((?:www\.)?[A-Za-z0-9-]+\.(?:com|net|org|co|io|info|biz)(?:/[A-Za-z0-9_\-./?=&%]*)?)",
        r"http://\1",
        fixed,
        flags=re.IGNORECASE
    )

    # Stop URL when OCR attaches normal sentence words after link
    stop_words = [
        "Once", "Thank", "Thankyou", "This", "Please", "If",
        "We", "Member", "Dear", "Failure", "Security", "Billing"
    ]

    for word in stop_words:
        fixed = re.sub(
            rf"(https?://[^\s]+?)({word})",
            rf"\1 \2",
            fixed,
            flags=re.IGNORECASE
        )

    # Clean duplicated protocols
    fixed = fixed.replace("http://http://", "http://")
    fixed = fixed.replace("https://https://", "https://")
    fixed = fixed.replace("http://securehttp://-login", "http://secure-login")
    fixed = fixed.replace("https://securehttps://-login", "https://secure-login")
    # Fix duplicated www + protocol mistakes
    fixed = fixed.replace("www.http://", "http://")
    fixed = fixed.replace("www.https://", "https://")
    fixed = fixed.replace("http://www.http://", "http://")
    fixed = fixed.replace("https://www.https://", "https://")
    fixed = fixed.replace("http://www.https://", "https://")
    fixed = fixed.replace("https://www.http://", "http://")

    # Fix OCR reading bttp lww... as http://www...
    fixed = fixed.replace("http://lww", "http://www")
    fixed = fixed.replace("http://Iww", "http://www")
    fixed = fixed.replace("https://lww", "https://www")
    fixed = fixed.replace("https://Iww", "https://www")

    # If OCR produced http://wwwtrustedbank.com, add dot after www
    fixed = re.sub(
        r"(https?://)www([A-Za-z0-9-]+\.(com|net|org|co|io|info|biz))",
        r"\1www.\2",
        fixed,
        flags=re.IGNORECASE
    )
    return fixed
def analyze_email_logic(text):
    email_label, email_confidence = predict_email(text)

    urls = extract_urls(text)
    url_decisions = []

    final_decision = email_label

    if urls:
        for url in urls:
            url = url.strip()

            url = url.replace("www.http://", "http://")
            url = url.replace("www.https://", "https://")
            url = url.replace("http://www.http://", "http://")
            url = url.replace("https://www.https://", "https://")
            url = url.replace("http://www.https://", "https://")
            url = url.replace("https://www.http://", "http://")

            if not url.startswith(("http://", "https://")):
                url = "http://" + url

            url_result = predict_url(url)

            url_decisions.append({
                "url": url,
                "prediction": str(url_result)
            })

        if any("Phishing" in item["prediction"] for item in url_decisions):
            final_decision = "Phishing Email"
        elif all("Safe" in item["prediction"] for item in url_decisions):
            final_decision = "Safe Email"

    risk_level = "High" if "Phishing" in str(final_decision) else "Low"

    return {
        "email_prediction": str(email_label),
        "email_confidence": round(to_float(email_confidence) * 100, 2),
        "extracted_urls": urls,
        "url_analysis": url_decisions,
        "final_decision": str(final_decision),
        "risk_level": risk_level
    }


def analyze_sms_logic(text):
    result = sms_module.predict_sms_with_url_logic(text)

    url_decisions = []
    for item in result.get("url_decisions", []):
        url, decision = item
        url_decisions.append({
            "url": url,
            "prediction": str(decision)
        })

    final_decision = result.get("final_decision")
    risk_level = "High" if "Smishing" in str(final_decision) else "Low"

    return {
        "sms_prediction": str(result.get("sms_prediction")),
        "sms_confidence": round(to_float(result.get("sms_confidence")) * 100, 2),
        "extracted_urls": result.get("urls", []),
        "url_analysis": url_decisions,
        "final_decision": str(final_decision),
        "risk_level": risk_level
    }


def extract_text_with_ocr(image_path):
    process = subprocess.run(
        [OCR_PYTHON, OCR_SCRIPT, image_path],
        capture_output=True,
        text=True
    )

    if process.returncode != 0:
        raise RuntimeError(process.stderr)

    return process.stdout.strip()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/usecases")
def usecases():
    return render_template("usecases.html")


@app.route("/predict_url", methods=["POST"])
def predict_url_route():
    data = request.get_json()
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    return jsonify(analyze_url_logic(url))


@app.route("/predict_email", methods=["POST"])
def predict_email_route():
    data = request.get_json()
    text = data.get("email_text", "")

    if not text:
        return jsonify({"error": "Email text is required"}), 400

    return jsonify(analyze_email_logic(text))


@app.route("/predict_sms", methods=["POST"])
def predict_sms_route():
    data = request.get_json()
    text = data.get("sms_text", "")

    if not text:
        return jsonify({"error": "SMS text is required"}), 400

    return jsonify(analyze_sms_logic(text))


@app.route("/predict_image_email", methods=["POST"])
def predict_image_email_route():
    if "email_image" not in request.files:
        return jsonify({"error": "Image file is required"}), 400

    image = request.files["email_image"]

    if image.filename == "":
        return jsonify({"error": "No selected image"}), 400

    image_path = os.path.join(UPLOAD_DIR, image.filename)
    image.save(image_path)

    try:
        raw_ocr_text = extract_text_with_ocr(image_path)
        normalized_text = normalize_ocr_text_for_urls(raw_ocr_text)

        analysis = analyze_email_logic(normalized_text)

        analysis["channel"] = "Image Email"
        analysis["raw_ocr_text"] = raw_ocr_text
        analysis["extracted_ocr_text"] = normalized_text
        return jsonify(analysis)

    finally:
        if os.path.exists(image_path):
            os.remove(image_path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)