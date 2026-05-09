import os
import sys
import re
import pickle

from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

BASE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# باش يقدر يلقى مجلد url لو موجود في /d/Projects/phishing_project/url
sys.path.append(PROJECT_ROOT)

from url.predict import predict_url

MODEL_PATH = os.path.join(BASE_DIR, "models", "sms_model.h5")
TOKENIZER_PATH = os.path.join(BASE_DIR, "models", "sms_tokenizer.pkl")
MAX_LENGTH = 100

model = load_model(MODEL_PATH)

with open(TOKENIZER_PATH, "rb") as f:
    tokenizer = pickle.load(f)


def extract_urls_from_sms(text):
    url_pattern = r'(https?://\S+|www\.\S+)'
    return re.findall(url_pattern, text)


def predict_sms(text):
    sequence = tokenizer.texts_to_sequences([text])
    padded = pad_sequences(sequence, maxlen=MAX_LENGTH, padding="post")

    prediction = model.predict(padded, verbose=0)[0][0]

    if prediction >= 0.5:
        label = "Smishing SMS"
        confidence = prediction
    else:
        label = "Safe SMS"
        confidence = 1 - prediction

    return label, confidence


def predict_sms_with_url_logic(text):
    sms_label, sms_confidence = predict_sms(text)
    urls = extract_urls_from_sms(text)

    final_result = sms_label
    url_decisions = []

    if urls:
        for url in urls:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url

            url_result = predict_url(url)
            url_decisions.append((url, url_result))

        # URL له الأولوية
        if any("Phishing" in str(result) for _, result in url_decisions):
            final_result = "Smishing SMS"
        elif all("Safe" in str(result) for _, result in url_decisions):
            final_result = "Safe SMS"

    return {
        "sms_prediction": sms_label,
        "sms_confidence": sms_confidence,
        "urls": urls,
        "url_decisions": url_decisions,
        "final_decision": final_result
    }


if __name__ == "__main__":
    sms = input("Enter SMS text: ")
    result = predict_sms_with_url_logic(sms)

    print("\n==========================")
    print("SMS Prediction:", result["sms_prediction"])
    print("SMS Confidence:", round(result["sms_confidence"] * 100, 2), "%")
    print("Extracted URLs:", result["urls"])

    if result["url_decisions"]:
        print("\n🔎 URL Analysis:")
        for url, decision in result["url_decisions"]:
            print("URL:", url)
            print("URL Prediction:", decision)

    print("\n🚨 Final Decision:", result["final_decision"])
    print("==========================")