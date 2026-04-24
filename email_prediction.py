import os
import sys
import warnings
import pickle

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.append(PROJECT_ROOT)

from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

from url.extract import extract_urls
from url.predict import predict_url
BASE_DIR = os.path.dirname(__file__)

# Load model and tools
model = load_model(os.path.join(BASE_DIR, "email_model.h5"))
tokenizer = pickle.load(open(os.path.join(BASE_DIR, "models", "tokenizer.pkl"), "rb"))
label_encoder = pickle.load(open(os.path.join(BASE_DIR, "models", "label_encoder.pkl"), "rb"))

MAX_LEN = 150


def predict_email(text):
    sequence = tokenizer.texts_to_sequences([text])
    padded = pad_sequences(sequence, maxlen=MAX_LEN)

    prediction = model.predict(padded)
    prob = prediction[0][0]

    label_index = int(prob > 0.5)
    label = label_encoder.inverse_transform([label_index])[0]

    confidence = prob if label_index == 1 else 1 - prob

    return label, confidence


if __name__ == "__main__":
    print("📩 Email Phishing Detector")
    print("Paste FULL email. When finished press Ctrl+Z then Enter\n")

    user_input = sys.stdin.read()

    result, probability = predict_email(user_input)

    print("\n==========================")
    print("Prediction:", result)
    print("Confidence:", round(probability * 100, 2), "%")
    print("==========================\n")

    urls = extract_urls(user_input)
    print("Extracted URLs:", urls)

final_result = result

if urls:
    print("\n🔎 URL Analysis:")
    url_decisions = []

    for url in urls:
        url_result = predict_url(url)
        print("URL:", url)
        print("URL Prediction:", url_result)
        url_decisions.append(str(url_result))

    # URL has priority only if URLs exist
    if any("Phishing" in decision for decision in url_decisions):
        final_result = "Phishing Email"
    elif all("Safe" in decision for decision in url_decisions):
        final_result = "Safe Email"
else:
    # no URLs -> rely on email model
    final_result = result

print("\n🚨 Final Decision:", final_result)