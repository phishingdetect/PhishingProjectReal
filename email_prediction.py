import pickle
import sys

import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from url.extract import extract_urls
from url.feature import FeatureExtraction

# Load model and tools
model = load_model("email_model.h5")
tokenizer = pickle.load(open("models/tokenizer.pkl", "rb"))
label_encoder = pickle.load(open("models/label_encoder.pkl", "rb"))
url_model = pickle.load(open("url/newmodel.pkl", "rb"))
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
def predict_url(url):
    obj = FeatureExtraction(url)
    features = obj.features
    features = np.array(features).reshape(1, -1)

    prediction = url_model.predict(features)
    return prediction[0]
if __name__ == "__main__":

    print("📩 Email Phishing Detector")
    print("Paste FULL email. When finished press Ctrl+Z then Enter\n")

    user_input = sys.stdin.read()

    result, probability = predict_email(user_input)

    print("\n==========================")
    print("Prediction:", result)
    print("Confidence:", round(probability * 100, 2), "%")
    print("==========================\n")

    # 👇 مهم: هذا لازم يكون موجود
    urls = extract_urls(user_input)
    print("Extracted URLs:", urls)

    final_result = result

final_result = result

if urls:
    print("\n🔎 URL Analysis:")
    for url in urls:
        url_result = predict_url(url)
        print("URL:", url)
        print("URL Prediction:", url_result)

        if url_result == -1:
            final_result = "Phishing Email"
            break

print("\n🚨 Final Decision:", final_result)
