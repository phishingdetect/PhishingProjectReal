import os
import pickle
import pandas as pd
from feature import FeatureExtraction
from preprocess import pii_filter, blacklist_check, resolve_redirects

MODEL_PATH = os.path.join(os.path.dirname(__file__), "newmodel.pkl")

with open(MODEL_PATH, "rb") as file:
    gbc = pickle.load(file)


def predict_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    print("Checking blacklist...")

    if blacklist_check(url):
        print("BLACKLIST HIT!")
        return "Phishing ❌ (Blacklisted URL)"

    print("Not in blacklist")

    pii_flag = pii_filter(url)
    final_url = resolve_redirects(url)

    obj = FeatureExtraction(final_url)
    feature_names = gbc.feature_names_in_
    x = pd.DataFrame([obj.getFeaturesList()], columns=feature_names)

    y_pred = gbc.predict(x)[0]

    if y_pred == 1:
        return "Safe ✅"
    else:
        if pii_flag:
            return "Phishing ❌ (Model Prediction + PII Page)"
        return "Phishing ❌ (Model Prediction)"


if __name__ == "__main__":
    url = input("Enter URL: ")
    result = predict_url(url)
    print("Result:", result)