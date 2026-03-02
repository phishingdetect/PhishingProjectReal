import pickle
import pandas as pd
from feature import FeatureExtraction

# تحميل المودل
with open("url/newmodel.pkl", "rb") as file:
    gbc = pickle.load(file)
def predict_url(url):
    obj = FeatureExtraction(url)
    features = obj.features
    features = np.array(features).reshape(1, -1)

    prediction = gbc.predict(features)
    return prediction[0]

def predict_url(url):
    obj = FeatureExtraction(url)

    feature_names = gbc.feature_names_in_
    x = pd.DataFrame([obj.getFeaturesList()], columns=feature_names)

    y_pred = gbc.predict(x)[0]

    if y_pred == 1:
        return "Safe ✅"
    else:
        return "Phishing ❌"


if __name__ == "__main__":
    url = input("Enter URL: ")
    result = predict_url(url)
print("Result:", result)

