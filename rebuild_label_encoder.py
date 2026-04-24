import os
import pickle
import pandas as pd
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv("data/Phishing_Email.csv")

label_encoder = LabelEncoder()
label_encoder.fit(df["Email Type"].astype(str))

os.makedirs("models", exist_ok=True)

with open("models/label_encoder.pkl", "wb") as f:
    pickle.dump(label_encoder, f)

print("✅ label_encoder.pkl created successfully")
print("Classes:", label_encoder.classes_)