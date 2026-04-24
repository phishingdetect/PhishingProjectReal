import os
import pickle
import pandas as pd
from tensorflow.keras.preprocessing.text import Tokenizer

# Load dataset
df = pd.read_csv("data/Phishing_Email.csv")

# النصوص
texts = df["Email Text"].astype(str)

vocab_size = 5000
oov_tok = "<OOV>"

tokenizer = Tokenizer(num_words=vocab_size, oov_token=oov_tok)
tokenizer.fit_on_texts(texts)

#   إنشاء مجلد models
os.makedirs("models", exist_ok=True)

# حفظ tokenizer
with open("models/tokenizer.pkl", "wb") as f:
    pickle.dump(tokenizer, f)

print("✅ tokenizer.pkl created successfully")