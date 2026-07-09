

import sys
from pathlib import Path
import easyocr

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "easyocr_models"
MODEL_DIR.mkdir(exist_ok=True)

reader = easyocr.Reader(
    ["en"],
    gpu=False,
    model_storage_directory=str(MODEL_DIR)
)

def extract_text_from_image(image_path):
    result = reader.readtext(image_path, detail=0)
    return " ".join(result)

if __name__ == "__main__":
    image_path = sys.argv[1]
    text = extract_text_from_image(image_path)
    print(text)