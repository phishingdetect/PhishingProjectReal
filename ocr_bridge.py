import sys
import easyocr

MODEL_DIR = r"D:\Projects\phishing_project\easyocr_models"

reader = easyocr.Reader(
    ["en"],
    gpu=False,
    model_storage_directory=MODEL_DIR
)


def extract_text_from_image(image_path):
    result = reader.readtext(image_path, detail=0)
    return " ".join(result)


if __name__ == "__main__":
    image_path = sys.argv[1]
    text = extract_text_from_image(image_path)
    print(text)