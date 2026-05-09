import easyocr

MODEL_DIR = r"D:\Projects\phishing_project\easyocr_models"

reader = easyocr.Reader(
    ['en'],
    gpu=False,
    model_storage_directory=MODEL_DIR
)

def extract_text_from_image(image_path):
    result = reader.readtext(image_path, detail=0)
    text = " ".join(result)
    return text


if __name__ == "__main__":
    image_path = input("Enter image path: ")

    extracted_text = extract_text_from_image(image_path)

    output_path = r"D:\Projects\phishing_project\extracted_email_text.txt"

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(extracted_text)

    print("\n==========================")
    print("Extracted Text:")
    print(extracted_text)
    print("==========================")
    print(f"\nSaved to: {output_path}")