import os
from PIL import Image
import pytesseract
# --- ADD THIS LINE ---
# For Windows (adjust the path if you installed it elsewhere)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# For macOS/Linux (uncomment and adjust path if not found automatically)
# pytesseract.pytesseract.tesseract_cmd = r'/usr/local/bin/tesseract'
# --------------------
def extract_text_from_diagram_folder(folder_path):
    all_texts = {}
    for filename in os.listdir(folder_path):
        if filename.lower().endswith((".png", ".jpg", ".jpeg")):
            file_path = os.path.join(folder_path, filename)
            try:
                img = Image.open(file_path)
                text = pytesseract.image_to_string(img)
                all_texts[filename] = text
            except Exception as e:
                print(f"[ERROR] OCR failed for {filename}: {e}")
    return all_texts
