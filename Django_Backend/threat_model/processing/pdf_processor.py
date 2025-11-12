from pdfminer.high_level import extract_text
import os
def extract_text_from_pdf_folder(folder_path):
    all_texts = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".pdf"):
            file_path = os.path.join(folder_path, filename)
            text = extract_text(file_path)
            all_texts[filename] = text
    return all_texts
