import os
from docx import Document

def extract_text_from_docx_folder(folder_path):
    all_texts = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".docx"):
            file_path = os.path.join(folder_path, filename)
            doc = Document(file_path)
            text = "\n".join([para.text for para in doc.paragraphs])
            all_texts[filename] = text
    return all_texts
