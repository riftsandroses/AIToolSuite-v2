import os
def extract_text_from_txt_folder(folder_path):
    """
    Reads all text content from .txt files in a given folder.
    """
    all_texts = {}
    for filename in os.listdir(folder_path):
        if filename.lower().endswith(".txt"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    all_texts[filename] = f.read()
            except Exception as e:
                print(f"[ERROR] Reading TXT file {filename}: {e}")
    return all_texts