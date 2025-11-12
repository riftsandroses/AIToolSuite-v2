import os
import pandas as pd

def extract_text_from_excel_folder(folder_path):
    all_texts = {}
    for filename in os.listdir(folder_path):
        if filename.endswith((".xls", ".xlsx")):
            file_path = os.path.join(folder_path, filename)
            try:
                df = pd.read_excel(file_path, sheet_name=None)  # all sheets
                all_sheets_text = ""
                for name, sheet in df.items():
                    all_sheets_text += sheet.to_string(index=False) + "\n"
                all_texts[filename] = all_sheets_text
            except Exception as e:
                print(f"[ERROR] Reading Excel {filename}: {e}")
    return all_texts
