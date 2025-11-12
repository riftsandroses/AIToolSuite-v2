# File: processing_controller.py
import os
import logging
import tempfile
from datetime import datetime
from django.conf import settings
from .pdf_processor import extract_text_from_pdf_folder
from .excel_processor import extract_text_from_excel_folder
from .docx_processor import extract_text_from_docx_folder
from .diagram_ocr import extract_text_from_diagram_folder
from .faiss_store import build_faiss_index
from .txt_processor import extract_text_from_txt_folder

logger = logging.getLogger(__name__)

# Allowed extensions for safety
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".xls", ".png", ".jpg", ".jpeg", ".txt"}

class DocumentProcessingError(Exception):
    """Custom exception for document processing failures"""
    pass

def is_valid_file(filename):
    """Check if the file has a supported extension."""
    ext = os.path.splitext(filename)[-1].lower()
    return ext in ALLOWED_EXTENSIONS

def process_uploaded_documents(app_name, threat_model_id=None, fail_fast=True):
    """
    Process uploaded documents for an app with improved error handling:
    1. Validate files
    2. Extract text (with fail-fast option)
    3. Build FAISS index with metadata
    
    Args:
        app_name: Name of the application
        threat_model_id: ID of the threat model
        fail_fast: If True, stop processing on first critical error
    """
    base_path = os.path.join(settings.MEDIA_ROOT, app_name)
    if not os.path.exists(base_path):
        logger.warning(f"[PROCESSOR] No media directory found for: {app_name}")
        return False

    logger.info(f"[PROCESSOR] Starting ingestion for app: {app_name}")

    all_texts = {}
    start_time = datetime.utcnow()
    processing_errors = []

    # Folder mappings for cleaner loop
    folder_processors = {
        "pdf": extract_text_from_pdf_folder,
        "docx": extract_text_from_docx_folder,
        "excel": extract_text_from_excel_folder,
        "diagram": extract_text_from_diagram_folder,
        "txt": extract_text_from_txt_folder,
        "png": extract_text_from_diagram_folder,
        "jpg": extract_text_from_diagram_folder,
        "jpeg": extract_text_from_diagram_folder,
    }

    # Track processing statistics
    total_files_found = 0
    files_processed = 0

    for folder, processor in folder_processors.items():
        folder_path = os.path.join(base_path, folder)
        if not os.path.exists(folder_path):
            continue

        valid_files = [f for f in os.listdir(folder_path) if is_valid_file(f)]
        if not valid_files:
            logger.info(f"[PROCESSOR] No valid {folder.upper()} files found for {app_name}")
            continue

        total_files_found += len(valid_files)
        logger.info(f"[PROCESSOR] Found {len(valid_files)} valid {folder.upper()} files...")

        try:
            logger.info(f"[PROCESSOR] Processing {len(valid_files)} {folder.upper()} files...")
            extracted = processor(folder_path)
            
            if not extracted:
                error_msg = f"No content extracted from {folder} files"
                logger.warning(f"[PROCESSOR] {error_msg}")
                processing_errors.append(error_msg)
                
                if fail_fast:
                    raise DocumentProcessingError(f"Failed to extract content from {folder} files for {app_name}")
            else:
                all_texts.update(extracted)
                files_processed += len(extracted)
                logger.info(f"[PROCESSOR] Successfully processed {len(extracted)} {folder.upper()} files")
                
        except Exception as e:
            error_msg = f"Failed to process {folder} files: {str(e)}"
            logger.error(f"[PROCESSOR] {error_msg}", exc_info=True)
            processing_errors.append(error_msg)
            
            if fail_fast:
                logger.error(f"[PROCESSOR] Fail-fast enabled, stopping processing for {app_name}")
                raise DocumentProcessingError(f"Critical error processing {folder} files for {app_name}: {str(e)}")

    # Check if we have any content to index
    if not all_texts:
        error_msg = f"No valid documents to index for: {app_name}"
        logger.error(f"[PROCESSOR] {error_msg}")
        if processing_errors:
            logger.error(f"[PROCESSOR] Processing errors encountered: {processing_errors}")
        return False

    # Log processing summary
    logger.info(f"[PROCESSOR] Processing summary for {app_name}: {files_processed}/{total_files_found} files processed successfully")
    if processing_errors and not fail_fast:
        logger.warning(f"[PROCESSOR] Non-critical errors encountered: {processing_errors}")

    # Add richer metadata for indexing
    enriched_texts = {}
    for filename, text in all_texts.items():
        enriched_texts[filename] = {
            "text": text,
            "threat_model_id": threat_model_id,
            "ingested_at": start_time.isoformat(),
            "processing_errors": processing_errors if not fail_fast else []
        }

    # Use temp dir for safe FAISS build
    with tempfile.TemporaryDirectory() as tmpdir:
        logger.info(f"[PROCESSOR] Building FAISS index in temp dir for {app_name}")
        try:
            build_faiss_index(app_name, enriched_texts, output_dir=tmpdir)
        except Exception as e:
            logger.error(f"[PROCESSOR] FAISS index build failed for {app_name}: {e}", exc_info=True)
            if fail_fast:
                raise DocumentProcessingError(f"FAISS index build failed for {app_name}: {str(e)}")
            return False

    logger.info(f"[PROCESSOR] Successfully ingested and indexed data for {app_name}")
    
    # Return success with warning if there were non-critical errors
    if processing_errors and not fail_fast:
        logger.info(f"[PROCESSOR] Completed with warnings for {app_name}")
    
    return True

def process_uploaded_documents_resilient(app_name, threat_model_id=None):
    """
    Wrapper function for resilient processing (fail_fast=False)
    Use this when you want to process as many documents as possible even if some fail.
    """
    return process_uploaded_documents(app_name, threat_model_id, fail_fast=False)

def process_uploaded_documents_strict(app_name, threat_model_id=None):
    """
    Wrapper function for strict processing (fail_fast=True)
    Use this when document integrity is critical and partial results are not acceptable.
    """
    return process_uploaded_documents(app_name, threat_model_id, fail_fast=True)