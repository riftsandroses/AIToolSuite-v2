# threat_model/processing/faiss_store.py

import os
import faiss
import pickle
import shutil
import logging
from datetime import datetime
from django.apps import apps
from sentence_transformers import SentenceTransformer
from langchain.text_splitter import CharacterTextSplitter

# Get a logger instance for this module
logger = logging.getLogger(__name__)

class FaissIndexer:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", chunk_size: int = 512, chunk_overlap: int = 50):
        """
        Handles FAISS index creation with lazy SentenceTransformer loading.
        """
        self.text_splitter = CharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        self.model_name = model_name
        self._model = None  # Lazy-loaded model

    @property
    def model(self):
        """
        Load the model only when first accessed.
        """
        if self._model is None:
            try:
                logger.info(f"Loading SentenceTransformer model: {self.model_name}")
                self._model = SentenceTransformer(self.model_name)
            except Exception as e:
                logger.error(f"Failed to load SentenceTransformer model: {e}", exc_info=True)
                raise
        return self._model

    def build_faiss_index(self, app_name: str, raw_text_dict: dict, output_dir: str = None):
        """
        Builds a FAISS index for given raw_text_dict.
        Stores index + metadata in versioned directories under threat_model/faiss_indexes.
        """
        try:
            chunks, metadata = [], []

            # --- Split text into chunks ---
            for filename, full_text in raw_text_dict.items():
                if isinstance(full_text, dict) and "text" in full_text:
                    text_data = full_text["text"]
                else:
                    text_data = full_text

                text_chunks = self.text_splitter.split_text(text_data)
                chunks.extend(text_chunks)

                metadata.extend([
                    {
                        "chunk_text": text_chunks[i],
                        "filename": filename,
                        "file_type": filename.split(".")[-1].lower(),
                        "chunk_index": i,
                        **({k: v for k, v in full_text.items() if k != "text"} if isinstance(full_text, dict) else {})
                    }
                    for i in range(len(text_chunks))
                ])

            if not chunks:
                logger.warning(f"No content to index for {app_name}.")
                return None

            # --- Generate embeddings ---
            logger.info(f"Generating embeddings for {len(chunks)} chunks...")
            embeddings = self.model.encode(chunks, show_progress_bar=True)

            dim = embeddings.shape[1]
            index = faiss.IndexFlatL2(dim)
            index.add(embeddings)

            # --- Storage paths ---
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            app_path = apps.get_app_config("threat_model").path
            base_dir = os.path.join(app_path, "faiss_indexes", app_name)
            version_dir = os.path.join(base_dir, timestamp)
            latest_dir = os.path.join(base_dir, "latest")

            build_dir = output_dir if output_dir else version_dir
            os.makedirs(build_dir, exist_ok=True)

            # --- Save FAISS index + metadata ---
            faiss.write_index(index, os.path.join(build_dir, "index.faiss"))
            with open(os.path.join(build_dir, "metadata.pkl"), "wb") as f:
                pickle.dump(metadata, f)

            logger.info(f"Stored {len(chunks)} chunks for app: {app_name} → {build_dir}")

            # --- Sync 'latest' directory ---
            if output_dir:
                os.makedirs(version_dir, exist_ok=True)
                shutil.copytree(output_dir, version_dir, dirs_exist_ok=True)

            if os.path.exists(latest_dir):
                shutil.rmtree(latest_dir)
            shutil.copytree(version_dir, latest_dir)
            logger.info(f"Synced latest index to: {latest_dir}")

            return {
                "app_name": app_name,
                "chunks": len(chunks),
                "index_path": os.path.join(build_dir, "index.faiss"),
                "metadata_path": os.path.join(build_dir, "metadata.pkl"),
            }
        except Exception as e:
            logger.error(f"An error occurred during FAISS index building for {app_name}: {e}", exc_info=True)
            raise

# --- Singleton instance for Celery tasks ---
faiss_indexer = FaissIndexer()

def build_faiss_index(app_name: str, raw_text_dict: dict, output_dir: str = None):
    """
    Exposed function for Celery tasks.
    """
    try:
        return faiss_indexer.build_faiss_index(app_name, raw_text_dict, output_dir)
    except Exception as e:
        logger.error(f"FAISS index build failed for {app_name} in exposed function: {e}", exc_info=True)
        raise