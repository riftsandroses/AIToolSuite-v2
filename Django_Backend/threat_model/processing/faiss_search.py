import os
import faiss
import pickle
from sentence_transformers import SentenceTransformer
from django.conf import settings
from ..models import ThreatModel
from django.apps import apps
# Use the same model as in faiss_store.py
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

def search_faiss(threat_model_id, query, top_k=5):
    """
    Search the FAISS index for a given ThreatModel ID and return top matching chunks.
    
    Args:
        threat_model_id (int): The ThreatModel database ID
        query (str): The search query
        top_k (int): Number of results to return
        
    Returns:
        list[dict]: List of matching chunks with metadata
    """
    try:
        tm_obj = ThreatModel.objects.get(id=threat_model_id)
    except ThreatModel.DoesNotExist:
        raise ValueError(f"ThreatModel ID {threat_model_id} not found.")

    # Locate the latest FAISS index
    app_path = apps.get_app_config('threat_model').path
    # Locate the latest FAISS index inside the threat_model app
    index_dir = os.path.join(app_path, "faiss_indexes", tm_obj.app_name, "latest")
    index_path = os.path.join(index_dir, "index.faiss")
    metadata_path = os.path.join(index_dir, "metadata.pkl")

    if not os.path.exists(index_path) or not os.path.exists(metadata_path):
        raise FileNotFoundError(f"No FAISS index found for {tm_obj.app_name}")

    # Load FAISS index & metadata
    index = faiss.read_index(index_path)
    with open(metadata_path, "rb") as f:
        metadata = pickle.load(f)

    # Create embedding for the query
    query_embedding = embedding_model.encode([query])

    # Search
    distances, indices = index.search(query_embedding, top_k)

    results = []
    for i, idx in enumerate(indices[0]):
        if idx < 0 or idx >= len(metadata):
            continue
        item = metadata[idx].copy()
        item["score"] = float(distances[0][i])
        # If enriched_texts were used, text might be in DB; here we don't store full text in FAISS metadata
        # For RAG, you'd want to also retrieve original chunk text from ingestion step
        # In our case, we can add a 'text' field here if stored in metadata
        results.append(item)

    return results
