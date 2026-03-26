"""
services.py — AI services for architecture_assessment

Architecture of the RAG feedback loop
======================================

1. INDEXING (write path)
   Every VulnerabilityFeedback record is embedded and stored in ChromaDB
   under the collection "feedback_knowledge" with rich metadata:
     - feedback_type  (false_positive | prior_control | missed_finding)
     - category_tag, severity, assessment_id
   This happens immediately when feedback is submitted (via FeedbackVectorIndexer)
   AND in bulk during the weekly TrainingJob.

2. RETRIEVAL (read path)
   Before every SecurityAnalyzer call the RAG pipeline:
     a. Embeds the current query (architecture context + tech stack etc.)
     b. Queries ChromaDB for the top-K most similar past feedback items
     c. Formats the results as a human-readable "PAST FEEDBACK CONTEXT" block
     d. Injects that block into the LLM prompt alongside the training addendum

3. PROMPT ADDENDUM (training path)
   The weekly FeedbackTrainer distils ALL feedback into a concise numbered
   rule-list (max 800 words) stored in TrainingJob.refined_system_prompt.
   SecurityAnalyzer._load_training_addendum() prepends this to every prompt.

4. TOKEN TRACKING
   Every OpenAI call (chat AND embeddings) is wrapped by _track_usage(), which
   creates a TokenUsage DB record so the statistics endpoint can aggregate
   per-user consumption.
"""

import os
import base64
import json
import re
import logging
from datetime import datetime
from decimal import Decimal
from typing import Dict, List, Tuple, Optional, Any
from io import BytesIO

from PIL import Image
import chromadb
from chromadb.config import Settings
from openai import OpenAI
from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.utils import timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OpenAI pricing (USD per 1 000 tokens) — update as pricing changes
# ---------------------------------------------------------------------------
_PRICING: Dict[str, Dict[str, float]] = {
    "gpt-4o": {"prompt": 0.005, "completion": 0.015},
    "gpt-4o-mini": {"prompt": 0.00015, "completion": 0.0006},
    "text-embedding-3-small": {"prompt": 0.00002, "completion": 0.0},
    "text-embedding-3-large": {"prompt": 0.00013, "completion": 0.0},
}


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> Optional[Decimal]:
    p = _PRICING.get(model)
    if not p:
        return None
    cost = (prompt_tokens * p["prompt"] + completion_tokens * p["completion"]) / 1000
    return Decimal(str(round(cost, 6)))


# ---------------------------------------------------------------------------
# Token usage recorder
# ---------------------------------------------------------------------------

def _track_usage(
    *,
    operation: str,
    model_name: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    user=None,
    assessment=None,
    training_job=None,
) -> None:
    """
    Persist a TokenUsage record.  Failures are swallowed so that tracking
    never interrupts the primary AI flow.
    """
    try:
        from .models import TokenUsage
        TokenUsage.objects.create(
            user=user,
            operation=operation,
            model_name=model_name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            assessment=assessment,
            training_job=training_job,
            estimated_cost_usd=_estimate_cost(model_name, prompt_tokens, completion_tokens),
        )
    except Exception as exc:
        logger.warning("Token usage tracking failed: %s", exc)


# ---------------------------------------------------------------------------
# Image / file processor
# ---------------------------------------------------------------------------

class ImageProcessor:
    """Process and analyze architecture diagrams and evidence files"""

    IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'tif', 'svg'}
    TEXT_EXTENSIONS = {
        'txt', 'log', 'md', 'rst', 'csv', 'tsv',
        'yaml', 'yml', 'json', 'xml', 'toml', 'ini', 'cfg', 'conf', 'env',
        'sh', 'bash', 'zsh', 'ps1', 'bat', 'cmd',
        'py', 'js', 'ts', 'rb', 'go', 'java', 'kt', 'cs', 'cpp', 'c', 'h',
        'tf', 'tfvars', 'hcl', 'dockerfile', 'dockerignore',
        'sql', 'graphql', 'proto', 'html', 'htm', 'css',
        'properties', 'pem', 'crt', 'key', 'pub',
    }

    @staticmethod
    def process_image(image_file: UploadedFile) -> Tuple[str, str]:
        """Convert image to base64 for OpenAI API"""
        try:
            image_file.seek(0)
            image_data = image_file.read()
            ext = image_file.name.split('.')[-1].lower()

            if ext == 'pdf':
                try:
                    import fitz
                    pdf_document = fitz.open(stream=image_data, filetype="pdf")
                    page = pdf_document[0]
                    pix = page.get_pixmap(matrix=fitz.Matrix(300 / 72, 300 / 72))
                    image_data = pix.tobytes("png")
                    mime_type = 'image/png'
                    pdf_document.close()
                except ImportError:
                    from pdf2image import convert_from_bytes
                    images = convert_from_bytes(image_data, first_page=1, last_page=1)
                    if images:
                        buf = BytesIO()
                        images[0].save(buf, format='PNG')
                        image_data = buf.getvalue()
                        mime_type = 'image/png'
            else:
                mime_types = {
                    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
                    'png': 'image/png', 'gif': 'image/gif',
                    'bmp': 'image/bmp', 'webp': 'image/webp',
                    'tiff': 'image/tiff', 'tif': 'image/tiff',
                }
                mime_type = mime_types.get(ext, 'image/jpeg')
                img = Image.open(BytesIO(image_data))
                img.verify()
                image_file.seek(0)
                image_data = image_file.read()

            base64_image = base64.b64encode(image_data).decode('utf-8')
            image_file.seek(0)
            return base64_image, mime_type
        except Exception as e:
            raise Exception(f"Error processing image: {str(e)}")

    @classmethod
    def extract_file_content(cls, file_obj) -> Tuple[str, str, str]:
        """
        Extract readable content from any uploaded file.
        Returns (content_type, content, filename)
        content_type: 'image' | 'text' | 'pdf' | 'docx' | 'binary'
        """
        if hasattr(file_obj, 'seek'):
            file_obj.seek(0)
        raw_bytes = file_obj.read() if hasattr(file_obj, 'read') else open(file_obj, 'rb').read()
        name = getattr(file_obj, 'name', str(file_obj))
        parts = name.rsplit('.', 1)
        ext = parts[1].lower() if len(parts) == 2 else name.lower()

        if ext in cls.IMAGE_EXTENSIONS:
            mime_map = {
                'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
                'gif': 'image/gif', 'bmp': 'image/bmp', 'webp': 'image/webp',
                'tiff': 'image/tiff', 'tif': 'image/tiff', 'svg': 'image/svg+xml',
            }
            mime = mime_map.get(ext, 'image/jpeg')
            b64 = base64.b64encode(raw_bytes).decode('utf-8')
            return 'image', f"data:{mime};base64,{b64}", name

        if ext == 'pdf':
            try:
                import fitz
                doc = fitz.open(stream=raw_bytes, filetype='pdf')
                pages_text = [page.get_text() for page in doc]
                doc.close()
                return 'pdf', '\n'.join(pages_text)[:20000], name
            except ImportError:
                pass
            return 'pdf', raw_bytes.decode('latin-1', errors='replace')[:20000], name

        if ext in ('docx', 'doc'):
            try:
                import docx as python_docx
                import io as _io
                doc = python_docx.Document(_io.BytesIO(raw_bytes))
                text = '\n'.join(p.text for p in doc.paragraphs)
                return 'docx', text[:20000], name
            except ImportError:
                pass
            return 'binary', raw_bytes[:512].hex(), name

        if ext in cls.TEXT_EXTENSIONS:
            for encoding in ('utf-8', 'utf-8-sig', 'latin-1'):
                try:
                    text = raw_bytes.decode(encoding)
                    if len(text) > 12000:
                        text = text[:12000] + '\n\n... [truncated]'
                    return 'text', text, name
                except UnicodeDecodeError:
                    continue
            return 'binary', raw_bytes[:512].hex(), name

        try:
            text = raw_bytes.decode('utf-8')
            if len(text) > 12000:
                text = text[:12000] + '\n\n... [truncated]'
            return 'text', text, name
        except UnicodeDecodeError:
            return 'binary', raw_bytes[:512].hex(), name

    @staticmethod
    def extract_architecture_details(
        image_file: UploadedFile,
        client: OpenAI,
        user=None,
        assessment=None,
    ) -> str:
        """Extract detailed architecture information from diagram using GPT-4o Vision"""
        base64_image, mime_type = ImageProcessor.process_image(image_file)
        prompt = (
            "You are an expert security architect analyzing an architecture diagram. "
            "Extract ALL technical details visible including components, services, data flows, "
            "network boundaries, security zones, external integrations, databases, load balancers, "
            "gateways, authentication flows, security controls (firewalls, WAF), cloud services, "
            "deployment architecture, labels, annotations, and notes.\n\n"
            "Provide a comprehensive, detailed description capturing every technical element. "
            "Be specific about technologies, connections, and configurations shown."
        )
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{base64_image}"}}
                    ]
                }],
                max_tokens=4096,
                temperature=0.3
            )
            usage = response.usage
            _track_usage(
                operation='architecture_extraction',
                model_name='gpt-4o',
                prompt_tokens=usage.prompt_tokens,
                completion_tokens=usage.completion_tokens,
                total_tokens=usage.total_tokens,
                user=user,
                assessment=assessment,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise Exception(f"Error analyzing architecture diagram: {str(e)}")


# ---------------------------------------------------------------------------
# ChromaDB Vector Store — dual-collection design
# ---------------------------------------------------------------------------

class VectorStore:
    """
    Manages two ChromaDB collections:

    1. "security_knowledge"  — assessment context chunks for per-assessment RAG
    2. "feedback_knowledge"  — feedback documents for cross-assessment learning

    The feedback collection is the core of the RAG improvement loop: every
    piece of human feedback is stored here, semantically searchable, and
    injected into analysis prompts as few-shot examples.
    """

    FEEDBACK_COLLECTION = "feedback_knowledge"
    ASSESSMENT_COLLECTION = "security_knowledge"

    def __init__(self):
        chroma_path = getattr(settings, 'CHROMADB_PATH', '/tmp/chromadb')
        self._client = chromadb.PersistentClient(
            path=chroma_path,
            settings=Settings(anonymized_telemetry=False, allow_reset=True)
        )
        self._assessment_col = self._client.get_or_create_collection(
            name=self.ASSESSMENT_COLLECTION,
            metadata={"hnsw:space": "cosine"}
        )
        self._feedback_col = self._client.get_or_create_collection(
            name=self.FEEDBACK_COLLECTION,
            metadata={"hnsw:space": "cosine"}
        )
        self._openai = OpenAI(api_key=settings.OPENAI_API_KEY)

    # ------------------------------------------------------------------ #
    # Embedding helper                                                     #
    # ------------------------------------------------------------------ #

    def get_embedding(self, text: str, user=None, assessment=None, training_job=None) -> List[float]:
        """Return OpenAI embedding and track token usage."""
        response = self._openai.embeddings.create(
            model="text-embedding-3-small",
            input=text[:8000]  # stay within token limit
        )
        usage = response.usage
        _track_usage(
            operation='embedding',
            model_name='text-embedding-3-small',
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=0,
            total_tokens=usage.total_tokens,
            user=user,
            assessment=assessment,
            training_job=training_job,
        )
        return response.data[0].embedding

    # ------------------------------------------------------------------ #
    # Assessment context (existing behaviour)                              #
    # ------------------------------------------------------------------ #

    def add_assessment_context(self, assessment_id: str, context_data: Dict, user=None, assessment_obj=None):
        """Chunk and index assessment context for per-assessment retrieval."""
        chunks = []

        if context_data.get('architecture_analysis'):
            chunks.append({
                'text': f"Architecture Analysis: {context_data['architecture_analysis']}",
                'type': 'architecture',
            })

        for group_name, fields in [
            ('technology', [
                'programming_languages', 'frameworks_versions', 'databases',
                'cloud_services', 'containerization_platforms'
            ]),
            ('security_controls', [
                'authentication_mechanisms', 'authorization_model',
                'encryption_at_rest', 'encryption_in_transit',
                'input_validation_controls', 'api_authentication'
            ]),
            ('network', [
                'network_architecture', 'network_segmentation',
                'firewall_config', 'load_balancers', 'cdn_usage'
            ]),
        ]:
            data = [
                f"{f.replace('_', ' ').title()}: {context_data[f]}"
                for f in fields if context_data.get(f)
            ]
            if data:
                chunks.append({
                    'text': f"{group_name.title()}: " + "; ".join(data),
                    'type': group_name,
                })

        for idx, chunk in enumerate(chunks):
            embedding = self.get_embedding(
                chunk['text'], user=user, assessment=assessment_obj
            )
            doc_id = f"{assessment_id}_{chunk['type']}_{idx}"
            # Upsert so re-running the same assessment doesn't create duplicates
            try:
                self._assessment_col.delete(ids=[doc_id])
            except Exception:
                pass
            self._assessment_col.add(
                embeddings=[embedding],
                documents=[chunk['text']],
                metadatas=[{'assessment_id': assessment_id, 'type': chunk['type']}],
                ids=[doc_id]
            )

    def query_assessment_context(
        self, query: str, assessment_id: str, n_results: int = 5, user=None
    ) -> List[str]:
        embedding = self.get_embedding(query, user=user)
        results = self._assessment_col.query(
            query_embeddings=[embedding],
            n_results=n_results,
            where={"assessment_id": assessment_id}
        )
        return results['documents'][0] if results['documents'] else []

    # ------------------------------------------------------------------ #
    # Feedback knowledge base                                              #
    # ------------------------------------------------------------------ #

    def index_feedback(
        self,
        feedback_id: str,
        feedback_type: str,
        text: str,
        metadata: Dict,
        user=None,
        training_job=None,
    ) -> str:
        """
        Embed and store a feedback document in the feedback collection.
        Returns the ChromaDB document ID.
        """
        doc_id = f"feedback_{feedback_id}"
        embedding = self.get_embedding(text, user=user, training_job=training_job)

        safe_meta = {k: (str(v) if v is not None else "") for k, v in metadata.items()}
        safe_meta['feedback_type'] = feedback_type
        safe_meta['feedback_id'] = str(feedback_id)

        # Upsert — safe to call multiple times for the same feedback item
        try:
            self._feedback_col.delete(ids=[doc_id])
        except Exception:
            pass

        self._feedback_col.add(
            embeddings=[embedding],
            documents=[text],
            metadatas=[safe_meta],
            ids=[doc_id]
        )
        return doc_id

    def query_feedback_context(
        self,
        query: str,
        n_results: int = 8,
        feedback_type: Optional[str] = None,
        user=None,
        assessment=None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve the most relevant past feedback for a given query.

        Returns a list of dicts with keys: text, metadata, distance.
        Lower distance = more similar.
        """
        embedding = self.get_embedding(query, user=user, assessment=assessment)

        where_filter = {}
        if feedback_type:
            where_filter["feedback_type"] = feedback_type

        query_kwargs: Dict = dict(
            query_embeddings=[embedding],
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )
        if where_filter:
            query_kwargs["where"] = where_filter

        try:
            results = self._feedback_col.query(**query_kwargs)
        except Exception as exc:
            logger.warning("ChromaDB feedback query failed: %s", exc)
            return []

        if not results['documents'] or not results['documents'][0]:
            return []

        output = []
        for doc, meta, dist in zip(
            results['documents'][0],
            results['metadatas'][0],
            results['distances'][0],
        ):
            output.append({"text": doc, "metadata": meta, "distance": dist})
        return output

    def delete_feedback(self, feedback_id: str) -> None:
        """Remove a feedback document from the vector store."""
        try:
            self._feedback_col.delete(ids=[f"feedback_{feedback_id}"])
        except Exception as exc:
            logger.warning("Failed to delete feedback %s from ChromaDB: %s", feedback_id, exc)

    def get_feedback_collection_stats(self) -> Dict:
        """Return basic stats about the feedback collection."""
        try:
            count = self._feedback_col.count()
            return {"total_indexed": count}
        except Exception:
            return {"total_indexed": 0}


# ---------------------------------------------------------------------------
# Feedback Vector Indexer — called immediately on feedback submission
# ---------------------------------------------------------------------------

class FeedbackVectorIndexer:
    """
    Indexes a single VulnerabilityFeedback record into ChromaDB immediately
    after it is created so that the very next assessment benefits from it.
    """

    def __init__(self):
        self.vector_store = VectorStore()

    def index(self, feedback, user=None) -> str:
        """
        Build a rich text representation of the feedback and store it.
        Updates feedback.chroma_vector_id and saves.
        Returns the ChromaDB doc ID.
        """
        text, metadata = self._build_document(feedback)

        doc_id = self.vector_store.index_feedback(
            feedback_id=str(feedback.id),
            feedback_type=feedback.feedback_type,
            text=text,
            metadata=metadata,
            user=user,
        )

        # Persist the vector ID back to the DB record
        feedback.chroma_vector_id = doc_id
        feedback.save(update_fields=['chroma_vector_id', 'updated_at'])
        return doc_id

    @staticmethod
    def _build_document(feedback) -> Tuple[str, Dict]:
        """Build the text and metadata for a feedback document."""
        ft = feedback.feedback_type
        vc = feedback.vulnerable_component

        if ft == 'false_positive':
            title = vc.control_title if vc else "Unknown"
            category = vc.category_tag if vc else "Unknown"
            severity = vc.severity if vc else "Unknown"
            text = (
                f"FEEDBACK TYPE: False Positive\n"
                f"FINDING: {title}\n"
                f"CATEGORY: {category} | SEVERITY: {severity}\n"
                f"REASON: {feedback.false_positive_reason or feedback.explanation}\n"
                f"EXPLANATION: {feedback.explanation}"
            )
            metadata = {
                "category_tag": category,
                "severity": severity,
                "finding_title": title,
            }

        elif ft == 'prior_control':
            title = vc.control_title if vc else "Unknown"
            category = vc.category_tag if vc else "Unknown"
            text = (
                f"FEEDBACK TYPE: Prior Control Already Implemented\n"
                f"FINDING: {title}\n"
                f"CATEGORY: {category}\n"
                f"EXISTING CONTROL: {feedback.prior_control_name}\n"
                f"CONTROL DESCRIPTION: {feedback.prior_control_description}\n"
                f"CONTEXT: {feedback.explanation}"
            )
            metadata = {
                "category_tag": category,
                "finding_title": title,
                "prior_control_name": feedback.prior_control_name or "",
            }

        else:  # missed_finding
            text = (
                f"FEEDBACK TYPE: Missed Finding\n"
                f"FINDING TITLE: {feedback.missed_finding_title}\n"
                f"CATEGORY: {feedback.missed_finding_category} | SEVERITY: {feedback.missed_finding_severity}\n"
                f"DESCRIPTION: {feedback.missed_finding_description}\n"
                f"RECOMMENDATION: {feedback.missed_finding_recommendation}\n"
                f"CONTEXT: {feedback.explanation}"
            )
            metadata = {
                "category_tag": feedback.missed_finding_category or "",
                "severity": feedback.missed_finding_severity or "",
                "finding_title": feedback.missed_finding_title or "",
            }

        metadata["assessment_id"] = str(feedback.assessment_id) if feedback.assessment_id else ""
        metadata["submitted_by"] = feedback.submitted_by or ""
        return text, metadata


# ---------------------------------------------------------------------------
# RAG Context Builder — retrieves and formats feedback for prompt injection
# ---------------------------------------------------------------------------

class RAGContextBuilder:
    """
    Retrieves relevant past feedback from ChromaDB and formats it as a
    "PAST FEEDBACK CONTEXT" block to inject into analysis prompts.
    """

    # Cosine distance threshold — only include results that are similar enough
    SIMILARITY_THRESHOLD = 0.65

    def __init__(self):
        self.vector_store = VectorStore()

    def build_context(
        self,
        query: str,
        n_results: int = 8,
        user=None,
        assessment=None,
    ) -> str:
        """
        Query ChromaDB for relevant feedback and format as a prompt block.
        Returns an empty string if no relevant feedback is found.
        """
        results = self.vector_store.query_feedback_context(
            query=query,
            n_results=n_results,
            user=user,
            assessment=assessment,
        )

        # Filter by similarity threshold
        relevant = [r for r in results if r['distance'] <= self.SIMILARITY_THRESHOLD]
        if not relevant:
            return ""

        # Group by feedback type for readability
        fps, pcs, mfs = [], [], []
        for r in relevant:
            ft = r['metadata'].get('feedback_type', '')
            if ft == 'false_positive':
                fps.append(r['text'])
            elif ft == 'prior_control':
                pcs.append(r['text'])
            elif ft == 'missed_finding':
                mfs.append(r['text'])

        lines = [
            "\n\n=== RELEVANT PAST FEEDBACK (from human analysts) ===",
            "Use the following analyst corrections from similar past assessments to improve accuracy.\n",
        ]

        if fps:
            lines.append("--- FALSE POSITIVES TO AVOID ---")
            for i, text in enumerate(fps, 1):
                lines.append(f"[FP-{i}] {text}\n")

        if pcs:
            lines.append("--- PRIOR CONTROLS TO RECOGNISE ---")
            for i, text in enumerate(pcs, 1):
                lines.append(f"[PC-{i}] {text}\n")

        if mfs:
            lines.append("--- VULNERABILITIES PREVIOUSLY MISSED ---")
            for i, text in enumerate(mfs, 1):
                lines.append(f"[MF-{i}] {text}\n")

        lines.append("=== END OF PAST FEEDBACK ===\n")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Security Analyzer — main AI service, now RAG-augmented
# ---------------------------------------------------------------------------

class SecurityAnalyzer:
    """Main service for AI-powered security analysis with RAG feedback loop."""

    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self.vector_store = VectorStore()
        self.image_processor = ImageProcessor()
        self.rag_builder = RAGContextBuilder()

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _clean_llm_response(content: str) -> str:
        content = re.sub(r'^```json\s*', '', content, flags=re.MULTILINE)
        content = re.sub(r'^```\s*', '', content, flags=re.MULTILINE)
        content = re.sub(r'```$', '', content, flags=re.MULTILINE)
        return content.replace('`', '').strip()

    @staticmethod
    def _load_training_addendum() -> str:
        """
        Load the most recent completed TrainingJob's refined_system_prompt.
        This rule-based addendum complements the example-based RAG context.
        """
        try:
            from .models import TrainingJob
            job = TrainingJob.objects.filter(
                status='completed'
            ).order_by('-completed_at').first()
            if job and job.refined_system_prompt:
                return (
                    "\n\n=== LEARNED PATTERNS FROM HUMAN FEEDBACK ===\n"
                    + job.refined_system_prompt
                    + "\n=== END OF LEARNED PATTERNS ===\n\n"
                )
        except Exception:
            pass
        return ""

    def _chat(
        self,
        prompt: str,
        *,
        operation: str,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        user=None,
        assessment=None,
        training_job=None,
    ) -> str:
        """
        Call GPT-4o, track token usage, and return the response text.
        """
        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        usage = response.usage
        _track_usage(
            operation=operation,
            model_name='gpt-4o',
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            user=user,
            assessment=assessment,
            training_job=training_job,
        )
        return response.choices[0].message.content.strip()

    # ------------------------------------------------------------------ #
    # Core analysis                                                        #
    # ------------------------------------------------------------------ #

    def analyze_security(
        self,
        assessment_data: Dict,
        architecture_file: UploadedFile,
        user=None,
        assessment_obj=None,
    ) -> Tuple[int, str, List[Dict]]:
        """
        Perform comprehensive security analysis with RAG augmentation.

        Pipeline:
        1. Extract architecture details from diagram (Vision)
        2. Store assessment context chunks in ChromaDB
        3. Build RAG context from past feedback
        4. Load rule-based training addendum
        5. Calculate risk score (RAG + addendum augmented)
        6. Identify all vulnerabilities (RAG + addendum augmented)

        Returns: (risk_score, reasoning, vulnerabilities_list)
        """
        logger.info("Analyzing architecture diagram...")
        architecture_analysis = self.image_processor.extract_architecture_details(
            architecture_file, self.client,
            user=user, assessment=assessment_obj,
        )

        logger.info("Storing assessment context in ChromaDB...")
        assessment_data['architecture_analysis'] = architecture_analysis
        assessment_id = assessment_data.get('id', 'temp_id')
        self.vector_store.add_assessment_context(
            assessment_id, assessment_data,
            user=user, assessment_obj=assessment_obj,
        )

        context = self._build_analysis_context(assessment_data, architecture_analysis)

        # Build RAG context from past feedback (this is the learning loop)
        logger.info("Retrieving relevant past feedback from ChromaDB...")
        rag_context = self.rag_builder.build_context(
            query=context[:3000],  # use first 3k chars as semantic query
            n_results=10,
            user=user,
            assessment=assessment_obj,
        )

        # Load rule-based addendum from last training job
        addendum = self._load_training_addendum()

        # Combined augmentation = RAG examples + rule-based addendum
        augmentation = rag_context + addendum

        logger.info("Calculating risk score...")
        risk_score, reasoning = self._calculate_risk_score(
            context, augmentation, user=user, assessment=assessment_obj
        )

        logger.info("Identifying vulnerabilities...")
        vulnerabilities = self._identify_vulnerabilities(
            context, risk_score, augmentation, user=user, assessment=assessment_obj
        )

        return risk_score, reasoning, vulnerabilities

    def _build_analysis_context(self, assessment_data: Dict, architecture_analysis: str) -> str:
        context_parts = [
            "=== SECURITY ASSESSMENT CONTEXT ===\n",
            f"\n--- ARCHITECTURE ANALYSIS ---\n{architecture_analysis}\n"
        ]

        field_groups = {
            "APPLICATION CONTEXT": [
                'application_purpose', 'business_objectives', 'business_criticality',
                'regulatory_requirements', 'compliance_requirements'
            ],
            "TECHNOLOGY STACK": [
                'programming_languages', 'frameworks_versions', 'databases',
                'cloud_services', 'containerization_platforms'
            ],
            "SECURITY CONTROLS": [
                'authentication_mechanisms', 'authorization_model', 'encryption_at_rest',
                'encryption_in_transit', 'secrets_management', 'input_validation_controls'
            ],
            "NETWORK SECURITY": [
                'network_architecture', 'network_segmentation', 'firewall_config',
                'tls_configuration', 'zero_trust_controls'
            ],
            "DATA SECURITY": [
                'data_types_processed', 'sensitive_data_locations', 'data_retention_policies',
                'data_masking', 'key_rotation_practices'
            ],
            "INTEGRATIONS": [
                'third_party_integrations', 'external_apis', 'api_authentication', 'rate_limiting'
            ],
            "OPERATIONS": [
                'patch_management', 'logging_architecture', 'monitoring_coverage',
                'incident_response_procedures', 'backup_architecture'
            ],
            "COMPLIANCE": [
                'compliance_standards', 'prior_audit_findings', 'known_vulnerabilities', 'accepted_risks'
            ],
        }

        for group_name, fields in field_groups.items():
            group_data = [
                f"  - {f.replace('_', ' ').title()}: {assessment_data[f]}"
                for f in fields if assessment_data.get(f)
            ]
            if group_data:
                context_parts.append(f"\n--- {group_name} ---")
                context_parts.extend(group_data)

        return "\n".join(context_parts)

    def _calculate_risk_score(
        self,
        context: str,
        augmentation: str = "",
        user=None,
        assessment=None,
    ) -> Tuple[int, str]:
        prompt = f"""{augmentation}You are a senior security architect performing a comprehensive security risk assessment.

Based on the following application context and architecture analysis, calculate an overall security risk score from 0-100, where:
- 0-20: Low risk (well-secured, minimal concerns)
- 21-40: Low-Medium risk (good security posture with minor gaps)
- 41-60: Medium risk (moderate concerns requiring attention)
- 61-80: Medium-High risk (significant vulnerabilities present)
- 81-100: High risk (critical security issues, immediate action required)

Consider ALL aspects including architecture design, authentication, data protection, network security, cloud configurations, APIs, third-party integrations, logging/monitoring, compliance gaps, and known vulnerabilities.

{context}

Provide your response in the following JSON format (no markdown, no backticks):
{{
    "risk_score": <integer 0-100>,
    "reasoning": "<detailed multi-paragraph explanation of the risk score>"
}}"""

        content = self._chat(
            prompt,
            operation='risk_score',
            max_tokens=2000,
            temperature=0.3,
            user=user,
            assessment=assessment,
        )
        result = json.loads(self._clean_llm_response(content))
        return result['risk_score'], result['reasoning']

    def _identify_vulnerabilities(
        self,
        context: str,
        risk_score: int,
        augmentation: str = "",
        user=None,
        assessment=None,
    ) -> List[Dict]:
        prompt = f"""{augmentation}You are a security auditor performing an exhaustive vulnerability identification.

Based on the following application context, identify EVERY security vulnerability, misconfiguration, and risk across ALL domains: architecture/design flaws, authentication/authorization weaknesses, data security gaps, network issues, cloud misconfigurations, API security problems, missing controls, compliance gaps, operational concerns, third-party/supply-chain risks, logging/monitoring blind spots.

Overall Risk Score: {risk_score}/100

{context}

IMPORTANT: Do NOT limit the number of findings. Identify every single issue — there is no maximum cap.

For EACH vulnerability found, provide details in the following JSON format (valid JSON array only, no markdown):

[
    {{
        "control_title": "Brief, clear title of the security issue",
        "control_description": "It was observed that [detailed description]",
        "control_impact": "If exploited, this vulnerability could [specific consequences]",
        "control_recommendation": "It is recommended to [specific, actionable steps]",
        "severity": "critical|high|medium|low|informational",
        "affected_devices": "Specific components affected",
        "category_tag": "One of: Authentication, Authorization, Data Protection, Network Security, Cloud Security, API Security, Cryptography, Input Validation, Session Management, Configuration, Logging & Monitoring, Compliance, Architecture, Third-Party",
        "framework_mapping": "Relevant frameworks (e.g., OWASP Top 10, NIST CSF, CIS Controls, ISO 27001)",
        "cvss_score": 7.5,
        "cwe_id": "CWE-XXX",
        "owasp_category": "Relevant OWASP category if applicable"
    }}
]"""

        content = self._chat(
            prompt,
            operation='vulnerability_identification',
            max_tokens=16000,
            temperature=0.4,
            user=user,
            assessment=assessment,
        )
        return json.loads(self._clean_llm_response(content))

    # ------------------------------------------------------------------ #
    # Severity recalculation                                               #
    # ------------------------------------------------------------------ #

    def recalculate_vulnerability_severity(
        self,
        vulnerability_data: Dict,
        implemented_controls: List[Dict],
        user=None,
        assessment=None,
    ) -> Tuple[str, str]:
        controls_summary = "\n".join([
            f"  - [{c['status'].upper()}] {c['control_name']}: {c['control_description']} "
            f"(Risk Reduction: {c.get('risk_reduction_percentage', 0)}%)"
            for c in implemented_controls
        ]) or "  (no controls added yet)"

        prompt = f"""You are a senior security engineer re-evaluating the severity of a vulnerability
after remediation controls have been applied.

ORIGINAL VULNERABILITY:
  Title       : {vulnerability_data.get('control_title', 'N/A')}
  Description : {vulnerability_data.get('control_description', 'N/A')}
  Impact      : {vulnerability_data.get('control_impact', 'N/A')}
  Category    : {vulnerability_data.get('category_tag', 'N/A')}
  CVSS Score  : {vulnerability_data.get('cvss_score', 'N/A')}
  CWE         : {vulnerability_data.get('cwe_id', 'N/A')}
  Original Severity: {vulnerability_data.get('severity', 'N/A')}

CONTROLS APPLIED:
{controls_summary}

Determine the RESIDUAL severity considering: control effectiveness, implementation completeness, residual attack surface, and compensating controls.

Respond ONLY with valid JSON (no markdown):
{{
    "severity": "critical|high|medium|low|informational",
    "reasoning": "<explanation>"
}}"""

        try:
            content = self._chat(
                prompt,
                operation='severity_recalculation',
                max_tokens=800,
                temperature=0.2,
                user=user,
                assessment=assessment,
            )
            result = json.loads(self._clean_llm_response(content))
            return result['severity'], result['reasoning']
        except Exception as e:
            raise Exception(f"Error recalculating severity: {str(e)}")

    # ------------------------------------------------------------------ #
    # Evidence verification                                                #
    # ------------------------------------------------------------------ #

    def verify_evidence_file(
        self,
        control_data: Dict,
        vulnerability_data: Dict,
        evidence_file,
        user=None,
        assessment=None,
    ) -> Tuple[bool, str]:
        """Analyse an uploaded evidence file and determine if it proves implementation."""
        verification_context = (
            f"Control being verified:\n"
            f"  Name        : {control_data.get('control_name', 'N/A')}\n"
            f"  Description : {control_data.get('control_description', 'N/A')}\n"
            f"  Details     : {control_data.get('implementation_details', 'N/A')}\n\n"
            f"Vulnerability it addresses:\n"
            f"  Title    : {vulnerability_data.get('control_title', 'N/A')}\n"
            f"  Category : {vulnerability_data.get('category_tag', 'N/A')}\n"
            f"  Severity : {vulnerability_data.get('severity', 'N/A')}"
        )

        audit_instructions = (
            "You are a security auditor verifying that a remediation control has been "
            "properly implemented. Analyse the evidence and determine:\n"
            "1. Does it clearly prove the control is in place?\n"
            "2. Are there any gaps, misconfigurations, or missing elements?\n"
            "3. Would you accept this as sufficient evidence of implementation?\n\n"
            "Respond ONLY with valid JSON (no markdown):\n"
            '{"passed": true|false, "analysis": "<detailed findings>"}'
        )

        try:
            content_type, extracted, filename = ImageProcessor.extract_file_content(evidence_file)
        except Exception as e:
            return False, f"Could not read evidence file: {e}"

        try:
            if content_type == 'image':
                messages = [{
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                audit_instructions + "\n\n" + verification_context
                                + f"\n\nEvidence file: {filename} (image)\nThe image is attached below."
                            )
                        },
                        {"type": "image_url", "image_url": {"url": extracted}}
                    ]
                }]
            elif content_type == 'binary':
                messages = [{
                    "role": "user",
                    "content": (
                        audit_instructions + "\n\n" + verification_context
                        + f"\n\nEvidence file: {filename} (binary — first 512 bytes as hex)\n\n"
                        + f"HEX PREVIEW:\n{extracted}\n\n"
                        "Note: binary file, assess based on control description plausibility."
                    )
                }]
            else:
                type_label = {
                    'text': 'text/config/code', 'pdf': 'PDF',
                    'docx': 'Word document', 'xlsx': 'spreadsheet'
                }.get(content_type, content_type)
                messages = [{
                    "role": "user",
                    "content": (
                        audit_instructions + "\n\n" + verification_context
                        + f"\n\nEvidence file: {filename} ({type_label})\n\n"
                        + "FILE CONTENT:\n```\n" + extracted + "\n```"
                    )
                }]

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=0.2,
                max_tokens=1200,
            )
            usage = response.usage
            _track_usage(
                operation='evidence_verification',
                model_name='gpt-4o',
                prompt_tokens=usage.prompt_tokens,
                completion_tokens=usage.completion_tokens,
                total_tokens=usage.total_tokens,
                user=user,
                assessment=assessment,
            )
            result_text = self._clean_llm_response(response.choices[0].message.content.strip())
            result = json.loads(result_text)
            return bool(result.get("passed", False)), result.get("analysis", "")
        except Exception as e:
            return False, f"Evidence verification failed: {str(e)}"

    # ------------------------------------------------------------------ #
    # Risk reduction calculation                                           #
    # ------------------------------------------------------------------ #

    def calculate_risk_reduction(
        self,
        control_data: Dict,
        vulnerability_data: Dict,
        evidence_analyses: List[str],
        evidence_all_passed: bool,
        user=None,
        assessment=None,
    ) -> Tuple[int, str]:
        evidence_summary = (
            "\n".join(f"  - {a}" for a in evidence_analyses)
            if evidence_analyses else "  (no evidence analyses available)"
        )

        prompt = (
            "You are a senior security engineer calculating the risk reduction percentage "
            "that a remediation control provides for a specific vulnerability.\n\n"
            f"VULNERABILITY:\n"
            f"  Title       : {vulnerability_data.get('control_title', 'N/A')}\n"
            f"  Description : {vulnerability_data.get('control_description', 'N/A')}\n"
            f"  Impact      : {vulnerability_data.get('control_impact', 'N/A')}\n"
            f"  Category    : {vulnerability_data.get('category_tag', 'N/A')}\n"
            f"  Severity    : {vulnerability_data.get('severity', 'N/A')}\n"
            f"  CVSS        : {vulnerability_data.get('cvss_score', 'N/A')}\n\n"
            f"CONTROL BEING APPLIED:\n"
            f"  Name        : {control_data.get('control_name', 'N/A')}\n"
            f"  Description : {control_data.get('control_description', 'N/A')}\n"
            f"  Details     : {control_data.get('implementation_details', 'N/A')}\n"
            f"  Status      : {control_data.get('status', 'N/A')}\n\n"
            f"EVIDENCE VERIFICATION:\n"
            f"  All evidence passed: {evidence_all_passed}\n"
            f"  Analyses:\n{evidence_summary}\n\n"
            "Estimate the percentage (0-100) by which this control reduces vulnerability risk.\n"
            "Scale: 0-20%=minor; 21-40%=partial; 41-60%=meaningful; 61-80%=strong; 81-100%=near-complete\n\n"
            "Respond ONLY with valid JSON (no markdown):\n"
            '{"risk_reduction_percentage": <integer 0-100>, "reasoning": "<explanation>"}'
        )

        try:
            content = self._chat(
                prompt,
                operation='risk_reduction',
                max_tokens=600,
                temperature=0.2,
                user=user,
                assessment=assessment,
            )
            result = json.loads(self._clean_llm_response(content))
            pct = max(0, min(100, int(result["risk_reduction_percentage"])))
            return pct, result.get("reasoning", "")
        except Exception as e:
            raise Exception(f"Error calculating risk reduction: {str(e)}")

    # ------------------------------------------------------------------ #
    # Risk recalculation after controls are applied                        #
    # ------------------------------------------------------------------ #

    def recalculate_risk_with_controls(
        self,
        assessment_id: str,
        original_context: str,
        remediation_controls: List[Dict],
        user=None,
        assessment=None,
    ) -> Tuple[int, str]:
        controls_summary = "\n".join([
            f"- {c['control_name']}: {c['control_description']} "
            f"(Risk Reduction: {c['risk_reduction_percentage']}%)"
            for c in remediation_controls if c.get('status') == 'implemented'
        ])

        prompt = f"""You are recalculating the security risk score after remediation controls have been implemented.

ORIGINAL CONTEXT:
{original_context}

IMPLEMENTED CONTROLS:
{controls_summary}

Calculate the NEW risk score (0-100) considering original vulnerabilities, implemented controls, effectiveness, and residual risks.

Provide response in JSON format (no markdown):
{{
    "new_risk_score": <integer 0-100>,
    "reasoning": "<explanation of score change and residual risks>"
}}"""

        content = self._chat(
            prompt,
            operation='risk_with_controls',
            max_tokens=1500,
            temperature=0.3,
            user=user,
            assessment=assessment,
        )
        result = json.loads(self._clean_llm_response(content))
        return result['new_risk_score'], result['reasoning']


# ---------------------------------------------------------------------------
# Feedback-driven training service — now also re-indexes all feedback into
# ChromaDB so the vector store stays consistent with the DB.
# ---------------------------------------------------------------------------

class FeedbackTrainer:
    """
    Distils accumulated VulnerabilityFeedback records into:
    1. An updated system-prompt addendum (rule-based guidance)
    2. A fully up-to-date ChromaDB feedback collection (example-based RAG)

    Both outputs are used at inference time, complementing each other.
    """

    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self.vector_store = VectorStore()
        self.indexer = FeedbackVectorIndexer()

    def run_weekly_training(self, user=None) -> 'TrainingJob':  # noqa: F821
        """
        Entry point called by the weekly Celery beat task or manual trigger.
        """
        from .models import VulnerabilityFeedback, TrainingJob

        job = TrainingJob.objects.create(status='running', started_at=timezone.now())

        try:
            feedback_qs = VulnerabilityFeedback.objects.filter(
                incorporated_in_training=False
            ).select_related('vulnerable_component', 'assessment')

            if not feedback_qs.exists():
                job.status = 'completed'
                job.completed_at = timezone.now()
                job.training_summary = "No new feedback to incorporate."
                job.save()
                return job

            # Step 1: Re-index ALL unincorporated feedback into ChromaDB
            logger.info("[training] Re-indexing feedback into ChromaDB...")
            chroma_count = 0
            for fb in feedback_qs:
                try:
                    self.indexer.index(fb, user=user)
                    chroma_count += 1
                except Exception as exc:
                    logger.warning("[training] Failed to index feedback %s: %s", fb.id, exc)

            # Step 2: Serialise feedback into structured text for addendum generation
            fp_items, pc_items, mf_items = [], [], []
            for fb in feedback_qs:
                if fb.feedback_type == 'false_positive':
                    fp_items.append(self._serialise_fp(fb))
                elif fb.feedback_type == 'prior_control':
                    pc_items.append(self._serialise_pc(fb))
                elif fb.feedback_type == 'missed_finding':
                    mf_items.append(self._serialise_mf(fb))

            # Step 3: Generate rule-based addendum via GPT-4o
            logger.info("[training] Generating refined system prompt addendum...")
            addendum, summary = self._generate_addendum(
                fp_items, pc_items, mf_items, user=user, training_job=job
            )

            # Step 4: Persist results
            job.feedback_count = feedback_qs.count()
            job.false_positive_count = len(fp_items)
            job.prior_control_count = len(pc_items)
            job.missed_finding_count = len(mf_items)
            job.chroma_indexed_count = chroma_count
            job.refined_system_prompt = addendum
            job.training_summary = summary
            job.status = 'completed'
            job.completed_at = timezone.now()
            job.save()

            # Step 5: Mark all feedback as incorporated
            feedback_qs.update(incorporated_in_training=True, training_job=job)

            logger.info(
                "[training] Completed. job=%s feedback=%s chroma_indexed=%s",
                job.id, job.feedback_count, chroma_count,
            )
            return job

        except Exception as e:
            job.status = 'failed'
            job.error_message = str(e)
            job.completed_at = timezone.now()
            job.save()
            raise

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _serialise_fp(fb) -> str:
        vc = fb.vulnerable_component
        title = vc.control_title if vc else "Unknown"
        category = vc.category_tag if vc else "Unknown"
        return (
            f"Finding: '{title}' (Category: {category})\n"
            f"False-positive reason: {fb.false_positive_reason or fb.explanation}"
        )

    @staticmethod
    def _serialise_pc(fb) -> str:
        vc = fb.vulnerable_component
        title = vc.control_title if vc else "Unknown"
        return (
            f"Finding: '{title}'\n"
            f"Pre-existing control: {fb.prior_control_name} — {fb.prior_control_description}\n"
            f"Context: {fb.explanation}"
        )

    @staticmethod
    def _serialise_mf(fb) -> str:
        return (
            f"Missed finding: '{fb.missed_finding_title}'\n"
            f"Severity: {fb.missed_finding_severity} | Category: {fb.missed_finding_category}\n"
            f"Description: {fb.missed_finding_description}\n"
            f"Recommendation: {fb.missed_finding_recommendation}"
        )

    def _generate_addendum(
        self,
        fp_items: List[str],
        pc_items: List[str],
        mf_items: List[str],
        user=None,
        training_job=None,
    ) -> Tuple[str, str]:
        """Ask GPT-4o to synthesise feedback into concise analyst guidelines."""

        fp_block = "\n\n".join(fp_items) if fp_items else "(none)"
        pc_block = "\n\n".join(pc_items) if pc_items else "(none)"
        mf_block = "\n\n".join(mf_items) if mf_items else "(none)"

        prompt = f"""You are a senior security analyst synthesising analyst feedback to improve an
AI security assessment system. Below are three categories of feedback. Distil them into
concise ANALYST GUIDELINES (max 800 words) that, when prepended to future prompts, will make the AI:
1. Stop raising false positives like the ones described
2. Recognise and credit pre-existing controls when present
3. Catch vulnerabilities that were previously missed

FALSE POSITIVES REPORTED:
{fp_block}

PRE-EXISTING CONTROLS THAT SHOULD HAVE BEEN RECOGNISED:
{pc_block}

MISSED FINDINGS THAT SHOULD HAVE BEEN RAISED:
{mf_block}

Write guidelines as a numbered list of clear, actionable instructions addressed to the AI analyst.
Be specific. Reference patterns, not individual assessments.

Also produce a one-paragraph TRAINING SUMMARY for human reviewers.

Respond with valid JSON only (no markdown):
{{
    "addendum": "<the analyst guidelines text>",
    "summary": "<one-paragraph summary for human reviewers>"
}}"""

        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1500
        )
        usage = response.usage
        _track_usage(
            operation='feedback_training',
            model_name='gpt-4o',
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            user=user,
            training_job=training_job,
        )

        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json\s*', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'^```\s*', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'```$', '', raw, flags=re.MULTILINE)
        raw = raw.replace('`', '').strip()
        result = json.loads(raw)
        return result['addendum'], result['summary']