import os
import base64
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from io import BytesIO
from PIL import Image
import chromadb
from chromadb.config import Settings
from openai import OpenAI
from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.utils import timezone


class ImageProcessor:
    """Process and analyze architecture diagrams"""
    
    @staticmethod
    def process_image(image_file: UploadedFile) -> tuple:
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
                    pix = page.get_pixmap(matrix=fitz.Matrix(300/72, 300/72))
                    image_data = pix.tobytes("png")
                    mime_type = 'image/png'
                    pdf_document.close()
                except ImportError:
                    try:
                        from pdf2image import convert_from_bytes
                        images = convert_from_bytes(image_data, first_page=1, last_page=1)
                        if images:
                            img_byte_arr = BytesIO()
                            images[0].save(img_byte_arr, format='PNG')
                            image_data = img_byte_arr.getvalue()
                            mime_type = 'image/png'
                    except ImportError:
                        raise Exception("PDF support requires 'PyMuPDF' or 'pdf2image'.")
            else:
                mime_types = {
                    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
                    'png': 'image/png', 'gif': 'image/gif',
                    'bmp': 'image/bmp', 'webp': 'image/webp',
                    'tiff': 'image/tiff', 'tif': 'image/tiff'
                }
                mime_type = mime_types.get(ext, 'image/jpeg')
                try:
                    img = Image.open(BytesIO(image_data))
                    img.verify()
                    image_file.seek(0)
                    image_data = image_file.read()
                except Exception as e:
                    raise Exception(f"Invalid image file: {str(e)}")
            
            base64_image = base64.b64encode(image_data).decode('utf-8')
            image_file.seek(0)
            return base64_image, mime_type
            
        except Exception as e:
            raise Exception(f"Error processing image: {str(e)}")

    # Extensions the AI can read as images (sent via image_url)
    IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'tif', 'svg'}

    # Extensions whose raw bytes can be decoded directly as UTF-8 / latin-1 text
    TEXT_EXTENSIONS = {
        'txt', 'log', 'md', 'rst', 'csv', 'tsv',
        'yaml', 'yml', 'json', 'xml', 'toml', 'ini', 'cfg', 'conf', 'env',
        'sh', 'bash', 'zsh', 'ps1', 'bat', 'cmd',
        'py', 'js', 'ts', 'rb', 'go', 'java', 'kt', 'cs', 'cpp', 'c', 'h',
        'tf', 'tfvars', 'hcl',          # Terraform / HCL
        'dockerfile', 'dockerignore',
        'sql', 'graphql', 'proto',
        'html', 'htm', 'css',
        'properties', 'pem', 'crt', 'key', 'pub',
    }

    @staticmethod
    def file_to_base64(file_obj) -> Tuple[str, str]:
        """Return (base64_bytes, mime_type) for image files only (legacy helper)."""
        if hasattr(file_obj, 'seek'):
            file_obj.seek(0)
        raw = file_obj.read() if hasattr(file_obj, 'read') else open(file_obj, 'rb').read()
        name = getattr(file_obj, 'name', str(file_obj))
        ext = name.split('.')[-1].lower()
        mime_map = {
            'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
            'png': 'image/png', 'gif': 'image/gif',
            'bmp': 'image/bmp', 'webp': 'image/webp',
            'tiff': 'image/tiff', 'tif': 'image/tiff',
            'pdf': 'application/pdf',
        }
        mime_type = mime_map.get(ext, 'application/octet-stream')
        return base64.b64encode(raw).decode('utf-8'), mime_type

    @classmethod
    def extract_file_content(cls, file_obj) -> Tuple[str, str, str]:
        """
        Extract readable content from any uploaded file.

        Returns:
            (content_type, extracted_text_or_b64, filename)

        content_type is one of: 'image' | 'text' | 'pdf' | 'docx' | 'binary'

        - 'image'  : base64 data-URI sent to GPT-4o Vision
        - 'text'   : decoded text, truncated to 12 000 chars
        - 'pdf'    : text extracted from PDF pages
        - 'docx'   : text extracted from Word document paragraphs
        - 'binary' : hex-encoded preview of first 512 bytes
        """
        if hasattr(file_obj, 'seek'):
            file_obj.seek(0)
        raw_bytes = file_obj.read() if hasattr(file_obj, 'read') else open(file_obj, 'rb').read()

        name = getattr(file_obj, 'name', str(file_obj))
        # Handle filenames with no extension (e.g. 'Dockerfile')
        parts = name.rsplit('.', 1)
        ext = parts[1].lower() if len(parts) == 2 else name.lower()

        # Images
        if ext in cls.IMAGE_EXTENSIONS:
            mime_map = {
                'jpg': 'image/jpeg',  'jpeg': 'image/jpeg',
                'png': 'image/png',   'gif': 'image/gif',
                'bmp': 'image/bmp',   'webp': 'image/webp',
                'tiff': 'image/tiff', 'tif': 'image/tiff',
                'svg': 'image/svg+xml',
            }
            mime = mime_map.get(ext, 'image/jpeg')
            b64 = base64.b64encode(raw_bytes).decode('utf-8')
            return 'image', f"data:{mime};base64,{b64}", name

        # PDF
        if ext == 'pdf':
            try:
                import fitz  # PyMuPDF
                doc = fitz.open(stream=raw_bytes, filetype='pdf')
                pages_text = [page.get_text() for page in doc]
                doc.close()
                return 'pdf', '\n'.join(pages_text)[:20000], name
            except ImportError:
                pass
            try:
                import pdfplumber
                import io as _io
                with pdfplumber.open(_io.BytesIO(raw_bytes)) as pdf:
                    text = '\n'.join(p.extract_text() or '' for p in pdf.pages)
                return 'pdf', text[:20000], name
            except ImportError:
                pass
            return 'pdf', raw_bytes.decode('latin-1', errors='replace')[:20000], name

        # Word documents
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

        # Excel / spreadsheets
        if ext in ('xlsx', 'xls', 'ods'):
            try:
                import openpyxl
                import io as _io
                wb = openpyxl.load_workbook(_io.BytesIO(raw_bytes), read_only=True, data_only=True)
                rows = []
                for sheet in wb.worksheets:
                    rows.append(f'[Sheet: {sheet.title}]')
                    for row in sheet.iter_rows(values_only=True):
                        rows.append('\t'.join(str(c) if c is not None else '' for c in row))
                return 'text', '\n'.join(rows)[:20000], name
            except ImportError:
                pass
            return 'binary', raw_bytes[:512].hex(), name

        # Plain text / config / code / YAML / JSON / CSV / etc.
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

        # Unknown extension — try UTF-8, fall back to binary
        try:
            text = raw_bytes.decode('utf-8')
            if len(text) > 12000:
                text = text[:12000] + '\n\n... [truncated]'
            return 'text', text, name
        except UnicodeDecodeError:
            return 'binary', raw_bytes[:512].hex(), name

    @staticmethod
    def extract_architecture_details(image_file: UploadedFile, client: OpenAI) -> str:
        """Extract detailed architecture information from diagram using GPT-4 Vision"""
        base64_image, mime_type = ImageProcessor.process_image(image_file)
        
        prompt = """You are an expert security architect analyzing an architecture diagram. 
        Extract ALL technical details visible in this architecture diagram including:
        
        1. All components, services, and systems shown
        2. Data flow paths and connections between components
        3. Network boundaries and security zones
        4. External integrations and third-party services
        5. Database and storage systems
        6. Load balancers, gateways, and infrastructure components
        7. Authentication/authorization flows
        8. Any security controls visible (firewalls, WAF, etc.)
        9. Cloud services and deployment architecture
        10. Any labels, annotations, or notes on the diagram
        
        Provide a comprehensive, detailed description that captures every technical element 
        visible in the diagram. Be specific about technologies, connections, and configurations shown."""
        
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
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise Exception(f"Error analyzing architecture diagram: {str(e)}")


class VectorStore:
    """Manage ChromaDB vector store for RAG"""
    
    def __init__(self):
        self.client = chromadb.PersistentClient(
            path=settings.CHROMADB_PATH,
            settings=Settings(anonymized_telemetry=False, allow_reset=True)
        )
        self.collection = self.client.get_or_create_collection(
            name="security_knowledge",
            metadata={"hnsw:space": "cosine"}
        )
        self.openai_client = OpenAI(api_key=settings.OPENAI_API_KEY)
    
    def get_embedding(self, text: str) -> List[float]:
        response = self.openai_client.embeddings.create(
            model="text-embedding-3-small",
            input=text
        )
        return response.data[0].embedding
    
    def add_assessment_context(self, assessment_id: str, context_data: Dict):
        chunks = []
        
        if context_data.get('architecture_analysis'):
            chunks.append({
                'text': f"Architecture Analysis: {context_data['architecture_analysis']}",
                'type': 'architecture', 'assessment_id': assessment_id
            })
        
        for group_name, fields in [
            ('technology', ['programming_languages', 'frameworks_versions', 'databases', 'cloud_services', 'containerization_platforms']),
            ('security_controls', ['authentication_mechanisms', 'authorization_model', 'encryption_at_rest', 'encryption_in_transit', 'input_validation_controls', 'api_authentication']),
            ('network', ['network_architecture', 'network_segmentation', 'firewall_config', 'load_balancers', 'cdn_usage']),
        ]:
            data = [f"{f.replace('_', ' ').title()}: {context_data[f]}" for f in fields if context_data.get(f)]
            if data:
                chunks.append({'text': f"{group_name.title()}: " + "; ".join(data), 'type': group_name, 'assessment_id': assessment_id})
        
        for idx, chunk in enumerate(chunks):
            embedding = self.get_embedding(chunk['text'])
            self.collection.add(
                embeddings=[embedding],
                documents=[chunk['text']],
                metadatas=[{'assessment_id': assessment_id, 'type': chunk['type']}],
                ids=[f"{assessment_id}_{chunk['type']}_{idx}"]
            )
    
    def query_context(self, query: str, assessment_id: str, n_results: int = 5) -> List[str]:
        embedding = self.get_embedding(query)
        results = self.collection.query(
            query_embeddings=[embedding],
            n_results=n_results,
            where={"assessment_id": assessment_id}
        )
        return results['documents'][0] if results['documents'] else []


class SecurityAnalyzer:
    """Main service for AI-powered security analysis"""
    
    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self.vector_store = VectorStore()
        self.image_processor = ImageProcessor()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_llm_response(content: str) -> str:
        content = re.sub(r'^```json\s*', '', content, flags=re.MULTILINE)
        content = re.sub(r'^```\s*', '', content, flags=re.MULTILINE)
        content = re.sub(r'```$', '', content, flags=re.MULTILINE)
        content = content.replace('`', '')
        return content.strip()

    @staticmethod
    def _load_training_addendum() -> str:
        """
        Load the most recent completed TrainingJob's refined_system_prompt,
        if any. This addendum is prepended to analysis prompts so the model
        learns from all accumulated human feedback without a full fine-tune.
        """
        try:
            from .models import TrainingJob
            job = TrainingJob.objects.filter(status='completed').order_by('-completed_at').first()
            if job and job.refined_system_prompt:
                return (
                    "\n\n=== LEARNED PATTERNS FROM HUMAN FEEDBACK ===\n"
                    + job.refined_system_prompt
                    + "\n=== END OF LEARNED PATTERNS ===\n\n"
                )
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def analyze_security(
        self,
        assessment_data: Dict,
        architecture_file: UploadedFile
    ) -> Tuple[int, str, List[Dict]]:
        """
        Perform comprehensive security analysis.

        Returns:
            Tuple of (risk_score, reasoning, vulnerabilities_list)
        """
        print("Analyzing architecture diagram...")
        architecture_analysis = self.image_processor.extract_architecture_details(
            architecture_file, self.client
        )
        
        print("Storing assessment context...")
        assessment_data['architecture_analysis'] = architecture_analysis
        assessment_id = assessment_data.get('id', 'temp_id')
        self.vector_store.add_assessment_context(assessment_id, assessment_data)
        
        context = self._build_analysis_context(assessment_data, architecture_analysis)
        addendum = self._load_training_addendum()

        print("Performing AI security analysis...")
        risk_score, reasoning = self._calculate_risk_score(context, addendum)
        
        print("Identifying vulnerabilities...")
        vulnerabilities = self._identify_vulnerabilities(context, risk_score, addendum)
        
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
            ]
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

    def _calculate_risk_score(self, context: str, addendum: str = "") -> Tuple[int, str]:
        prompt = f"""{addendum}You are a senior security architect performing a comprehensive security risk assessment.

Based on the following application context and architecture analysis, calculate an overall security risk score from 0-100, where:
- 0-20: Low risk (well-secured, minimal concerns)
- 21-40: Low-Medium risk (good security posture with minor gaps)
- 41-60: Medium risk (moderate concerns requiring attention)
- 61-80: Medium-High risk (significant vulnerabilities present)
- 81-100: High risk (critical security issues, immediate action required)

Consider ALL aspects including:
1. Architecture design flaws and security patterns
2. Authentication and authorization mechanisms
3. Data protection and encryption
4. Network security and segmentation
5. Cloud security configurations
6. API security
7. Third-party integrations and dependencies
8. Logging, monitoring, and incident response
9. Compliance gaps
10. Known vulnerabilities and technical debt

{context}

Provide your response in the following JSON format (no markdown, no backticks):
{{
    "risk_score": <integer 0-100>,
    "reasoning": "<detailed multi-paragraph explanation of the risk score, covering key security concerns across all areas>"
}}"""
        
        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=2000
        )
        content = self._clean_llm_response(response.choices[0].message.content.strip())
        result = json.loads(content)
        return result['risk_score'], result['reasoning']

    def _identify_vulnerabilities(
        self,
        context: str,
        risk_score: int,
        addendum: str = ""
    ) -> List[Dict]:
        """
        Identify ALL vulnerabilities — no artificial cap.
        The prompt explicitly asks for exhaustive coverage and instructs the
        model to keep going until it has identified every issue it can find.
        """
        prompt = f"""{addendum}You are a security auditor performing an exhaustive vulnerability identification.

Based on the following application context, identify EVERY security vulnerability, misconfiguration, and risk you can find across ALL domains:
- Architecture and design flaws
- Authentication/authorization weaknesses
- Data security gaps
- Network security issues
- Cloud misconfigurations
- API security problems
- Missing security controls
- Compliance gaps
- Operational security concerns
- Third-party and supply-chain risks
- Logging and monitoring blind spots

Overall Risk Score: {risk_score}/100

{context}

IMPORTANT: Do NOT limit the number of findings. Identify every single issue you can find — there is no maximum. A thorough assessment is required regardless of how many findings that produces.

For EACH vulnerability found, provide details in the following JSON format (respond with a valid JSON array only, no markdown, no backticks):

[
    {{
        "control_title": "Brief, clear title of the security issue",
        "control_description": "It was observed that [detailed description of what was found, be specific]",
        "control_impact": "If exploited, this vulnerability could [describe specific consequences and business impact]",
        "control_recommendation": "It is recommended to [specific, actionable remediation steps]",
        "severity": "critical|high|medium|low|informational",
        "affected_devices": "Specific components, services, or systems affected",
        "category_tag": "One of: Authentication, Authorization, Data Protection, Network Security, Cloud Security, API Security, Cryptography, Input Validation, Session Management, Configuration, Logging & Monitoring, Compliance, Architecture, Third-Party",
        "framework_mapping": "Relevant frameworks (e.g., OWASP Top 10, NIST CSF, CIS Controls, ISO 27001)",
        "cvss_score": 7.5,
        "cwe_id": "CWE-XXX",
        "owasp_category": "Relevant OWASP category if applicable"
    }}
]"""

        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=16000   # Increase token budget so large finding sets aren't truncated
        )
        content = self._clean_llm_response(response.choices[0].message.content.strip())
        return json.loads(content)

    # ------------------------------------------------------------------
    # Severity auto-calculation after a control is added
    # ------------------------------------------------------------------

    def recalculate_vulnerability_severity(
        self,
        vulnerability_data: Dict,
        implemented_controls: List[Dict]
    ) -> Tuple[str, str]:
        """
        Re-evaluate the severity of a vulnerability given the controls that have
        been added for it.

        Returns:
            (new_severity, reasoning)  where new_severity is one of
            critical / high / medium / low / informational
        """
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

Based on the controls applied, determine the RESIDUAL severity of this vulnerability.
Consider:
1. How effectively each control addresses the root cause
2. Whether the controls are fully implemented or still planned/in-progress
3. Any residual attack surface that remains
4. Compensating controls that reduce exploitability

Respond ONLY with valid JSON (no markdown, no backticks):
{{
    "severity": "critical|high|medium|low|informational",
    "reasoning": "<explanation of why the severity changed or stayed the same given the controls>"
}}"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=800
            )
            content = self._clean_llm_response(response.choices[0].message.content.strip())
            result = json.loads(content)
            return result['severity'], result['reasoning']
        except Exception as e:
            raise Exception(f"Error recalculating severity: {str(e)}")

    # ------------------------------------------------------------------
    # Evidence file verification
    # ------------------------------------------------------------------

    def verify_evidence_file(
        self,
        control_data: Dict,
        vulnerability_data: Dict,
        evidence_file
    ) -> Tuple[bool, str]:
        """
        Analyse an uploaded evidence file of ANY format and determine whether it
        sufficiently proves the remediation control is implemented.

        Supported formats (non-exhaustive):
          Images   : jpg, jpeg, png, gif, bmp, webp, tiff, svg
          Documents: pdf, docx, doc, xlsx, xls
          Text/Code: txt, log, md, yaml, yml, json, xml, toml, ini, cfg, conf,
                     env, sh, bash, ps1, tf, tfvars, hcl, dockerfile, sql,
                     py, js, ts, rb, go, java, kt, cs, cpp, html, csv, ...
          Binary   : any other format (hex preview shown to the AI)

        Returns:
            (passed: bool, analysis: str)
        """
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
            "properly implemented. Analyse the evidence provided and determine:\n"
            "1. Does it clearly prove the control is in place?\n"
            "2. Are there any gaps, misconfigurations, or missing elements?\n"
            "3. Would you accept this as sufficient evidence of implementation?\n\n"
            "Respond ONLY with valid JSON (no markdown, no backticks):\n"
            '{"passed": true|false, "analysis": "<detailed findings>"}'
        )

        try:
            content_type, extracted, filename = ImageProcessor.extract_file_content(evidence_file)
        except Exception as e:
            return False, f"Could not read evidence file: {e}"

        try:
            if content_type == 'image':
                # Send as vision message
                messages = [{
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                audit_instructions + "\n\n" + verification_context
                                + f"\n\nEvidence file: {filename} (image)"
                                + "\n\nThe image is attached below."
                            )
                        },
                        {"type": "image_url", "image_url": {"url": extracted}}
                    ]
                }]
            elif content_type == 'binary':
                # Binary file — send hex preview and note the limitation
                messages = [{
                    "role": "user",
                    "content": (
                        audit_instructions + "\n\n" + verification_context
                        + f"\n\nEvidence file: {filename} (binary — first 512 bytes shown as hex)\n\n"
                        + f"HEX PREVIEW:\n{extracted}\n\n"
                        "Note: this is a binary file and its full content cannot be inspected. "
                        "Base your assessment primarily on whether the control description and "
                        "implementation details are plausible and consistent."
                    )
                }]
            else:
                # text, pdf, docx, xlsx — full content available
                type_label = {
                    'text': 'text/config/code', 'pdf': 'PDF',
                    'docx': 'Word document', 'xlsx': 'spreadsheet'
                }.get(content_type, content_type)
                messages = [{
                    "role": "user",
                    "content": (
                        audit_instructions + "\n\n" + verification_context
                        + f"\n\nEvidence file: {filename} ({type_label})\n\n"
                        + "FILE CONTENT:\n"
                        + "```\n" + extracted + "\n```"
                    )
                }]

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=0.2,
                max_tokens=1200
            )
            result_text = self._clean_llm_response(response.choices[0].message.content.strip())
            result = json.loads(result_text)
            passed = result.get("passed")
            if passed is None:
                passed = False
            return bool(passed), result.get("analysis", "")

        except Exception as e:
            return False, f"Evidence verification failed: {str(e)}"

    def calculate_risk_reduction(
        self,
        control_data: Dict,
        vulnerability_data: Dict,
        evidence_analyses: List[str],
        evidence_all_passed: bool,
    ) -> Tuple[int, str]:
        """
        Ask the AI to calculate what percentage of risk this control reduces for
        the given vulnerability, factoring in the evidence quality.

        Returns:
            (risk_reduction_percentage: int 0-100, reasoning: str)
        """
        evidence_summary = (
            "\n".join(f"  - {a}" for a in evidence_analyses)
            if evidence_analyses
            else "  (no evidence analyses available)"
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
            f"  All evidence passed AI verification: {evidence_all_passed}\n"
            f"  Evidence analyses:\n{evidence_summary}\n\n"
            "Based on the above, estimate the percentage (0-100) by which this control "
            "reduces the risk of the vulnerability being exploited. Consider:\n"
            "1. How directly the control addresses the root cause\n"
            "2. Whether the evidence confirms full implementation\n"
            "3. Any residual risk that remains after the control\n"
            "4. The control status (planned/in_progress controls reduce less than verified ones)\n\n"
            "Scale guidance:\n"
            "  0-20%  : Minor mitigation, root cause largely unaddressed\n"
            "  21-40% : Partial mitigation, significant residual risk\n"
            "  41-60% : Meaningful reduction, some residual risk\n"
            "  61-80% : Strong mitigation, minor residual risk\n"
            "  81-100%: Near-complete mitigation, negligible residual risk\n\n"
            "Respond ONLY with valid JSON (no markdown):\n"
            '{"risk_reduction_percentage": <integer 0-100>, "reasoning": "<explanation>"}'
        )

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=600,
            )
            content = self._clean_llm_response(response.choices[0].message.content.strip())
            result = json.loads(content)
            pct = max(0, min(100, int(result["risk_reduction_percentage"])))
            return pct, result.get("reasoning", "")
        except Exception as e:
            raise Exception(f"Error calculating risk reduction: {str(e)}")

    # ------------------------------------------------------------------
    # Risk recalculation
    # ------------------------------------------------------------------

    def recalculate_risk_with_controls(
        self,
        assessment_id: str,
        original_context: str,
        remediation_controls: List[Dict]
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

Calculate the NEW risk score (0-100) considering:
1. The original vulnerabilities and risks
2. Which controls have been implemented
3. The effectiveness of each control
4. Any residual risks that remain

Provide response in JSON format (no markdown, no backticks):
{{
    "new_risk_score": <integer 0-100>,
    "reasoning": "<explanation of score change and residual risks>"
}}"""
        
        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1500
        )
        content = self._clean_llm_response(response.choices[0].message.content.strip())
        result = json.loads(content)
        return result['new_risk_score'], result['reasoning']


# ---------------------------------------------------------------------------
# Feedback-driven training service
# ---------------------------------------------------------------------------

class FeedbackTrainer:
    """
    Distils accumulated VulnerabilityFeedback records into an updated
    system-prompt addendum that makes future SecurityAnalyzer runs smarter.

    This is intentionally NOT a full OpenAI fine-tune — it synthesises
    feedback patterns via GPT-4o into a concise set of analyst guidelines
    that are injected into every subsequent analysis prompt.  This approach
    is cheaper, faster, and gives deterministic control over what the model
    learns.
    """

    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)

    def run_weekly_training(self) -> 'TrainingJob':  # noqa: F821
        """
        Entry point called by the weekly Celery beat task (or management command).
        Creates a TrainingJob, processes all unincorporated feedback, generates
        a refined system-prompt addendum, and marks the feedback as incorporated.
        """
        from .models import VulnerabilityFeedback, TrainingJob

        job = TrainingJob.objects.create(status='running', started_at=timezone.now())

        try:
            # Collect all unincorporated feedback
            feedback_qs = VulnerabilityFeedback.objects.filter(
                incorporated_in_training=False
            ).select_related('vulnerable_component', 'assessment')

            if not feedback_qs.exists():
                job.status = 'completed'
                job.completed_at = timezone.now()
                job.training_summary = "No new feedback to incorporate."
                job.save()
                return job

            # Serialise feedback into structured text
            fp_items, pc_items, mf_items = [], [], []
            for fb in feedback_qs:
                if fb.feedback_type == 'false_positive':
                    fp_items.append(self._serialise_fp(fb))
                elif fb.feedback_type == 'prior_control':
                    pc_items.append(self._serialise_pc(fb))
                elif fb.feedback_type == 'missed_finding':
                    mf_items.append(self._serialise_mf(fb))

            addendum, summary = self._generate_addendum(fp_items, pc_items, mf_items)

            # Persist results on the job
            job.feedback_count = feedback_qs.count()
            job.false_positive_count = len(fp_items)
            job.prior_control_count = len(pc_items)
            job.missed_finding_count = len(mf_items)
            job.refined_system_prompt = addendum
            job.training_summary = summary
            job.status = 'completed'
            job.completed_at = timezone.now()
            job.save()

            # Mark all feedback as incorporated
            feedback_qs.update(incorporated_in_training=True, training_job=job)

            return job

        except Exception as e:
            job.status = 'failed'
            job.error_message = str(e)
            job.completed_at = timezone.now()
            job.save()
            raise

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
        mf_items: List[str]
    ) -> Tuple[str, str]:
        """Ask GPT-4o to synthesise feedback into concise analyst guidelines."""

        fp_block = "\n\n".join(fp_items) if fp_items else "(none)"
        pc_block = "\n\n".join(pc_items) if pc_items else "(none)"
        mf_block = "\n\n".join(mf_items) if mf_items else "(none)"

        prompt = f"""You are a senior security analyst synthesising analyst feedback to improve an
AI security assessment system.  Below are three categories of feedback collected since the
last training run.  Your job is to distil them into a concise set of ANALYST GUIDELINES
(maximum 800 words) that, when prepended to future assessment prompts, will make the AI:

1. Stop raising false positives like the ones described
2. Recognise and credit pre-existing controls when they are present
3. Catch vulnerabilities that were previously missed

FALSE POSITIVES REPORTED:
{fp_block}

PRE-EXISTING CONTROLS THAT SHOULD HAVE BEEN RECOGNISED:
{pc_block}

MISSED FINDINGS THAT SHOULD HAVE BEEN RAISED:
{mf_block}

Write the guidelines as a numbered list of clear, actionable instructions addressed to the
AI analyst (e.g. "Do NOT flag X as a vulnerability if Y control is present because...").
Be specific. Reference patterns, not individual assessments.

Also produce a one-paragraph TRAINING SUMMARY for human reviewers describing what was
learned.

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
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json\s*', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'^```\s*', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'```$', '', raw, flags=re.MULTILINE)
        raw = raw.replace('`', '').strip()
        result = json.loads(raw)
        return result['addendum'], result['summary']