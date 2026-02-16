import os
import base64
import json
import re
from typing import Dict, List, Tuple, Optional
from io import BytesIO
from PIL import Image
import chromadb
from chromadb.config import Settings
from openai import OpenAI
from django.conf import settings
from django.core.files.uploadedfile import UploadedFile


class ImageProcessor:
    """Process and analyze architecture diagrams"""
    
    @staticmethod
    def process_image(image_file: UploadedFile) -> tuple:
        """Convert image to base64 for OpenAI API"""
        try:
            # Reset file pointer to beginning
            image_file.seek(0)
            
            # Read the file
            image_data = image_file.read()
            
            # Determine mime type and extension
            ext = image_file.name.split('.')[-1].lower()
            
            # Handle PDFs - convert first page to image
            if ext == 'pdf':
                try:
                    import fitz  # PyMuPDF
                    # Open PDF
                    pdf_document = fitz.open(stream=image_data, filetype="pdf")
                    # Get first page
                    page = pdf_document[0]
                    # Convert to image (300 DPI)
                    pix = page.get_pixmap(matrix=fitz.Matrix(300/72, 300/72))
                    # Convert to PNG bytes
                    image_data = pix.tobytes("png")
                    mime_type = 'image/png'
                    pdf_document.close()
                except ImportError:
                    # If PyMuPDF not available, try pdf2image
                    try:
                        from pdf2image import convert_from_bytes
                        images = convert_from_bytes(image_data, first_page=1, last_page=1)
                        if images:
                            img_byte_arr = BytesIO()
                            images[0].save(img_byte_arr, format='PNG')
                            image_data = img_byte_arr.getvalue()
                            mime_type = 'image/png'
                    except ImportError:
                        raise Exception("PDF support requires 'PyMuPDF' or 'pdf2image'. Install with: pip install PyMuPDF")
            else:
                # Regular image file
                mime_types = {
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'gif': 'image/gif',
                    'bmp': 'image/bmp',
                    'webp': 'image/webp',
                    'tiff': 'image/tiff',
                    'tif': 'image/tiff'
                }
                mime_type = mime_types.get(ext, 'image/jpeg')
                
                # Validate it's actually an image
                try:
                    img = Image.open(BytesIO(image_data))
                    img.verify()
                    # Re-read the image data as verify() closes the file
                    image_file.seek(0)
                    image_data = image_file.read()
                except Exception as e:
                    raise Exception(f"Invalid image file: {str(e)}")
            
            # Convert to base64
            base64_image = base64.b64encode(image_data).decode('utf-8')
            
            # Reset file pointer for potential reuse
            image_file.seek(0)
            
            return base64_image, mime_type
            
        except Exception as e:
            raise Exception(f"Error processing image: {str(e)}")
    
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
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:{mime_type};base64,{base64_image}"
                                }
                            }
                        ]
                    }
                ],
                max_tokens=4096,
                temperature=0.3
            )
            
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise Exception(f"Error analyzing architecture diagram: {str(e)}")


class VectorStore:
    """Manage ChromaDB vector store for RAG"""
    
    def __init__(self):
        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=settings.CHROMADB_PATH,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name="security_knowledge",
            metadata={"hnsw:space": "cosine"}
        )
        
        self.openai_client = OpenAI(api_key=settings.OPENAI_API_KEY)
    
    def get_embedding(self, text: str) -> List[float]:
        """Generate embedding for text using OpenAI"""
        try:
            response = self.openai_client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return response.data[0].embedding
        except Exception as e:
            raise Exception(f"Error generating embedding: {str(e)}")
    
    def add_assessment_context(self, assessment_id: str, context_data: Dict):
        """Add assessment context to vector store"""
        
        # Create text chunks from assessment data
        chunks = []
        
        # Architecture details
        if context_data.get('architecture_analysis'):
            chunks.append({
                'text': f"Architecture Analysis: {context_data['architecture_analysis']}",
                'type': 'architecture',
                'assessment_id': assessment_id
            })
        
        # Technology stack
        tech_fields = [
            'programming_languages', 'frameworks_versions', 'databases',
            'cloud_services', 'containerization_platforms'
        ]
        tech_data = []
        for field in tech_fields:
            if context_data.get(field):
                tech_data.append(f"{field.replace('_', ' ').title()}: {context_data[field]}")
        
        if tech_data:
            chunks.append({
                'text': "Technology Stack: " + "; ".join(tech_data),
                'type': 'technology',
                'assessment_id': assessment_id
            })
        
        # Security controls
        security_fields = [
            'authentication_mechanisms', 'authorization_model', 'encryption_at_rest',
            'encryption_in_transit', 'input_validation_controls', 'api_authentication'
        ]
        security_data = []
        for field in security_fields:
            if context_data.get(field):
                security_data.append(f"{field.replace('_', ' ').title()}: {context_data[field]}")
        
        if security_data:
            chunks.append({
                'text': "Security Controls: " + "; ".join(security_data),
                'type': 'security_controls',
                'assessment_id': assessment_id
            })
        
        # Network and infrastructure
        network_fields = [
            'network_architecture', 'network_segmentation', 'firewall_config',
            'load_balancers', 'cdn_usage'
        ]
        network_data = []
        for field in network_fields:
            if context_data.get(field):
                network_data.append(f"{field.replace('_', ' ').title()}: {context_data[field]}")
        
        if network_data:
            chunks.append({
                'text': "Network & Infrastructure: " + "; ".join(network_data),
                'type': 'network',
                'assessment_id': assessment_id
            })
        
        # Store chunks in vector database
        for idx, chunk in enumerate(chunks):
            embedding = self.get_embedding(chunk['text'])
            self.collection.add(
                embeddings=[embedding],
                documents=[chunk['text']],
                metadatas=[{
                    'assessment_id': assessment_id,
                    'type': chunk['type']
                }],
                ids=[f"{assessment_id}_{chunk['type']}_{idx}"]
            )
    
    def query_context(self, query: str, assessment_id: str, n_results: int = 5) -> List[str]:
        """Query relevant context from vector store"""
        
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
    
    def analyze_security(self, assessment_data: Dict, architecture_file: UploadedFile) -> Tuple[int, str, List[Dict]]:
        """
        Perform comprehensive security analysis
        
        Returns:
            Tuple of (risk_score, reasoning, vulnerabilities_list)
        """
        
        # Step 1: Analyze architecture diagram
        print("Analyzing architecture diagram...")
        architecture_analysis = self.image_processor.extract_architecture_details(
            architecture_file,
            self.client
        )
        
        # Step 2: Store context in vector database
        print("Storing assessment context...")
        assessment_data['architecture_analysis'] = architecture_analysis
        assessment_id = assessment_data.get('id', 'temp_id')
        self.vector_store.add_assessment_context(assessment_id, assessment_data)
        
        # Step 3: Build comprehensive context for LLM
        context = self._build_analysis_context(assessment_data, architecture_analysis)
        
        # Step 4: Perform security analysis
        print("Performing AI security analysis...")
        risk_score, reasoning = self._calculate_risk_score(context)
        
        # Step 5: Identify vulnerabilities
        print("Identifying vulnerabilities...")
        vulnerabilities = self._identify_vulnerabilities(context, risk_score)
        
        return risk_score, reasoning, vulnerabilities
    
    def _build_analysis_context(self, assessment_data: Dict, architecture_analysis: str) -> str:
        """Build comprehensive context for LLM analysis"""
        
        context_parts = [
            "=== SECURITY ASSESSMENT CONTEXT ===\n",
            f"\n--- ARCHITECTURE ANALYSIS ---\n{architecture_analysis}\n"
        ]
        
        # Add all non-empty fields from assessment
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
                'third_party_integrations', 'external_apis', 'api_authentication',
                'rate_limiting'
            ],
            "OPERATIONS": [
                'patch_management', 'logging_architecture', 'monitoring_coverage',
                'incident_response_procedures', 'backup_architecture'
            ],
            "COMPLIANCE": [
                'compliance_standards', 'prior_audit_findings', 'known_vulnerabilities',
                'accepted_risks'
            ]
        }
        
        for group_name, fields in field_groups.items():
            group_data = []
            for field in fields:
                value = assessment_data.get(field)
                if value:
                    group_data.append(f"  - {field.replace('_', ' ').title()}: {value}")
            
            if group_data:
                context_parts.append(f"\n--- {group_name} ---")
                context_parts.extend(group_data)
        
        return "\n".join(context_parts)
    
    def _calculate_risk_score(self, context: str) -> Tuple[int, str]:
        """Calculate overall risk score using LLM"""
        
        prompt = f"""You are a senior security architect performing a comprehensive security risk assessment.

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
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=2000
            )
            
            content = response.choices[0].message.content.strip()
            # Remove markdown code blocks if present
            content = self._clean_llm_response(content)
            
            result = json.loads(content)
            return result['risk_score'], result['reasoning']
            
        except Exception as e:
            raise Exception(f"Error calculating risk score: {str(e)}")
    
    def _identify_vulnerabilities(self, context: str, risk_score: int) -> List[Dict]:
        """Identify specific vulnerabilities and security issues"""
        
        prompt = f"""You are a security auditor identifying specific vulnerabilities and security issues.

Based on the following application context, identify ALL security vulnerabilities, misconfigurations, and risks across:
- Architecture and design flaws
- Authentication/authorization weaknesses
- Data security gaps
- Network security issues
- Cloud misconfigurations
- API security problems
- Missing security controls
- Compliance gaps
- Operational security concerns

Overall Risk Score: {risk_score}/100

{context}

For EACH vulnerability found, provide details in the following format (respond with valid JSON array only, no markdown, no backticks):

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
]

Identify at least 5-15 findings depending on the risk score. Higher risk scores should have more findings."""
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=4000
            )
            
            content = response.choices[0].message.content.strip()
            # Remove markdown code blocks if present
            content = self._clean_llm_response(content)
            
            vulnerabilities = json.loads(content)
            return vulnerabilities
            
        except Exception as e:
            raise Exception(f"Error identifying vulnerabilities: {str(e)}")
    
    def recalculate_risk_with_controls(
        self,
        assessment_id: str,
        original_context: str,
        remediation_controls: List[Dict]
    ) -> Tuple[int, str]:
        """Recalculate risk score after implementing controls"""
        
        controls_summary = "\n".join([
            f"- {ctrl['control_name']}: {ctrl['control_description']} "
            f"(Risk Reduction: {ctrl['risk_reduction_percentage']}%)"
            for ctrl in remediation_controls if ctrl.get('status') == 'implemented'
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
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1500
            )
            
            content = response.choices[0].message.content.strip()
            content = self._clean_llm_response(content)
            
            result = json.loads(content)
            return result['new_risk_score'], result['reasoning']
            
        except Exception as e:
            raise Exception(f"Error recalculating risk: {str(e)}")
    
    @staticmethod
    def _clean_llm_response(content: str) -> str:
        """Remove markdown code blocks and backticks from LLM response"""
        # Remove ```json and ``` markers
        content = re.sub(r'^```json\s*', '', content, flags=re.MULTILINE)
        content = re.sub(r'^```\s*', '', content, flags=re.MULTILINE)
        content = re.sub(r'```$', '', content, flags=re.MULTILINE)
        
        # Remove any remaining backticks
        content = content.replace('`', '')
        
        return content.strip()