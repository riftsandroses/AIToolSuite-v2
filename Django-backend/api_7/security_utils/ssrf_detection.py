import json
import re
from typing import Dict, Any
from urllib.parse import urlparse
from api_orch.models import PostmanAPI, Scan
from ..models import SSRFCandidate

class SSRFDataExtractor:
    """
    Extracts relevant data from PostmanAPI objects for SSRF vulnerability detection
    with an improved, more actionable structure for vulnerable components.
    """
    SSRF_PRONE_PARAMS = [
        'url', 'uri', 'link', 'href', 'redirect', 'callback', 'webhook', 'api_url', 
        'endpoint', 'service_url', 'proxy', 'target', 'host', 'server', 'domain', 
        'ip', 'address', 'destination', 'fetch', 'load', 'get', 'retrieve', 'download', 
        'upload', 'import', 'export', 'sync', 'connect', 'ping', 'health_check'
    ]
    SSRF_PRONE_HEADERS = [
        'x-forwarded-for', 'x-real-ip', 'x-original-url', 'x-rewrite-url', 'host', 
        'origin', 'referer', 'x-forwarded-host', 'x-forwarded-proto', 'x-cluster-client-ip', 
        'x-forwarded', 'forwarded-for', 'forwarded', 'client-ip', 'true-client-ip', 
        'cf-connecting-ip'
    ]

    @classmethod
    def extract_ssrf_candidates(cls, scan: Scan) -> Dict[str, Any]:
        """Extracts all potential SSRF vulnerable data from a scan and stores it."""
        ssrf_data = {
            'scan_info': { 'scan_id': scan.id, 'scan_name': scan.scan_name, 'client_name': scan.client_name, 'total_apis': scan.postman_apis.count() },
            'candidates': []
        }
        SSRFCandidate.objects.filter(api__scan=scan).delete()

        for api in scan.postman_apis.all():
            candidate_data = cls._analyze_api_for_ssrf(api)
            if candidate_data['risk_score'] > 0:
                ssrf_candidate_obj = SSRFCandidate.objects.create(
                    api=api,
                    risk_score=candidate_data['risk_score'],
                    risk_factors=candidate_data['risk_factors'],
                    vulnerable_components=candidate_data['vulnerable_components']
                )
                candidate_data['candidate_id'] = ssrf_candidate_obj.id
                ssrf_data['candidates'].append(candidate_data)

        ssrf_data['candidates'].sort(key=lambda x: x['risk_score'], reverse=True)
        scan.total_ssrf_candidates = len(ssrf_data['candidates'])
        scan.save()
        return ssrf_data

    @classmethod
    def _analyze_api_for_ssrf(cls, api: PostmanAPI) -> Dict[str, Any]:
        """Analyzes a single API and returns a structured dictionary of findings."""
        candidate_data = {
            'api_id': api.id, 'api_name': api.name, 'method': api.method, 'url': api.url,
            'folder_path': api.folder_path, 'risk_score': 0, 'risk_factors': [],
            # --- UPDATED STRUCTURE ---
            'vulnerable_components': []  # Now a single list of findings
        }
        cls._analyze_url_path(api, candidate_data)
        cls._analyze_query_params(api, candidate_data)
        cls._analyze_body_params(api, candidate_data)
        cls._analyze_headers(api, candidate_data)
        return candidate_data

    @classmethod
    def _analyze_url_path(cls, api: PostmanAPI, candidate_data: Dict) -> None:
        if not api.url: return
        try:
            path = urlparse(api.url).path
            for part in [p for p in path.split('/') if p]:
                if (part.startswith('{') and part.endswith('}')) or (part.startswith('{{') and part.endswith('}}')):
                    variable_name = re.sub(r'[{}]', '', part)
                    is_high_risk = any(param in variable_name.lower() for param in cls.SSRF_PRONE_PARAMS)
                    candidate_data['risk_score'] += 20 if is_high_risk else 10
                    candidate_data['risk_factors'].append(f"URL path has a dynamic segment: '{part}'")
                    candidate_data['vulnerable_components'].append({
                        'location': 'path',
                        'injection_point': variable_name,
                        'original_value': part,
                        'reason': 'URL path contains a dynamic segment that could be replaced with a URL.'
                    })
        except Exception:
            pass # Failsafe for malformed URLs

    @classmethod
    def _analyze_query_params(cls, api: PostmanAPI, candidate_data: Dict) -> None:
        if not api.query_params: return
        for param, value in api.query_params.items():
            if any(p in param.lower() for p in cls.SSRF_PRONE_PARAMS):
                candidate_data['risk_score'] += 20
                candidate_data['risk_factors'].append(f"Query parameter name is suspicious: '{param}'")
                candidate_data['vulnerable_components'].append({
                    'location': 'query', 'injection_point': param, 'original_value': str(value),
                    'reason': 'Query parameter name suggests it may accept a URL.'
                })

    @classmethod
    def _analyze_headers(cls, api: PostmanAPI, candidate_data: Dict) -> None:
        if not api.headers: return
        for header, value in api.headers.items():
            if any(h in header.lower() for h in cls.SSRF_PRONE_HEADERS):
                candidate_data['risk_score'] += 15
                candidate_data['risk_factors'].append(f"Header is commonly used in SSRF attacks: '{header}'")
                candidate_data['vulnerable_components'].append({
                    'location': 'header', 'injection_point': header, 'original_value': str(value),
                    'reason': 'Header is on a list of headers often vulnerable to SSRF.'
                })

    @classmethod
    def _analyze_body_params(cls, api: PostmanAPI, candidate_data: Dict) -> None:
        if not api.body or not isinstance(api.body, dict): return
        if api.body.get('mode') == 'raw' and api.body.get('raw'):
            try:
                json_data = json.loads(api.body.get('raw'))
                cls._analyze_json_recursively(json_data, candidate_data)
            except json.JSONDecodeError:
                pass # Not a valid JSON body

    @classmethod
    def _analyze_json_recursively(cls, data: Any, candidate_data: Dict, parent_key: str = '') -> None:
        """Recursively checks JSON for suspicious keys or URL values."""
        if isinstance(data, dict):
            for key, value in data.items():
                current_key = f"{parent_key}.{key}" if parent_key else key
                # Check if the key name is suspicious
                if any(p in key.lower() for p in cls.SSRF_PRONE_PARAMS):
                    candidate_data['risk_score'] += 25
                    candidate_data['risk_factors'].append(f"JSON key name is suspicious: '{key}'")
                    candidate_data['vulnerable_components'].append({
                        'location': 'body', 'injection_point': current_key, 'original_value': str(value),
                        'reason': 'JSON key suggests it may accept a URL.'
                    })
                # Check if the value itself is a URL
                elif isinstance(value, str) and re.search(r'https?://', value, re.IGNORECASE):
                    candidate_data['risk_score'] += 20
                    candidate_data['risk_factors'].append(f"JSON value is a URL: '{key}'")
                    candidate_data['vulnerable_components'].append({
                        'location': 'body', 'injection_point': current_key, 'original_value': value,
                        'reason': 'JSON value is a URL and may be user-controllable.'
                    })
                # Recurse into nested objects
                if isinstance(value, (dict, list)):
                    cls._analyze_json_recursively(value, candidate_data, current_key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                cls._analyze_json_recursively(item, candidate_data, f"{parent_key}[{i}]")

# ... The SSRFLLMDataFormatter class remains unchanged ...
class SSRFLLMDataFormatter:
    @classmethod
    def format_for_llm(cls, candidate: 'SSRFCandidate') -> str:
        # ... (no changes needed to this class) ...
        components_str = json.dumps(candidate.vulnerable_components, indent=2)

        prompt_header = f"""**Objective:** Validate a potential SSRF vulnerability and provide a prioritized, multi-step testing strategy.

            **Vulnerability Candidate:**
            - **API Name:** {candidate.api.name}
            - **Endpoint:** {candidate.api.method} {candidate.api.url}
            - **Vulnerable Component Details:**
            ```json
            {components_str}
            Initial Heuristic Risk Score: {candidate.risk_score}
            """
        instructions_and_example = """
            Your Task:
            Based on your analysis of the candidate, provide a JSON object with the following keys. Do not add any commentary outside of the JSON object.

            is_ssrf_candidate: (boolean) - Is this a likely exploitable SSRF vulnerability?

            primary_payload_category: (string) - Choose the best category for the malicious content to inject from the options: "cloud_metadata", "local_ips", "dns_rebinding", "protocols".

            vector_category: (string or null) - Choose the category for the injection vector from the options: "headers", "encoded", "waf_bypass", "ports". If not needed, return null.

            recommended_payload: (JSON object or string) - Provide one specific, ready-to-use payload. If using a header, the format must be {"header": "X-Name", "value": "..."}. Otherwise, provide the payload as a string.

            Example Response for a Header-Based Vulnerability:

            JSON

            {
            "is_ssrf_candidate": true,
            "primary_payload_category": "cloud_metadata,
            "vector_category": "headers",
            "recommended_payload": {
                "header": "X-Forwarded-For",
                "value": "[http://169.254.169.254/latest/meta-data/](http://169.254.169.254/latest/meta-data/)"
            }
            }
            """
        return prompt_header + instructions_and_example