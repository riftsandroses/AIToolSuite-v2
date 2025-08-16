import re
import time
import json
import logging
import threading
from datetime import timedelta
from typing import Dict, List, Any, Tuple
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import openai
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from django.conf import settings
from django.utils import timezone
from django.db import transaction, connection
from django.db.models import Count, Avg, Q
from .models import (
    ScanResultTC1,
    ScanSessionTC1,
    VulnerabilitySummaryTC1,
    ScanResultTC2,
    ScanSummaryTC2,
    TestCredentialTC2,
)

logger = logging.getLogger(__name__)

class APIOrchDataServiceTC1:
    """Service to interact with api_orch app data"""
    
    @staticmethod
    def get_apis_by_scan_id(scan_id: int) -> List[Dict]:
        """Fetch APIs from api_orch_postmanapi table by scan_id"""
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                       "query_params", "original_url", "original_headers", "original_body",
                       "original_query_params", "scan_id"
                FROM api_orch_postmanapi 
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    @staticmethod
    def get_jwt_token_by_scan_id(scan_id: int) -> str:
        """Fetch JWT token from api_orch_scantokens table"""
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "access_token" 
                FROM api_orch_scantokens 
                WHERE "scan_id" = %s
                ORDER BY created_at DESC
                LIMIT 1
            """, [scan_id])
            
            result = cursor.fetchone()
            return result[0] if result else None

class VulnerabilityAnalyzerTC1:
    """Service to analyze APIs for vulnerabilities using ChatGPT"""
    
    def __init__(self):
        if hasattr(settings, 'OPENAI_API_KEY'):
            self.client = OpenAI(api_key=settings.OPENAI_API_KEY)  # Store client as instance variable
        else:
            logger.warning("OPENAI_API_KEY not found in settings")
            self.client = None
    
    def analyze_authentication_vulnerability(self, api_data: Dict) -> Dict:
        """Analyze API for missing or weak authentication vulnerabilities"""
        try:
            if not self.client:
                return self._fallback_analysis(api_data)

            prompt = f"""
            Analyze the following API endpoint for authentication vulnerabilities:
            
            API Name: {api_data.get('name', '')}
            Method: {api_data.get('method', '')}
            URL: {api_data.get('url', '')}
            Headers: {api_data.get('headers', '{}')}
            Body: {api_data.get('body', '{}')}
            Authorization: {api_data.get('authorization', '{}')}
            
            Check for:
            1. Missing authentication headers
            2. Weak authentication methods
            3. Sensitive endpoints without proper auth
            4. Default credentials or tokens
            
            Respond ONLY with a valid JSON object in this exact format:
            {{
                "has_vulnerability": boolean,
                "severity": "critical|high|medium|low|info",
                "title": "Brief title",
                "description": "Detailed description",
                "impact": "Impact description",
                "recommendation": "Fix recommendation",
                "evidence": "Technical evidence"
            }}
            """

            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.1,
                response_format={"type": "json_object"}  # Force JSON response
            )
            
            logger.debug(f"Raw API response: {response}")

            content = response.choices[0].message.content.strip()
            
            logger.debug(f"Response content: {content}")

            # Additional validation
            if not content:
                raise ValueError("Empty response from OpenAI API")
                
            try:
                result = json.loads(content)
                # Validate the required fields exist
                required_fields = ["has_vulnerability", "severity", "title", 
                                "description", "impact", "recommendation", "evidence"]
                if not all(field in result for field in required_fields):
                    raise ValueError("Missing required fields in response")
                    
                return result
            except json.JSONDecodeError as je:
                logger.error(f"Invalid JSON response: {content}")
                return self._fallback_analysis(api_data)
                
        except Exception as e:
            logger.error(f"Error in ChatGPT analysis: {str(e)}")
            return self._fallback_analysis(api_data)
    
    def _fallback_analysis(self, api_data: Dict) -> Dict:
        """Fallback analysis when ChatGPT is unavailable"""
        auth = json.loads(api_data.get('authorization', '{}'))
        headers = json.loads(api_data.get('headers', '{}'))
        
        has_auth_header = any(key.lower() in ['authorization', 'x-api-key', 'api-key'] 
                             for key in headers.keys())
        
        auth_type = auth.get('type', 'noauth')
        
        if auth_type == 'noauth' and not has_auth_header:
            return {
                "has_vulnerability": True,
                "severity": "high",
                "title": "Missing Authentication on API Endpoint",
                "description": f"The API endpoint {api_data.get('name')} does not have any authentication mechanism configured.",
                "impact": "Unauthorized access to sensitive data or functionality",
                "recommendation": "Implement proper authentication (JWT, API Keys, OAuth)",
                "evidence": f"No authorization header found. Auth type: {auth_type}"
            }
        
        return {
            "has_vulnerability": False,
            "severity": "info",
            "title": "Authentication Present",
            "description": "API has authentication configured",
            "impact": "Low security risk",
            "recommendation": "Continue monitoring",
            "evidence": "Authentication headers detected"
        }

class APISecurityScannerTC1:
    """Main service for API security scanning"""
    
    def __init__(self, user):
        self.user = user
        self.data_service = APIOrchDataServiceTC1()
        self.analyzer = VulnerabilityAnalyzerTC1()
    
    @transaction.atomic
    def initiate_scan(self, scan_id: int, scan_config: Dict = None) -> Dict:
        """Initiate a security scan for the given scan_id"""
        try:
            # Get APIs for the scan
            apis = self.data_service.get_apis_by_scan_id(scan_id)
            
            if not apis:
                return {"error": "No APIs found for the given scan_id", "success": False}
            
            # Get existing session
            session = ScanSessionTC1.objects.get(scan_id=scan_id)
            session.status = 'scanning'
            session.save()
            
            # Start scanning APIs
            self._scan_apis(apis, scan_id)
            
            # Update session status
            session.status = 'completed'
            session.completed_at = timezone.now()
            session.save()
            
            # Generate vulnerability summary
            self._generate_vulnerability_summary(scan_id)
            
            return {
                "message": "Scan completed successfully",
                "scan_id": scan_id,
                "total_apis": len(apis),
                "session_id": session.id,
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Error in scan execution: {str(e)}")
            # Update session to failed
            try:
                session = ScanSessionTC1.objects.get(scan_id=scan_id)
                session.status = 'failed'
                session.completed_at = timezone.now()
                session.save()
            except:
                pass
            return {"error": str(e), "success": False}

    def _scan_apis(self, apis: List[Dict], scan_id: int):
        """Scan individual APIs for vulnerabilities"""
        session = ScanSessionTC1.objects.get(scan_id=scan_id)
        
        for api in apis:
            try:
                # Analyze for authentication vulnerabilities
                analysis = self.analyzer.analyze_authentication_vulnerability(api)
                
                if analysis.get('has_vulnerability', False):
                    # Create scan result
                    scan_result = ScanResultTC1.objects.create(
                        scan_id=scan_id,
                        api_id=api['id'],
                        api_name=api['name'],
                        api_method=api['method'],
                        api_url=api['url'],
                        vulnerability_type='weak_auth',
                        severity=analysis['severity'],
                        status='completed',
                        title=analysis['title'],
                        description=analysis['description'],
                        impact=analysis['impact'],
                        recommendation=analysis['recommendation'],
                        evidence=analysis['evidence'],
                        scan_completed_at=timezone.now(),
                        created_by=self.user
                    )
                    
                    session.vulnerabilities_found += 1
                
                session.completed_apis += 1
                session.save()
                
            except Exception as e:
                logger.error(f"Error scanning API {api['id']}: {str(e)}")
                session.failed_apis += 1
                session.save()
    
    def _generate_vulnerability_summary(self, scan_id: int):
        """Generate vulnerability summary for the scan"""
        # Clear existing summary
        VulnerabilitySummaryTC1.objects.filter(scan_id=scan_id).delete()
        
        # Get vulnerability counts by type and severity        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "vulnerability_type", "severity", COUNT(*) as count
                FROM api2_scan_results 
                WHERE "scan_id" = %s
                GROUP BY "vulnerability_type", "severity"
            """, [scan_id])
            
            for row in cursor.fetchall():
                VulnerabilitySummaryTC1.objects.create(
                    scan_id=scan_id,
                    vulnerability_type=row[0],
                    severity=row[1],
                    count=row[2]
                )
    
    def get_scan_results(self, filters: Dict = None) -> Dict:
        """Get scan results with optional filters"""
        queryset = ScanResultTC1.objects.all().order_by('-scan_started_at')
        
        if filters:
            if filters.get('scan_id'):
                queryset = queryset.filter(scan_id=filters['scan_id'])
            if filters.get('vulnerability_type'):
                queryset = queryset.filter(vulnerability_type=filters['vulnerability_type'])
            if filters.get('severity'):
                queryset = queryset.filter(severity=filters['severity'])
            if filters.get('status'):
                queryset = queryset.filter(status=filters['status'])
            if filters.get('api_method'):
                queryset = queryset.filter(api_method__icontains=filters['api_method'])
            if filters.get('date_from'):
                queryset = queryset.filter(scan_started_at__gte=filters['date_from'])
            if filters.get('date_to'):
                queryset = queryset.filter(scan_started_at__lte=filters['date_to'])
        
        return queryset
    
    def get_scan_stats(self) -> Dict:
        """Get overall scan statistics"""
        
        sessions = ScanSessionTC1.objects.aggregate(
            total=Count('id'),
            active=Count('id', filter=Q(status__in=['pending', 'scanning'])),
            completed=Count('id', filter=Q(status='completed')),
            failed=Count('id', filter=Q(status='failed'))
        )
        
        vulnerabilities = ScanResultTC1.objects.aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low'))
        )
        
        return {
            'total_scans': sessions['total'],
            'active_scans': sessions['active'],
            'completed_scans': sessions['completed'],
            'failed_scans': sessions['failed'],
            'total_vulnerabilities': vulnerabilities['total'],
            'critical_vulnerabilities': vulnerabilities['critical'],
            'high_vulnerabilities': vulnerabilities['high'],
            'medium_vulnerabilities': vulnerabilities['medium'],
            'low_vulnerabilities': vulnerabilities['low']
        }


class CredentialStuffingServiceTC2:
    """Service for performing credential stuffing vulnerability tests"""
    
    def __init__(self):
        self.session = self._create_session()
        self.openai_client = openai.OpenAI(api_key=getattr(settings, 'OPENAI_API_KEY', ''))
        
    def _create_session(self):
        """Create requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def initiate_scan(self, scan_id: int, user=None) -> Dict[str, Any]:
        """Initiate vulnerability scan for all APIs in the scan_id"""
        try:
            # Get APIs from api_orch_postmanapi table
            from django.db import connection
            
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT "id", "name", "method", "url", "headers", "body", "authorization" 
                    FROM api_orch_postmanapi 
                    WHERE "scan_id" = %s
                """, [scan_id])
                apis = cursor.fetchall()
            
            if not apis:
                return {'error': 'No APIs found for this scan_id', 'scan_id': scan_id}
            
            # Create scan summary
            summary, created = ScanSummaryTC2.objects.get_or_create(
                scan_id=scan_id,
                defaults={
                    'total_apis': len(apis),
                    'scan_status': 'running',
                    'created_by': user
                }
            )
            
            if not created:
                summary.scan_status = 'running'
                summary.total_apis = len(apis)
                summary.pending_apis = len(apis)
                summary.completed_apis = 0
                summary.failed_apis = 0
                summary.save()
            
            # Start async scan
            thread = threading.Thread(
                target=self._perform_scan,
                args=(scan_id, apis, user)
            )
            thread.daemon = True
            thread.start()
            
            return {
                'message': 'Scan initiated successfully',
                'scan_id': scan_id,
                'total_apis': len(apis),
                'status': 'running'
            }
            
        except Exception as e:
            logger.error(f"Error initiating scan {scan_id}: {str(e)}")
            return {'error': str(e), 'scan_id': scan_id}
    
    def _perform_scan(self, scan_id: int, apis: List[Tuple], user=None):
        """Perform the actual vulnerability scanning"""
        start_time = time.time()
        
        try:
            # Get JWT token
            jwt_token = self._get_jwt_token(scan_id)
            
            # Create scan result entries
            scan_results = []
            for api in apis:
                api_id, name, method, url, headers, body, authorization = api
                scan_result = ScanResultTC2.objects.create(
                    scan_id=scan_id,
                    api_id=api_id,
                    api_name=name,
                    api_url=url,
                    api_method=method,
                    scan_status='running',
                    created_by=user
                )
                scan_results.append((scan_result, api))
            
            # Perform tests with ThreadPoolExecutor for parallel execution
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_result = {
                    executor.submit(self._test_api_credentials, result, api_data, jwt_token): result
                    for result, api_data in scan_results
                }
                
                completed = 0
                failed = 0
                
                for future in as_completed(future_to_result):
                    result = future_to_result[future]
                    try:
                        future.result()
                        completed += 1
                    except Exception as e:
                        logger.error(f"API test failed for {result.api_name}: {str(e)}")
                        result.scan_status = 'failed'
                        result.error_messages = str(e)
                        result.save()
                        failed += 1
                    
                    # Update summary progress
                    self._update_scan_progress(scan_id, completed + failed, len(apis))
            
            # Finalize scan
            end_time = time.time()
            self._finalize_scan(scan_id, start_time, end_time)
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {str(e)}")
            self._mark_scan_failed(scan_id, str(e))
    
    def _get_jwt_token(self, scan_id: int) -> str:
        """Get JWT token from api_orch_scantokens table"""
        from django.db import connection
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "access_token" 
                FROM api_orch_scantokens 
                WHERE "scan_id" = %s 
                ORDER BY created_at DESC 
                LIMIT 1
            """, [scan_id])
            result = cursor.fetchone()
            
        return result[0] if result else ""
    
    def _test_api_credentials(self, scan_result: ScanResultTC2, api_data: Tuple, jwt_token: str):
        """Test API for credential stuffing vulnerabilities"""
        api_id, name, method, url, headers_json, body_json, authorization_json = api_data
        
        try:
            # Parse API configuration
            headers = json.loads(headers_json) if headers_json else {}
            body_config = json.loads(body_json) if body_json else {}
            
            # Add JWT token if needed
            if jwt_token:
                headers['Authorization'] = f'Bearer {jwt_token}'
            
            # Get test credentials
            test_credentials = self._get_test_credentials()
            
            # Perform credential stuffing test
            results = self._execute_credential_test(url, method, headers, body_config, test_credentials)
            
            # Analyze results with AI
            analysis = self._analyze_results_with_ai(results, name, url)
            
            # Update scan result
            self._update_scan_result(scan_result, results, analysis)
            
        except Exception as e:
            logger.error(f"Error testing API {name}: {str(e)}")
            scan_result.scan_status = 'failed'
            scan_result.error_messages = str(e)
            scan_result.completed_at = timezone.now()
            scan_result.save()
    
    def _get_test_credentials(self) -> List[Dict[str, str]]:
        """Get test credentials for brute force testing"""
        # First try to get from database
        db_credentials = TestCredentialTC2.objects.filter(is_active=True)[:50]
        credentials = []
        
        for cred in db_credentials:
            credentials.append({
                'username': cred.username,
                'email': cred.email or cred.username,
                'password': cred.password
            })
        
        # If no database credentials, auto-populate and get them
        if not credentials:
            from .utils.credential_generator import CredentialGeneratorTC2
            logger.info("No test credentials found in database. Auto-populating...")
            
            try:
                CredentialGeneratorTC2.populate_test_credentials(200)
                logger.info("Successfully auto-populated 200 test credentials")
                
                # Now get the credentials
                db_credentials = TestCredentialTC2.objects.filter(is_active=True)[:50]
                for cred in db_credentials:
                    credentials.append({
                        'username': cred.username,
                        'email': cred.email or cred.username,
                        'password': cred.password
                    })
            except Exception as e:
                logger.error(f"Failed to auto-populate credentials: {e}")
                # Fallback to hardcoded credentials
                credentials = [
                    {'username': 'admin', 'email': 'admin@admin.com', 'password': 'admin'},
                    {'username': 'admin', 'email': 'admin@admin.com', 'password': 'password'},
                    {'username': 'admin', 'email': 'admin@admin.com', 'password': '123456'},
                    {'username': 'user', 'email': 'user@example.com', 'password': 'user'},
                    {'username': 'test', 'email': 'test@test.com', 'password': 'test'},
                    {'username': 'demo', 'email': 'demo@demo.com', 'password': 'demo'},
                    {'username': 'guest', 'email': 'guest@guest.com', 'password': 'guest'},
                    {'username': 'admin', 'email': 'admin@admin.com', 'password': 'admin123'},
                    {'username': 'root', 'email': 'root@root.com', 'password': 'root'},
                    {'username': 'administrator', 'email': 'admin@site.com', 'password': 'password123'},
                ]
        
        return credentials
    
    def _execute_credential_test(self, url: str, method: str, headers: Dict, 
                               body_config: Dict, credentials: List[Dict]) -> Dict[str, Any]:
        """Execute the actual credential stuffing test"""
        results = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'rate_limited_attempts': 0,
            'response_times': [],
            'status_codes': {},
            'responses': [],
            'rate_limiting_detected': False,
            'account_lockout_detected': False,
            'captcha_detected': False,
            'exploit_successful': False
        }
        
        for i, cred in enumerate(credentials):
            if i >= 50:  # Limit attempts to avoid excessive load
                break
                
            try:
                # Prepare request body
                request_body = self._prepare_request_body(body_config, cred)
                
                # Make request with timing
                start_time = time.time()
                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    json=request_body if request_body else None,
                    timeout=30
                )
                response_time = time.time() - start_time
                
                results['total_attempts'] += 1
                results['response_times'].append(response_time)
                
                # Track status codes
                status_code = response.status_code
                results['status_codes'][status_code] = results['status_codes'].get(status_code, 0) + 1
                
                # Analyze response
                response_text = response.text.lower()
                
                # Check for rate limiting
                if status_code == 429 or 'rate limit' in response_text or 'too many requests' in response_text:
                    results['rate_limited_attempts'] += 1
                    results['rate_limiting_detected'] = True
                
                # Check for account lockout
                if 'locked' in response_text or 'blocked' in response_text or 'suspended' in response_text:
                    results['account_lockout_detected'] = True
                
                # Check for CAPTCHA
                if 'captcha' in response_text or 'recaptcha' in response_text:
                    results['captcha_detected'] = True
                
                # Check for successful login
                if status_code == 200 and ('token' in response_text or 'success' in response_text or 'welcome' in response_text):
                    results['successful_attempts'] += 1
                    results['exploit_successful'] = True
                elif status_code in [401, 403]:
                    results['failed_attempts'] += 1
                
                # Store sample responses
                if len(results['responses']) < 5:
                    results['responses'].append({
                        'status_code': status_code,
                        'response_text': response_text[:500],  # Limit response text
                        'credentials_used': f"{cred.get('username', 'N/A')}:{cred.get('password', 'N/A')}"
                    })
                
                # Add delay to avoid overwhelming the server
                time.sleep(0.1)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed for {url}: {str(e)}")
                results['failed_attempts'] += 1
                continue
        
        return results
    
    def _prepare_request_body(self, body_config: Dict, credentials: Dict) -> Dict:
        """Prepare request body with credentials"""
        if not body_config or 'raw' not in body_config:
            return {}
        
        try:
            raw_body = json.loads(body_config['raw'])
        except (json.JSONDecodeError, KeyError):
            return {}
        
        # Replace common field names with test credentials
        field_mappings = {
            'email': credentials.get('email', credentials.get('username', 'test@test.com')),
            'username': credentials.get('username', 'test'),
            'user': credentials.get('username', 'test'),
            'login': credentials.get('username', 'test'),
            'password': credentials.get('password', 'test123')
        }
        
        for field, value in field_mappings.items():
            if field in raw_body:
                raw_body[field] = value
        
        return raw_body
    
    def _analyze_results_with_ai(self, results: Dict, api_name: str, api_url: str) -> Dict[str, Any]:
        """Use OpenAI to analyze test results and provide recommendations"""
        try:
            if not self.openai_client.api_key:
                return self._basic_analysis(results)
            
            prompt = f"""
            Analyze the following credential stuffing test results for API: {api_name} ({api_url})
            
            Test Results:
            - Total attempts: {results['total_attempts']}
            - Successful attempts: {results['successful_attempts']}
            - Failed attempts: {results['failed_attempts']}
            - Rate limited attempts: {results['rate_limited_attempts']}
            - Rate limiting detected: {results['rate_limiting_detected']}
            - Account lockout detected: {results['account_lockout_detected']}
            - CAPTCHA detected: {results['captcha_detected']}
            - Status codes: {results['status_codes']}
            - Average response time: {sum(results['response_times']) / len(results['response_times']) if results['response_times'] else 0:.2f}s
            
            Sample responses: {results['responses'][:3]}
            
            Please provide:
            1. Vulnerability severity (low, medium, high, critical)
            2. Whether exploit was successful (true/false)
            3. Detailed explanation of findings
            4. Security recommendations
            5. Risk score (0-10)
            
            Respond in JSON format with keys: severity, exploit_successful, findings, recommendations, risk_score
            """
            
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.1
            )
            
            analysis = json.loads(response.choices[0].message.content)
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            return self._basic_analysis(results)
    
    def _basic_analysis(self, results: Dict) -> Dict[str, Any]:
        """Basic analysis without AI"""
        vulnerability_found = False
        severity = 'low'
        risk_score = 0
        
        # Determine vulnerability
        if not results['rate_limiting_detected'] and results['total_attempts'] > 20:
            vulnerability_found = True
            severity = 'high' if results['successful_attempts'] > 0 else 'medium'
            risk_score = 8 if results['successful_attempts'] > 0 else 6
        
        if results['exploit_successful']:
            severity = 'critical'
            risk_score = 10
        
        findings = f"Tested {results['total_attempts']} credential combinations. "
        if not results['rate_limiting_detected']:
            findings += "No rate limiting detected. "
        if not results['account_lockout_detected']:
            findings += "No account lockout mechanism found. "
        if results['successful_attempts'] > 0:
            findings += f"Successfully logged in with {results['successful_attempts']} credential(s). "
        
        recommendations = []
        if not results['rate_limiting_detected']:
            recommendations.append("Implement rate limiting on authentication endpoints")
        if not results['account_lockout_detected']:
            recommendations.append("Implement account lockout after failed attempts")
        if not results['captcha_detected']:
            recommendations.append("Consider implementing CAPTCHA for repeated failures")
        
        return {
            'severity': severity,
            'exploit_successful': results['exploit_successful'],
            'findings': findings,
            'recommendations': recommendations,
            'risk_score': risk_score
        }
    
    def _update_scan_result(self, scan_result: ScanResultTC2, results: Dict, analysis: Dict):
        """Update scan result with test findings"""
        try:
            scan_result.scan_status = 'completed'
            scan_result.completed_at = timezone.now()
            
            # Test metrics
            scan_result.total_attempts = results['total_attempts']
            scan_result.successful_attempts = results['successful_attempts']
            scan_result.failed_attempts = results['failed_attempts']
            scan_result.rate_limited_attempts = results['rate_limited_attempts']
            
            # Response analysis
            if results['response_times']:
                scan_result.avg_response_time = sum(results['response_times']) / len(results['response_times'])
            scan_result.status_codes_found = results['status_codes']
            scan_result.rate_limiting_detected = results['rate_limiting_detected']
            scan_result.account_lockout_detected = results['account_lockout_detected']
            scan_result.captcha_detected = results['captcha_detected']
            
            # Vulnerability findings
            scan_result.vulnerability_found = analysis.get('severity') in ['medium', 'high', 'critical']
            scan_result.severity = analysis.get('severity', 'low')
            scan_result.exploit_successful = analysis.get('exploit_successful', False)
            scan_result.exploit_details = analysis.get('findings', '')
            scan_result.recommendations = '\n'.join(analysis.get('recommendations', []))
            
            # Store samples
            scan_result.response_samples = results['responses']
            
            scan_result.save()
            
        except Exception as e:
            logger.error(f"Error updating scan result {scan_result.id}: {str(e)}")
    
    def _update_scan_progress(self, scan_id: int, completed: int, total: int):
        """Update scan progress in summary"""
        try:
            summary = ScanSummaryTC2.objects.get(scan_id=scan_id)
            summary.completed_apis = completed
            summary.pending_apis = total - completed
            summary.save()
        except ScanSummaryTC2.DoesNotExist:
            pass
    
    def _finalize_scan(self, scan_id: int, start_time: float, end_time: float):
        """Finalize scan and update summary"""
        try:
            with transaction.atomic():
                # Update scan summary
                summary = ScanSummaryTC2.objects.get(scan_id=scan_id)
                summary.scan_status = 'completed'
                summary.completed_at = timezone.now()
                summary.total_scan_time = end_time - start_time
                
                # Calculate vulnerability counts
                results = ScanResultTC2.objects.filter(scan_id=scan_id)
                summary.total_vulnerabilities = results.filter(vulnerability_found=True).count()
                summary.critical_vulnerabilities = results.filter(severity='critical').count()
                summary.high_vulnerabilities = results.filter(severity='high').count()
                summary.medium_vulnerabilities = results.filter(severity='medium').count()
                summary.low_vulnerabilities = results.filter(severity='low').count()
                summary.failed_apis = results.filter(scan_status='failed').count()
                
                summary.save()
                
        except Exception as e:
            logger.error(f"Error finalizing scan {scan_id}: {str(e)}")
    
    def _mark_scan_failed(self, scan_id: int, error_message: str):
        """Mark scan as failed"""
        try:
            summary = ScanSummaryTC2.objects.get(scan_id=scan_id)
            summary.scan_status = 'failed'
            summary.completed_at = timezone.now()
            summary.save()
            
            # Mark all pending results as failed
            ScanResultTC2.objects.filter(
                scan_id=scan_id, 
                scan_status__in=['pending', 'running']
            ).update(
                scan_status='failed',
                error_messages=error_message,
                completed_at=timezone.now()
            )
            
        except Exception as e:
            logger.error(f"Error marking scan {scan_id} as failed: {str(e)}")


class ScanAnalyticsServiceTC2:
    """Service for generating scan analytics and reports"""
    
    @staticmethod
    def get_scan_stats() -> Dict[str, Any]:
        """Get overall scan statistics"""
        from django.db.models import Count, Avg, Q
        from django.utils import timezone
        from datetime import timedelta
        
        now = timezone.now()
        
        # Basic counts
        total_scans = ScanSummaryTC2.objects.count()
        completed_scans = ScanSummaryTC2.objects.filter(scan_status='completed').count()
        running_scans = ScanSummaryTC2.objects.filter(scan_status='running').count()
        failed_scans = ScanSummaryTC2.objects.filter(scan_status='failed').count()
        
        # API and vulnerability counts
        total_apis = ScanResultTC2.objects.count()
        total_vulnerabilities = ScanResultTC2.objects.filter(vulnerability_found=True).count()
        
        # Vulnerability breakdown
        critical_vulns = ScanResultTC2.objects.filter(severity='critical').count()
        high_vulns = ScanResultTC2.objects.filter(severity='high').count()
        medium_vulns = ScanResultTC2.objects.filter(severity='medium').count()
        low_vulns = ScanResultTC2.objects.filter(severity='low').count()
        
        # Time-based stats
        scans_24h = ScanSummaryTC2.objects.filter(created_at__gte=now - timedelta(hours=24)).count()
        scans_7d = ScanSummaryTC2.objects.filter(created_at__gte=now - timedelta(days=7)).count()
        scans_30d = ScanSummaryTC2.objects.filter(created_at__gte=now - timedelta(days=30)).count()
        
        # Performance metrics
        avg_scan_time = ScanSummaryTC2.objects.filter(
            total_scan_time__isnull=False
        ).aggregate(Avg('total_scan_time'))['total_scan_time__avg'] or 0
        
        avg_api_time = ScanResultTC2.objects.filter(
            avg_response_time__isnull=False
        ).aggregate(Avg('avg_response_time'))['avg_response_time__avg'] or 0
        
        success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
        
        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'running_scans': running_scans,
            'failed_scans': failed_scans,
            'total_apis_scanned': total_apis,
            'total_vulnerabilities_found': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulns,
            'high_vulnerabilities': high_vulns,
            'medium_vulnerabilities': medium_vulns,
            'low_vulnerabilities': low_vulns,
            'scans_last_24h': scans_24h,
            'scans_last_7d': scans_7d,
            'scans_last_30d': scans_30d,
            'avg_scan_time': round(avg_scan_time, 2),
            'avg_api_scan_time': round(avg_api_time, 2),
            'success_rate': round(success_rate, 2)
        }
    
    @staticmethod
    def get_vulnerability_summary(scan_id: int) -> Dict[str, Any]:
        """Get vulnerability summary for a specific scan"""
        results = ScanResultTC2.objects.filter(scan_id=scan_id)
        vulnerable_results = results.filter(vulnerability_found=True)
        
        # Vulnerability breakdown
        vulnerability_types = {}
        for result in vulnerable_results:
            vuln_type = result.vulnerability_type
            if vuln_type not in vulnerability_types:
                vulnerability_types[vuln_type] = 0
            vulnerability_types[vuln_type] += 1
        
        # Severity distribution
        severity_dist = {
            'critical': vulnerable_results.filter(severity='critical').count(),
            'high': vulnerable_results.filter(severity='high').count(),
            'medium': vulnerable_results.filter(severity='medium').count(),
            'low': vulnerable_results.filter(severity='low').count(),
        }
        
        # APIs with vulnerabilities
        vulnerable_apis = []
        for result in vulnerable_results:
            vulnerable_apis.append({
                'api_name': result.api_name,
                'api_url': result.api_url,
                'severity': result.severity,
                'exploit_successful': result.exploit_successful
            })
        
        # Generate recommendations
        recommendations = []
        if not any(r.rate_limiting_detected for r in results):
            recommendations.append("Implement rate limiting on authentication endpoints")
        if not any(r.account_lockout_detected for r in results):
            recommendations.append("Implement account lockout mechanisms")
        if not any(r.captcha_detected for r in results):
            recommendations.append("Consider implementing CAPTCHA for failed attempts")
        if vulnerable_results.filter(exploit_successful=True).exists():
            recommendations.append("URGENT: Change default credentials immediately")
        
        # Calculate risk score
        risk_score = 0
        if severity_dist['critical'] > 0:
            risk_score = 10
        elif severity_dist['high'] > 0:
            risk_score = 8
        elif severity_dist['medium'] > 0:
            risk_score = 6
        elif severity_dist['low'] > 0:
            risk_score = 4
        
        return {
            'scan_id': scan_id,
            'total_vulnerabilities': vulnerable_results.count(),
            'vulnerability_breakdown': vulnerability_types,
            'most_common_vulnerability': max(vulnerability_types.items(), key=lambda x: x[1])[0] if vulnerability_types else "None",
            'apis_with_vulnerabilities': vulnerable_apis,
            'severity_distribution': severity_dist,
            'recommendations': recommendations,
            'risk_score': risk_score
        }