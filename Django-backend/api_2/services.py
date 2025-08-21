# Standard library imports
import base64
import hashlib
import hmac
import json
import logging
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from django.utils import timezone
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urljoin, urlparse

# Third-party imports
import jwt
import openai
import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.db import transaction, connection
from django.db.models import Count, Avg, Q
from django.utils import timezone as django_timezone
from openai import OpenAI
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Local application imports
from .models import (
    ScanResultTC1,
    ScanSessionTC1,
    VulnerabilitySummaryTC1,
    ScanResultTC2,
    ScanSummaryTC2,
    TestCredentialTC2,
    ScanResultTC3, 
    ScanSessionTC3, 
    VulnerabilityTemplateTC3,
    JWTScanTC4, 
    JWTVulnerabilityTC4, 
    JWTScanLogTC4, 
    JWTScanConfigTC4, 
    JWTTokenAnalysisTC4,
    ScanTC5, 
    VulnerabilityTypeTC5, 
    ScanResultTC5, 
    ScanLogTC5, 
    ApiRequestTC5, 
    ScanConfigurationTC5
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
            
            # Get existing session - HANDLE DoesNotExist PROPERLY
            try:
                session = ScanSessionTC1.objects.get(scan_id=scan_id)
            except ScanSessionTC1.DoesNotExist:
                # Create new session if it doesn't exist
                session = ScanSessionTC1.objects.create(
                    scan_id=scan_id,
                    status='scanning',
                    total_apis=len(apis)
                )
            else:
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
            # Update session to failed - REMOVE NESTED TRANSACTION
            try:
                # Don't use atomic here since we're already in one
                session = ScanSessionTC1.objects.get(scan_id=scan_id)
                session.status = 'failed'
                session.completed_at = timezone.now()
                session.save()
            except Exception as session_error:
                logger.error(f"Failed to update session status: {str(session_error)}")
            
            # Re-raise the exception to rollback the transaction
            raise

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


class VulnerabilityScannerServiceTC3:
    def __init__(self):
        self.openai_client = openai.OpenAI(api_key=getattr(settings, 'OPENAI_API_KEY', ''))
        self.weak_passwords = [
            '123456', 'password', 'qwerty', 'abc123', '12345678',
            'welcome', 'admin', 'letmein', '123123', 'Password1',
            'password123', '1234567890', 'changeme', 'test', 'guest'
        ]
    
    def get_api_data(self, scan_id):
        """Fetch API data from api_orch_postmanapi table"""
        from django.db import connection
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                       "query_params", "pre_request_script", "test_script"
                FROM api_orch_postmanapi 
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_jwt_token(self, scan_id):
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
            return result[0] if result else None
    
    def analyze_password_policy_with_ai(self, api_data, response_data):
        """Use OpenAI to analyze password policy vulnerability"""
        try:
            prompt = f"""
            Analyze this API for weak password policy vulnerabilities:
            
            API Details:
            - Name: {api_data.get('name')}
            - Method: {api_data.get('method')}
            - URL: {api_data.get('url')}
            - Body: {api_data.get('body')}
            
            Test Response:
            - Status Code: {response_data.get('status_code')}
            - Response Body: {response_data.get('response_body', '')}
            - Response Headers: {response_data.get('headers', {})}
            
            Weak passwords tested: {', '.join(self.weak_passwords[:5])}
            
            Please analyze and provide:
            1. Is this API vulnerable to weak password attacks? (yes/no)
            2. Severity level (critical/high/medium/low)
            3. Evidence of vulnerability
            4. Specific recommendations
            
            Respond in JSON format:
            {{
                "vulnerable": boolean,
                "severity": "string",
                "evidence": "string",
                "recommendation": "string",
                "confidence": "float (0.0-1.0)"
            }}
            """
            
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1
            )
            
            return json.loads(response.choices[0].message.content)
            
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            return {
                "vulnerable": False,
                "severity": "low",
                "evidence": f"Analysis failed: {str(e)}",
                "recommendation": "Manual review required",
                "confidence": 0.0
            }
    
    def test_weak_password_policy(self, api_data, jwt_token=None):
        """Test API for weak password policy vulnerability"""
        results = []
        
        try:
            headers = json.loads(api_data.get('headers', '{}'))
            body_data = json.loads(api_data.get('body', '{}'))
            
            if jwt_token:
                headers['Authorization'] = f'Bearer {jwt_token}'
            
            # Test with weak passwords
            for weak_password in self.weak_passwords:
                test_payload = body_data.copy()
                
                # Try to identify password fields
                password_fields = ['password', 'pwd', 'pass', 'passwd', 'secret']
                for field in password_fields:
                    if field in str(body_data).lower():
                        # Extract and modify the body
                        if 'raw' in body_data:
                            try:
                                raw_data = json.loads(body_data['raw'])
                                for key in raw_data:
                                    if any(pf in key.lower() for pf in password_fields):
                                        raw_data[key] = weak_password
                                        break
                                test_payload['raw'] = json.dumps(raw_data)
                            except:
                                pass
                        break
                
                # Make the request
                try:
                    response = requests.request(
                        method=api_data.get('method', 'GET'),
                        url=api_data.get('url'),
                        headers=headers,
                        json=json.loads(test_payload.get('raw', '{}')) if 'raw' in test_payload else None,
                        timeout=30
                    )
                    
                    response_data = {
                        'status_code': response.status_code,
                        'response_body': response.text[:1000],  # Limit response size
                        'headers': dict(response.headers),
                        'test_password': weak_password
                    }
                    
                    # Check if weak password was accepted
                    success_indicators = [200, 201, 302]
                    error_indicators = ['invalid', 'wrong', 'incorrect', 'failed', 'error']
                    
                    exploit_successful = (
                        response.status_code in success_indicators and
                        not any(indicator in response.text.lower() for indicator in error_indicators)
                    )
                    
                    if exploit_successful:
                        # Use AI to analyze the vulnerability
                        ai_analysis = self.analyze_password_policy_with_ai(api_data, response_data)
                        
                        results.append({
                            'vulnerable': ai_analysis.get('vulnerable', True),
                            'severity': ai_analysis.get('severity', 'medium'),
                            'test_payload': test_payload,
                            'response_data': response_data,
                            'exploit_successful': exploit_successful,
                            'evidence': {
                                'weak_password_accepted': weak_password,
                                'response_analysis': ai_analysis.get('evidence', ''),
                                'status_code': response.status_code
                            },
                            'ai_confidence': ai_analysis.get('confidence', 0.5)
                        })
                        
                        # If we found a vulnerability, no need to test all passwords
                        break
                    
                except requests.RequestException as e:
                    logger.error(f"Request failed for API {api_data.get('name')}: {str(e)}")
                    continue
            
            # If no vulnerabilities found, return a negative result
            if not results:
                results.append({
                    'vulnerable': False,
                    'severity': 'info',
                    'test_payload': {},
                    'response_data': {'message': 'No weak password vulnerabilities detected'},
                    'exploit_successful': False,
                    'evidence': {'message': 'API appears to have proper password validation'},
                    'ai_confidence': 0.8
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Vulnerability test failed: {str(e)}")
            return [{
                'vulnerable': False,
                'severity': 'info',
                'test_payload': {},
                'response_data': {'error': str(e)},
                'exploit_successful': False,
                'evidence': {'error': f'Test failed: {str(e)}'},
                'ai_confidence': 0.0
            }]
    
    def initiate_scan(self, scan_id, vulnerability_types=['weak_password_policy'], config=None):
        """Start vulnerability scan for given scan_id"""
        scan_session = None
        
        try:
            with transaction.atomic():
                # Create or update scan session
                scan_session, created = ScanSessionTC3.objects.get_or_create(
                    scan_id=scan_id,
                    defaults={
                        'status': 'running',
                        'scan_config': config or {}
                    }
                )
                
                if not created:
                    scan_session.status = 'running'
                    scan_session.started_at = timezone.now()
                    scan_session.save()
                
                # Get API data and JWT token
                api_list = self.get_api_data(scan_id)
                jwt_token = self.get_jwt_token(scan_id)
                
                scan_session.total_apis = len(api_list)
                scan_session.save()
                
                # Process each API
                vulnerabilities_found = 0
                
                for api_data in api_list:
                    try:
                        if 'weak_password_policy' in vulnerability_types:
                            results = self.test_weak_password_policy(api_data, jwt_token)
                            
                            for result in results:
                                if result.get('vulnerable', False):
                                    # Save vulnerability to database
                                    vulnerability = ScanResultTC3.objects.create(
                                        scan_id=scan_id,
                                        api_id=api_data['id'],
                                        vulnerability_type='weak_password_policy',
                                        severity=result.get('severity', 'medium'),
                                        api_name=api_data.get('name', ''),
                                        api_method=api_data.get('method', ''),
                                        api_url=api_data.get('url', ''),
                                        title='Weak or Default Password Policy',
                                        description='API accepts weak passwords that can be easily guessed or brute-forced.',
                                        impact='Attackers can gain unauthorized access using common passwords.',
                                        recommendation='Implement strong password policy with minimum length, complexity requirements, and rate limiting.',
                                        test_payload=result.get('test_payload', {}),
                                        test_response=result.get('response_data', {}),
                                        exploit_successful=result.get('exploit_successful', False),
                                        evidence=result.get('evidence', {})
                                    )
                                    
                                    vulnerabilities_found += 1
                                    
                                    # Update severity counts
                                    severity = result.get('severity', 'medium')
                                    if severity == 'critical':
                                        scan_session.critical_count += 1
                                    elif severity == 'high':
                                        scan_session.high_count += 1
                                    elif severity == 'medium':
                                        scan_session.medium_count += 1
                                    elif severity == 'low':
                                        scan_session.low_count += 1
                                    else:
                                        scan_session.info_count += 1
                    
                    except Exception as api_error:
                        logger.error(f"Error processing API {api_data.get('name')}: {str(api_error)}")
                        # Handle API-specific errors without breaking the transaction
                        if hasattr(scan_session, 'errors'):
                            if not isinstance(scan_session.errors, list):
                                scan_session.errors = []
                            scan_session.errors.append({
                                'api_id': api_data['id'],
                                'error': str(api_error),
                                'timestamp': timezone.now().isoformat()
                            })
                        continue  # Continue with next API instead of failing entire scan
                    
                    # Update progress
                    scan_session.apis_scanned += 1
                    scan_session.vulnerabilities_found = vulnerabilities_found
                    scan_session.save()
                
                # Complete scan
                scan_session.status = 'completed'
                scan_session.completed_at = timezone.now()
                scan_session.save()
                
                return scan_session
                
        except Exception as e:
            logger.error(f"Scan initiation failed: {str(e)}")
            
            # Update scan session status outside of the failed transaction
            if scan_session:
                try:
                    # Use a separate transaction for cleanup
                    with transaction.atomic():
                        scan_session.refresh_from_db()  # Get fresh instance
                        scan_session.status = 'failed'
                        if hasattr(scan_session, 'errors'):
                            if not isinstance(scan_session.errors, list):
                                scan_session.errors = []
                            scan_session.errors.append({
                                'error': f'Scan failed: {str(e)}',
                                'timestamp': timezone.now().isoformat()
                            })
                        scan_session.save()
                except Exception as cleanup_error:
                    logger.error(f"Failed to update scan session after error: {str(cleanup_error)}")
            
            raise

class ScanStatsServiceTC3:
    @staticmethod
    def get_scan_statistics():
        """Get comprehensive scan statistics"""
        from django.db.models import Count, Q
        
        # Scan session stats
        total_scans = ScanSessionTC3.objects.count()
        completed_scans = ScanSessionTC3.objects.filter(status='completed').count()
        running_scans = ScanSessionTC3.objects.filter(status='running').count()
        failed_scans = ScanSessionTC3.objects.filter(status='failed').count()
        
        # Vulnerability stats
        vulnerability_stats = ScanResultTC3.objects.aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low'))
        )
        
        # Recent scans
        recent_scans = ScanSessionTC3.objects.order_by('-started_at')[:10]
        
        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'running_scans': running_scans,
            'failed_scans': failed_scans,
            'total_vulnerabilities': vulnerability_stats['total'],
            'critical_vulnerabilities': vulnerability_stats['critical'],
            'high_vulnerabilities': vulnerability_stats['high'],
            'medium_vulnerabilities': vulnerability_stats['medium'],
            'low_vulnerabilities': vulnerability_stats['low'],
            'recent_scans': recent_scans
        }
    
    @staticmethod
    def get_vulnerability_summary(scan_id):
        """Get vulnerability summary for specific scan"""
        from django.db.models import Count
        
        try:
            scan_session = ScanSessionTC3.objects.get(scan_id=scan_id)
        except ScanSessionTC3.DoesNotExist:
            return None
        
        # Get vulnerability counts by type
        by_type = ScanResultTC3.objects.filter(scan_id=scan_id).values('vulnerability_type').annotate(
            count=Count('id')
        )
        
        # Get vulnerabilities by API
        by_api = ScanResultTC3.objects.filter(scan_id=scan_id).values(
            'api_name', 'api_method', 'api_url'
        ).annotate(
            vulnerability_count=Count('id')
        ).order_by('-vulnerability_count')
        
        return {
            'scan_id': scan_id,
            'total_vulnerabilities': scan_session.vulnerabilities_found,
            'critical_count': scan_session.critical_count,
            'high_count': scan_session.high_count,
            'medium_count': scan_session.medium_count,
            'low_count': scan_session.low_count,
            'info_count': scan_session.info_count,
            'by_type': {item['vulnerability_type']: item['count'] for item in by_type},
            'by_api': list(by_api),
            'scan_status': scan_session.status,
            'scan_progress': scan_session.progress_percentage
        }


class OpenAIServiceTC4:
    def __init__(self):
        self.client = OpenAI(api_key=getattr(settings, 'OPENAI_API_KEY', ''))
    
    def analyze_jwt_vulnerability(self, vulnerability_data):
        prompt = f"""
        Analyze this JWT vulnerability finding:
        
        API: {vulnerability_data.get('api_name')} ({vulnerability_data.get('api_method')} {vulnerability_data.get('api_url')})
        Vulnerability Type: {vulnerability_data.get('vulnerability_type')}
        Original Response Code: {vulnerability_data.get('original_response_code')}
        Forged Response Code: {vulnerability_data.get('forged_response_code')}
        Payload Changes: {vulnerability_data.get('payload_changes')}
        
        Original Token Header: {vulnerability_data.get('original_token_header')}
        Original Token Payload: {vulnerability_data.get('original_token_payload')}
        
        Provide a detailed analysis including:
        1. Risk assessment (1-10 scale)
        2. Potential impact
        3. Remediation recommendations
        4. Additional security considerations
        
        Keep the response concise but comprehensive.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {str(e)}")
            return f"AI analysis unavailable: {str(e)}"
    
    def analyze_jwt_token(self, token_data):
        prompt = f"""
        Analyze this JWT token for security issues:
        
        Header: {token_data.get('header')}
        Payload: {token_data.get('payload')}
        Algorithm: {token_data.get('algorithm')}
        
        Identify potential security risks and provide recommendations for:
        1. Algorithm security
        2. Payload structure
        3. Expiration handling
        4. General security best practices
        
        Be specific and actionable.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=400,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI token analysis failed: {str(e)}")
            return f"AI token analysis unavailable: {str(e)}"


class JWTManipulationServiceTC4:
    @staticmethod
    def decode_token_safe(token):
        """Decode JWT token without verification"""
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            return header, payload
        except Exception as e:
            logger.error(f"Token decode failed: {str(e)}")
            return None, None
    
    @staticmethod
    def create_none_algorithm_token(payload):
        """Create token with 'none' algorithm"""
        try:
            header = {"alg": "none", "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            return f"{header_b64}.{payload_b64}."
        except Exception as e:
            logger.error(f"None algorithm token creation failed: {str(e)}")
            return None
    
    @staticmethod
    def create_weak_secret_token(payload, secret):
        """Create token with weak secret"""
        try:
            return jwt.encode(payload, secret, algorithm='HS256')
        except Exception as e:
            logger.error(f"Weak secret token creation failed: {str(e)}")
            return None
    
    @staticmethod
    def manipulate_payload(original_payload, changes):
        """Apply changes to JWT payload"""
        try:
            new_payload = original_payload.copy()
            for key, value in changes.items():
                new_payload[key] = value
            return new_payload
        except Exception as e:
            logger.error(f"Payload manipulation failed: {str(e)}")
            return original_payload


class APITestServiceTC4:
    def __init__(self, timeout=30, max_retries=3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
    
    def make_api_call(self, api_data, token=None):
        """Make API call with optional JWT token"""
        try:
            method = api_data.get('method', 'GET').upper()
            url = api_data.get('url')
            headers = json.loads(api_data.get('headers', '{}'))
            body_data = json.loads(api_data.get('body', '{}'))
            query_params = json.loads(api_data.get('query_params', '{}'))
            
            # Add JWT token if provided
            if token:
                headers['Authorization'] = f'Bearer {token}'
            
            # Prepare request data
            kwargs = {
                'headers': headers,
                'timeout': self.timeout,
                'params': query_params
            }
            
            # Add body for methods that support it
            if method in ['POST', 'PUT', 'PATCH'] and body_data.get('raw'):
                try:
                    kwargs['json'] = json.loads(body_data['raw'])
                except json.JSONDecodeError:
                    kwargs['data'] = body_data['raw']
            
            # Make request with retries
            for attempt in range(self.max_retries):
                try:
                    response = self.session.request(method, url, **kwargs)
                    return {
                        'status_code': response.status_code,
                        'body': response.text,
                        'headers': dict(response.headers),
                        'success': True
                    }
                except requests.RequestException as e:
                    if attempt == self.max_retries - 1:
                        logger.error(f"API call failed after {self.max_retries} attempts: {str(e)}")
                        return {
                            'status_code': None,
                            'body': str(e),
                            'headers': {},
                            'success': False,
                            'error': str(e)
                        }
                    time.sleep(1)  # Wait before retry
            
        except Exception as e:
            logger.error(f"API test service error: {str(e)}")
            return {
                'status_code': None,
                'body': str(e),
                'headers': {},
                'success': False,
                'error': str(e)
            }


class JWTScanServiceTC4:
    def __init__(self):
        self.openai_service = OpenAIServiceTC4()
        self.jwt_service = JWTManipulationServiceTC4()
        self.api_service = APITestServiceTC4()
        
        # Default weak secrets to test
        self.default_weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key',
            'jwt', 'token', 'your-256-bit-secret', 'supersecret'
        ]
        
        # Default payload manipulations for role escalation
        self.default_role_payloads = [
            {'role': 'admin'},
            {'role': 'administrator'},
            {'is_admin': True},
            {'admin': True},
            {'user_type': 'admin'},
            {'permissions': ['admin']},
            {'level': 'admin'},
            {'privilege': 'admin'}
        ]
    
    def start_scan(self, scan_id, user, config_data=None):
        """Start JWT vulnerability scan"""
        scan = None
        
        try:
            with transaction.atomic():
                # Create scan record
                scan = JWTScanTC4.objects.create(
                    scan_id=scan_id,
                    status='in_progress',
                    created_by=user
                )
                
                # Create scan config
                config = JWTScanConfigTC4.objects.create(
                    scan=scan,
                    weak_secrets=self.default_weak_secrets,
                    role_escalation_payloads=self.default_role_payloads,
                    **(config_data or {})
                )
                
                self._log_scan_event(scan, 'info', f'Scan {scan_id} started')
            
            # Start scanning in background (outside of transaction)
            # Use threading or Celery for this
            import threading
            thread = threading.Thread(target=self._perform_scan, args=(scan,))
            thread.daemon = True
            thread.start()
            
            return scan
        
        except Exception as e:
            logger.error(f"Scan start failed: {str(e)}")
            
            # Cleanup failed scan outside of transaction
            if scan:
                try:
                    with transaction.atomic():
                        scan.refresh_from_db()
                        scan.status = 'failed'
                        scan.save()
                        self._log_scan_event(scan, 'error', f'Scan start failed: {str(e)}')
                except Exception as cleanup_error:
                    logger.error(f"Failed to cleanup after scan start failure: {str(cleanup_error)}")
            
            raise

    def _perform_scan(self, scan):
        """Perform the actual vulnerability scan"""
        try:
            start_time = time.time()
            
            # Use separate transactions for each operation
            with transaction.atomic():
                # Get APIs from api_orch
                apis = self._get_apis_for_scan(scan.scan_id)
                scan.total_apis = len(apis)
                scan.save()
                
                self._log_scan_event(scan, 'info', f'Found {len(apis)} APIs to scan')
            
            # Get JWT token for scan (outside transaction)
            jwt_token = self._get_jwt_token_for_scan(scan.scan_id)
            if not jwt_token:
                with transaction.atomic():
                    self._log_scan_event(scan, 'error', 'No JWT token found for scan')
                    scan.status = 'failed'
                    scan.save()
                return
            
            # Process each API in separate transactions
            for i, api in enumerate(apis, 1):
                try:
                    # Each API scan in its own transaction
                    with transaction.atomic():
                        self._scan_api_for_jwt_vulnerabilities(scan, api, jwt_token)
                        scan.scanned_apis = i
                        scan.save()
                        
                        self._log_scan_event(scan, 'info', f'Scanned API {api["id"]}: {api["name"]}')
                        
                except Exception as e:
                    # Log error but continue with next API
                    try:
                        with transaction.atomic():
                            self._log_scan_event(scan, 'error', f'Failed to scan API {api["id"]}: {str(e)}')
                    except Exception:
                        logger.error(f'Failed to log error for API {api["id"]}: {str(e)}')
                    continue
            
            # Complete scan
            with transaction.atomic():
                scan.refresh_from_db()
                scan.status = 'completed'
                scan.completed_at = django_timezone.now()
                scan.scan_duration = time.time() - start_time
                scan.vulnerable_apis = JWTVulnerabilityTC4.objects.filter(
                    scan=scan, is_vulnerable=True
                ).values('api_id').distinct().count()
                scan.save()
                
                self._log_scan_event(scan, 'info', f'Scan completed. Found {scan.vulnerable_apis} vulnerable APIs')
            
        except Exception as e:
            logger.error(f"Scan execution failed: {str(e)}")
            try:
                with transaction.atomic():
                    scan.refresh_from_db()
                    scan.status = 'failed'
                    scan.save()
                    self._log_scan_event(scan, 'error', f'Scan failed: {str(e)}')
            except Exception as cleanup_error:
                logger.error(f"Failed to mark scan as failed: {str(cleanup_error)}")

    def _get_apis_for_scan(self, scan_id):
        """Get APIs from api_orch_postmanapi table"""
        from django.db import connection
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                       "query_params", "original_url", "original_headers", "original_body"
                FROM api_orch_postmanapi 
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def _get_jwt_token_for_scan(self, scan_id):
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
            
            row = cursor.fetchone()
            return row[0] if row else None
    
    def _scan_api_for_jwt_vulnerabilities(self, scan, api_data, original_token):
        """Test API for various JWT vulnerabilities"""
        config = scan.config
        
        # Analyze original token
        token_analysis = self._analyze_token(scan, api_data['id'], original_token)
        
        # Test original API call
        original_response = self.api_service.make_api_call(api_data, original_token)
        
        if not original_response['success']:
            self._log_scan_event(scan, 'warning', f'Failed to call API {api_data["id"]} with original token')
            return
        
        # Test different vulnerability types
        if config.test_none_algorithm:
            self._test_none_algorithm(scan, api_data, original_token, original_response, token_analysis)
        
        if config.test_weak_secrets:
            self._test_weak_secrets(scan, api_data, original_token, original_response, token_analysis)
        
        if config.test_payload_manipulation:
            self._test_payload_manipulation(scan, api_data, original_token, original_response, token_analysis)
        
        if config.test_malformed_tokens:
            self._test_malformed_tokens(scan, api_data, original_response, token_analysis)
    
    def _analyze_token(self, scan, api_id, token):
        """Analyze JWT token structure and create analysis record"""
        header, payload = self.jwt_service.decode_token_safe(token)
        
        if not header or not payload:
            return None
        
        # Get AI analysis
        ai_analysis = self.openai_service.analyze_jwt_token({
            'header': header,
            'payload': payload,
            'algorithm': header.get('alg')
        })
        
        analysis = JWTTokenAnalysisTC4.objects.create(
            scan=scan,
            api_id=api_id,
            original_token=token,
            token_header=header,
            token_payload=payload,
            algorithm=header.get('alg'),
            issuer=payload.get('iss'),
            expiry=datetime.fromtimestamp(payload.get('exp'), timezone.utc) if payload.get('exp') else None,
            ai_risk_assessment=ai_analysis
        )
        
        return analysis
    
    def _test_none_algorithm(self, scan, api_data, original_token, original_response, token_analysis):
        """Test none algorithm vulnerability"""
        try:
            header, payload = self.jwt_service.decode_token_safe(original_token)
            if not payload:
                return
            
            # Create none algorithm token
            none_token = self.jwt_service.create_none_algorithm_token(payload)
            if not none_token:
                return
            
            # Test API with none algorithm token
            forged_response = self.api_service.make_api_call(api_data, none_token)
            
            # Determine if vulnerable
            is_vulnerable = (
                forged_response['success'] and 
                forged_response['status_code'] == original_response['status_code']
            )
            
            # Get AI analysis
            ai_analysis = self._get_vulnerability_ai_analysis({
                'api_name': api_data['name'],
                'api_method': api_data['method'],
                'api_url': api_data['url'],
                'vulnerability_type': 'none_algorithm',
                'original_response_code': original_response['status_code'],
                'forged_response_code': forged_response['status_code'],
                'payload_changes': {'algorithm': 'none'},
                'original_token_header': token_analysis.token_header if token_analysis else {},
                'original_token_payload': token_analysis.token_payload if token_analysis else {}
            })
            
            # Create vulnerability record
            JWTVulnerabilityTC4.objects.create(
                scan=scan,
                api_id=api_data['id'],
                api_name=api_data['name'],
                api_url=api_data['url'],
                api_method=api_data['method'],
                vulnerability_type='none_algorithm',
                severity='critical' if is_vulnerable else 'low',
                is_vulnerable=is_vulnerable,
                original_token=original_token,
                forged_token=none_token,
                original_response_code=original_response['status_code'],
                forged_response_code=forged_response['status_code'],
                original_response_body=original_response['body'][:1000],  # Limit size
                forged_response_body=forged_response['body'][:1000],
                payload_changes={'algorithm': 'none'},
                exploitation_details='Modified JWT algorithm to "none" to bypass signature verification',
                ai_analysis=ai_analysis
            )
            
        except Exception as e:
            self._log_scan_event(scan, 'error', f'None algorithm test failed for API {api_data["id"]}: {str(e)}')
    
    def _test_weak_secrets(self, scan, api_data, original_token, original_response, token_analysis):
        """Test weak secret vulnerability"""
        try:
            header, payload = self.jwt_service.decode_token_safe(original_token)
            if not payload or header.get('alg') != 'HS256':
                return
            
            config = scan.config
            for secret in config.weak_secrets:
                try:
                    # Try to create token with weak secret
                    weak_token = self.jwt_service.create_weak_secret_token(payload, secret)
                    if not weak_token:
                        continue
                    
                    # Test API with weak secret token
                    forged_response = self.api_service.make_api_call(api_data, weak_token)
                    
                    # Check if vulnerable
                    is_vulnerable = (
                        forged_response['success'] and 
                        forged_response['status_code'] == original_response['status_code']
                    )
                    
                    if is_vulnerable:
                        # Get AI analysis
                        ai_analysis = self._get_vulnerability_ai_analysis({
                            'api_name': api_data['name'],
                            'api_method': api_data['method'],
                            'api_url': api_data['url'],
                            'vulnerability_type': 'weak_secret',
                            'original_response_code': original_response['status_code'],
                            'forged_response_code': forged_response['status_code'],
                            'payload_changes': {'secret': secret},
                            'original_token_header': token_analysis.token_header if token_analysis else {},
                            'original_token_payload': token_analysis.token_payload if token_analysis else {}
                        })
                        
                        # Create vulnerability record
                        JWTVulnerabilityTC4.objects.create(
                            scan=scan,
                            api_id=api_data['id'],
                            api_name=api_data['name'],
                            api_url=api_data['url'],
                            api_method=api_data['method'],
                            vulnerability_type='weak_secret',
                            severity='high',
                            is_vulnerable=True,
                            original_token=original_token,
                            forged_token=weak_token,
                            original_response_code=original_response['status_code'],
                            forged_response_code=forged_response['status_code'],
                            original_response_body=original_response['body'][:1000],
                            forged_response_body=forged_response['body'][:1000],
                            payload_changes={'weak_secret_used': secret},
                            exploitation_details=f'JWT signature was successfully forged using weak secret: {secret}',
                            ai_analysis=ai_analysis
                        )
                        break  # Found vulnerability, no need to test more secrets
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            self._log_scan_event(scan, 'error', f'Weak secret test failed for API {api_data["id"]}: {str(e)}')
    
    def _test_payload_manipulation(self, scan, api_data, original_token, original_response, token_analysis):
        """Test payload manipulation vulnerability"""
        try:
            header, payload = self.jwt_service.decode_token_safe(original_token)
            if not payload:
                return
            
            config = scan.config
            
            # Test role escalation payloads
            for role_payload in config.role_escalation_payloads:
                try:
                    # Manipulate payload
                    new_payload = self.jwt_service.manipulate_payload(payload, role_payload)
                    
                    # Create forged token (try multiple methods)
                    forged_tokens = []
                    
                    # Try none algorithm
                    none_token = self.jwt_service.create_none_algorithm_token(new_payload)
                    if none_token:
                        forged_tokens.append(('none_algorithm', none_token))
                    
                    # Try with weak secrets
                    for secret in config.weak_secrets[:3]:  # Test only first 3 to save time
                        weak_token = self.jwt_service.create_weak_secret_token(new_payload, secret)
                        if weak_token:
                            forged_tokens.append(('weak_secret', weak_token))
                            break  # Use first working secret
                    
                    # Test each forged token
                    for token_type, forged_token in forged_tokens:
                        forged_response = self.api_service.make_api_call(api_data, forged_token)
                        
                        # Check if vulnerable
                        is_vulnerable = (
                            forged_response['success'] and 
                            forged_response['status_code'] == original_response['status_code']
                        )
                        
                        if is_vulnerable:
                            # Get AI analysis
                            ai_analysis = self._get_vulnerability_ai_analysis({
                                'api_name': api_data['name'],
                                'api_method': api_data['method'],
                                'api_url': api_data['url'],
                                'vulnerability_type': 'payload_manipulation',
                                'original_response_code': original_response['status_code'],
                                'forged_response_code': forged_response['status_code'],
                                'payload_changes': role_payload,
                                'original_token_header': token_analysis.token_header if token_analysis else {},
                                'original_token_payload': token_analysis.token_payload if token_analysis else {}
                            })
                            
                            # Create vulnerability record
                            JWTVulnerabilityTC4.objects.create(
                                scan=scan,
                                api_id=api_data['id'],
                                api_name=api_data['name'],
                                api_url=api_data['url'],
                                api_method=api_data['method'],
                                vulnerability_type='payload_manipulation',
                                severity='critical',
                                is_vulnerable=True,
                                original_token=original_token,
                                forged_token=forged_token,
                                original_response_code=original_response['status_code'],
                                forged_response_code=forged_response['status_code'],
                                original_response_body=original_response['body'][:1000],
                                forged_response_body=forged_response['body'][:1000],
                                payload_changes=role_payload,
                                exploitation_details=f'Successfully performed role escalation by modifying payload: {role_payload}',
                                ai_analysis=ai_analysis
                            )
                            return  # Found vulnerability, stop testing
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            self._log_scan_event(scan, 'error', f'Payload manipulation test failed for API {api_data["id"]}: {str(e)}')
    
    def _test_malformed_tokens(self, scan, api_data, original_response, token_analysis):
        """Test malformed token handling"""
        try:
            malformed_tokens = [
                '',  # Empty token
                'invalid.token.here',  # Invalid format
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.',  # Missing payload and signature
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',  # Missing signature
                'null',  # Null string
                'undefined',  # Undefined string
            ]
            
            for malformed_token in malformed_tokens:
                try:
                    forged_response = self.api_service.make_api_call(api_data, malformed_token)
                    
                    # Check if API accepts malformed token (should reject)
                    is_vulnerable = (
                        forged_response['success'] and 
                        forged_response['status_code'] not in [401, 403]
                    )
                    
                    if is_vulnerable:
                        # Get AI analysis
                        ai_analysis = self._get_vulnerability_ai_analysis({
                            'api_name': api_data['name'],
                            'api_method': api_data['method'],
                            'api_url': api_data['url'],
                            'vulnerability_type': 'malformed_token_accepted',
                            'original_response_code': original_response['status_code'],
                            'forged_response_code': forged_response['status_code'],
                            'payload_changes': {'token_format': 'malformed'},
                            'original_token_header': {},
                            'original_token_payload': {}
                        })
                        
                        # Create vulnerability record
                        JWTVulnerabilityTC4.objects.create(
                            scan=scan,
                            api_id=api_data['id'],
                            api_name=api_data['name'],
                            api_url=api_data['url'],
                            api_method=api_data['method'],
                            vulnerability_type='malformed_token_accepted',
                            severity='medium',
                            is_vulnerable=True,
                            original_token='N/A',
                            forged_token=malformed_token,
                            original_response_code=original_response['status_code'],
                            forged_response_code=forged_response['status_code'],
                            original_response_body=original_response['body'][:1000],
                            forged_response_body=forged_response['body'][:1000],
                            payload_changes={'malformed_token': malformed_token},
                            exploitation_details=f'API accepted malformed token: {malformed_token}',
                            ai_analysis=ai_analysis
                        )
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            self._log_scan_event(scan, 'error', f'Malformed token test failed for API {api_data["id"]}: {str(e)}')
    
    def _get_vulnerability_ai_analysis(self, vulnerability_data):
        """Get AI analysis for vulnerability"""
        try:
            return self.openai_service.analyze_jwt_vulnerability(vulnerability_data)
        except Exception as e:
            logger.error(f"AI vulnerability analysis failed: {str(e)}")
            return f"AI analysis unavailable: {str(e)}"
    
    def _log_scan_event(self, scan, level, message, api_id=None, additional_data=None):
        """Log scan event"""
        JWTScanLogTC4.objects.create(
            scan=scan,
            level=level,
            message=message,
            api_id=api_id,
            additional_data=additional_data or {}
        )


class OpenAIAnalysisServiceTC5:
    def __init__(self):
        openai.api_key = getattr(settings, 'OPENAI_API_KEY', '')
        self.model = "gpt-4o-mini"
    
    def analyze_password_reset_vulnerability(self, api_data: Dict, response_data: Dict) -> Dict:
        """Analyze API response for password reset vulnerabilities using OpenAI"""
        
        prompt = f"""
        Analyze this API endpoint for password reset vulnerabilities:
        
        API Details:
        - Method: {api_data.get('method')}
        - URL: {api_data.get('url')}
        - Headers: {json.dumps(api_data.get('headers', {}), indent=2)}
        - Body: {json.dumps(api_data.get('body', {}), indent=2)}
        
        Response Details:
        - Status Code: {response_data.get('status_code')}
        - Headers: {json.dumps(response_data.get('headers', {}), indent=2)}
        - Body: {response_data.get('body', '')}
        - Response Time: {response_data.get('response_time')}ms
        
        Check for these password reset vulnerabilities:
        1. Predictable or weak reset tokens
        2. Token reuse possibilities
        3. Missing verification of old password/OTP
        4. Exposed sensitive information in response
        5. Lack of rate limiting
        6. Missing CSRF protection
        7. Insecure token transmission
        8. Long-lived tokens
        
        Provide response in JSON format:
        {{
            "is_vulnerable": boolean,
            "confidence": float (0.0-1.0),
            "vulnerability_type": "string",
            "risk_score": float (0.0-10.0),
            "evidence": ["list of evidence"],
            "exploit_details": "string",
            "remediation": "string"
        }}
        """
        
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in API security testing."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            result = response.choices[0].message.content.strip()
            
            # Try to parse JSON response
            try:
                analysis = json.loads(result)
                return analysis
            except json.JSONDecodeError:
                # Fallback if AI doesn't return valid JSON
                return {
                    "is_vulnerable": False,
                    "confidence": 0.1,
                    "vulnerability_type": "analysis_error",
                    "risk_score": 0.0,
                    "evidence": ["AI analysis failed to parse"],
                    "exploit_details": "Could not analyze response",
                    "remediation": "Manual review required"
                }
                
        except Exception as e:
            return {
                "is_vulnerable": False,
                "confidence": 0.0,
                "vulnerability_type": "analysis_error",
                "risk_score": 0.0,
                "evidence": [f"AI analysis error: {str(e)}"],
                "exploit_details": "Analysis service unavailable",
                "remediation": "Manual review required"
            }


class ApiSecurityScannerTC5:
    def __init__(self):
        self.ai_service = OpenAIAnalysisServiceTC5()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0'
        })
    
    def scan_password_reset_endpoint(self, api_data: Dict, jwt_token: str) -> Dict:
        """Scan a single API endpoint for password reset vulnerabilities"""
        
        # Prepare headers
        headers = json.loads(api_data.get('headers', '{}'))
        if jwt_token:
            headers['Authorization'] = f'Bearer {jwt_token}'
        
        # Prepare request data
        method = api_data.get('method', 'GET').upper()
        url = api_data.get('url', '')
        body_data = api_data.get('body', {})
        
        # Parse body if it's a string
        if isinstance(body_data, str):
            try:
                body_data = json.loads(body_data)
            except:
                body_data = {}
        
        # Extract raw body content
        raw_body = None
        if body_data.get('raw'):
            try:
                raw_body = json.loads(body_data['raw'])
            except:
                raw_body = body_data['raw']
        
        # Test different password reset scenarios
        test_results = []
        
        # Test 1: Normal password reset request
        test_results.append(self._test_normal_reset(method, url, headers, raw_body))
        
        # Test 2: Token predictability
        test_results.append(self._test_token_predictability(method, url, headers, raw_body))
        
        # Test 3: Token reuse
        test_results.append(self._test_token_reuse(method, url, headers, raw_body))
        
        # Test 4: Missing verification
        test_results.append(self._test_missing_verification(method, url, headers, raw_body))
        
        # Combine results
        return self._combine_test_results(test_results, api_data)
    
    def _test_normal_reset(self, method: str, url: str, headers: Dict, body: any) -> Dict:
        """Test normal password reset flow"""
        try:
            start_time = time.time()
            
            if method == 'POST' and body:
                response = self.session.post(url, json=body, headers=headers, timeout=30)
            elif method == 'GET':
                response = self.session.get(url, headers=headers, timeout=30)
            else:
                response = self.session.request(method, url, json=body, headers=headers, timeout=30)
            
            response_time = (time.time() - start_time) * 1000
            
            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:2000],  # Limit body size
                'response_time': response_time
            }
            
            return {
                'test_name': 'normal_reset',
                'success': True,
                'response_data': response_data,
                'request_data': {
                    'method': method,
                    'url': url,
                    'headers': headers,
                    'body': body
                }
            }
            
        except Exception as e:
            return {
                'test_name': 'normal_reset',
                'success': False,
                'error': str(e),
                'response_data': None,
                'request_data': {
                    'method': method,
                    'url': url,
                    'headers': headers,
                    'body': body
                }
            }
    
    def _test_token_predictability(self, method: str, url: str, headers: Dict, body: any) -> Dict:
        """Test for predictable reset tokens"""
        # This is a simplified test - in practice, you'd need multiple requests to analyze patterns
        try:
            if not body or method != 'POST':
                return {'test_name': 'token_predictability', 'success': False, 'error': 'Not applicable'}
            
            # Make multiple requests to see if tokens follow a pattern
            responses = []
            for i in range(3):
                response = self.session.post(url, json=body, headers=headers, timeout=30)
                responses.append({
                    'status_code': response.status_code,
                    'body': response.text[:1000]
                })
                time.sleep(1)  # Delay between requests
            
            return {
                'test_name': 'token_predictability',
                'success': True,
                'responses': responses,
                'request_data': {'method': method, 'url': url}
            }
            
        except Exception as e:
            return {
                'test_name': 'token_predictability',
                'success': False,
                'error': str(e)
            }
    
    def _test_token_reuse(self, method: str, url: str, headers: Dict, body: any) -> Dict:
        """Test if tokens can be reused"""
        # Simplified implementation
        return {
            'test_name': 'token_reuse',
            'success': True,
            'finding': 'Manual verification required',
            'request_data': {'method': method, 'url': url}
        }
    
    def _test_missing_verification(self, method: str, url: str, headers: Dict, body: any) -> Dict:
        """Test for missing verification steps"""
        try:
            # Test with empty/missing fields
            if body and isinstance(body, dict):
                modified_body = body.copy()
                # Remove password field if exists
                for key in ['password', 'oldPassword', 'currentPassword']:
                    if key in modified_body:
                        del modified_body[key]
                
                response = self.session.request(method, url, json=modified_body, headers=headers, timeout=30)
                
                return {
                    'test_name': 'missing_verification',
                    'success': True,
                    'response_data': {
                        'status_code': response.status_code,
                        'body': response.text[:1000]
                    },
                    'request_data': {'method': method, 'url': url, 'modified_body': modified_body}
                }
            
            return {'test_name': 'missing_verification', 'success': False, 'error': 'Not applicable'}
            
        except Exception as e:
            return {
                'test_name': 'missing_verification',
                'success': False,
                'error': str(e)
            }
    
    def _combine_test_results(self, test_results: List[Dict], api_data: Dict) -> Dict:
        """Combine all test results and get AI analysis"""
        
        # Get the main response for AI analysis
        main_response = None
        for test in test_results:
            if test.get('test_name') == 'normal_reset' and test.get('success'):
                main_response = test.get('response_data')
                break
        
        if not main_response:
            return {
                'status': 'error',
                'error': 'Failed to get API response',
                'test_results': test_results
            }
        
        # Get AI analysis
        ai_analysis = self.ai_service.analyze_password_reset_vulnerability(api_data, main_response)
        
        return {
            'status': 'completed',
            'ai_analysis': ai_analysis,
            'test_results': test_results,
            'main_response': main_response
        }


class ScanServiceTC5:
    def __init__(self):
        self.scanner = ApiSecurityScannerTC5()
    
    def initiate_scan(self, scan_id: int, configuration_id: Optional[int] = None) -> ScanTC5:
        """Initiate a new security scan"""
        
        # Check if scan already exists
        existing_scan = ScanTC5.objects.filter(scan_id=scan_id).first()
        if existing_scan and existing_scan.status in ['running', 'pending']:
            raise ValueError(f"Scan {scan_id} is already {existing_scan.status}")
        
        # Create new scan record
        scan = ScanTC5.objects.create(
            scan_id=scan_id,
            status='pending'
        )
        
        # Log scan initiation
        ScanLogTC5.objects.create(
            scan=scan,
            level='info',
            message=f'Scan {scan_id} initiated',
            details={'configuration_id': configuration_id}
        )
        
        # Start scan asynchronously (in a real app, use Celery)
        self._execute_scan(scan, configuration_id)
        
        return scan
    
    def _execute_scan(self, scan: ScanTC5, configuration_id: Optional[int] = None):
        """Execute the security scan"""
        
        try:
            # Update scan status
            scan.status = 'running'
            scan.save()
            
            # Get APIs for this scan_id from api_orch app
            apis = self._get_apis_for_scan(scan.scan_id)
            if not apis:
                raise Exception(f"No APIs found for scan_id {scan.scan_id}")
            
            scan.total_apis = len(apis)
            scan.save()
            
            # Get JWT token
            jwt_token = self._get_jwt_token(scan.scan_id)
            
            # Get vulnerability type for password reset
            vuln_type, _ = VulnerabilityTypeTC5.objects.get_or_create(
                name='Insecure Password Reset Flow',
                defaults={
                    'severity': 'high',
                    'description': 'API endpoint vulnerable to insecure password reset attacks',
                    'remediation': 'Implement secure token generation, proper verification, and rate limiting'
                }
            )
            
            vulnerabilities_found = 0
            
            for api in apis:
                try:
                    # Log API scan start
                    ScanLogTC5.objects.create(
                        scan=scan,
                        level='info',
                        message=f'Scanning API: {api.get("name", "Unknown")}',
                        details={'api_id': api.get('id')}
                    )
                    
                    # Scan the API
                    scan_result = self.scanner.scan_password_reset_endpoint(api, jwt_token)
                    
                    # Save scan result
                    result = self._save_scan_result(scan, api, vuln_type, scan_result)
                    
                    if result.status == 'vulnerable':
                        vulnerabilities_found += 1
                    
                    scan.scanned_apis += 1
                    scan.save()
                    
                except Exception as api_error:
                    # Log API scan error
                    ScanLogTC5.objects.create(
                        scan=scan,
                        level='error',
                        message=f'Error scanning API {api.get("id")}: {str(api_error)}',
                        details={'api_id': api.get('id'), 'error': str(api_error)}
                    )
                    
                    # Create error result
                    ScanResultTC5.objects.create(
                        scan=scan,
                        api_id=api.get('id', 0),
                        api_name=api.get('name', 'Unknown'),
                        api_url=api.get('url', ''),
                        api_method=api.get('method', 'GET'),
                        vulnerability_type=vuln_type,
                        status='error',
                        evidence={'error': str(api_error)}
                    )
                    
                    scan.scanned_apis += 1
                    scan.save()
            
            # Complete scan
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.vulnerabilities_found = vulnerabilities_found
            scan.save()
            
            ScanLogTC5.objects.create(
                scan=scan,
                level='info',
                message=f'Scan completed. Found {vulnerabilities_found} vulnerabilities',
                details={'total_apis': scan.total_apis, 'vulnerabilities': vulnerabilities_found}
            )
            
        except Exception as e:
            # Mark scan as failed
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.completed_at = timezone.now()
            scan.save()
            
            ScanLogTC5.objects.create(
                scan=scan,
                level='error',
                message=f'Scan failed: {str(e)}',
                details={'error': str(e)}
            )
    
    def _get_apis_for_scan(self, scan_id: int) -> List[Dict]:
        """Get APIs from api_orch_postmanapi table"""
        from django.db import connection
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                       "query_params", "pre_request_script", "test_script", "created_at"
                FROM api_orch_postmanapi 
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            apis = []
            
            for row in cursor.fetchall():
                api_dict = dict(zip(columns, row))
                apis.append(api_dict)
            
            return apis
    
    def _get_jwt_token(self, scan_id: int) -> Optional[str]:
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
            return result[0] if result else None
    
    def _save_scan_result(self, scan: ScanTC5, api: Dict, vuln_type: VulnerabilityTypeTC5, scan_result: Dict) -> ScanResultTC5:
        """Save scan result to database"""
        
        ai_analysis = scan_result.get('ai_analysis', {})
        
        # Determine status based on AI analysis
        status = 'secure'
        if ai_analysis.get('is_vulnerable'):
            status = 'vulnerable'
        elif scan_result.get('status') == 'error':
            status = 'error'
        
        # Create scan result
        result = ScanResultTC5.objects.create(
            scan=scan,
            api_id=api.get('id', 0),
            api_name=api.get('name', 'Unknown'),
            api_url=api.get('url', ''),
            api_method=api.get('method', 'GET'),
            vulnerability_type=vuln_type,
            status=status,
            confidence=ai_analysis.get('confidence', 0.0),
            risk_score=ai_analysis.get('risk_score', 0.0),
            evidence=ai_analysis.get('evidence', []),
            exploit_details=ai_analysis.get('exploit_details', ''),
            remediation_suggestion=ai_analysis.get('remediation', ''),
            response_analysis=scan_result.get('main_response', {}),
            payload_used=scan_result.get('test_results', [])
        )
        
        # Save API requests/responses
        for test in scan_result.get('test_results', []):
            if test.get('success') and test.get('response_data'):
                ApiRequestTC5.objects.create(
                    scan_result=result,
                    request_url=api.get('url', ''),
                    request_method=api.get('method', 'GET'),
                    request_headers=test.get('request_data', {}).get('headers', {}),
                    request_body=json.dumps(test.get('request_data', {}).get('body', {})),
                    response_status=test.get('response_data', {}).get('status_code'),
                    response_headers=test.get('response_data', {}).get('headers', {}),
                    response_body=test.get('response_data', {}).get('body', ''),
                    response_time=test.get('response_data', {}).get('response_time', 0.0) / 1000.0
                )
        
        return result
    
    def get_scan_status(self, scan_id: int) -> Dict:
        """Get current status of a scan"""
        try:
            scan = ScanTC5.objects.get(scan_id=scan_id)
            
            progress = 0
            if scan.total_apis > 0:
                progress = (scan.scanned_apis / scan.total_apis) * 100
            
            return {
                'scan_id': scan.scan_id,
                'status': scan.status,
                'progress': round(progress, 2),
                'total_apis': scan.total_apis,
                'scanned_apis': scan.scanned_apis,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'started_at': scan.started_at,
                'completed_at': scan.completed_at,
                'error_message': scan.error_message
            }
        except ScanTC5.DoesNotExist:
            return {'error': f'Scan {scan_id} not found'}
    
    def get_scan_stats(self) -> Dict:
        """Get overall scanning statistics"""
        from django.db.models import Count, Avg, Q
        from django.db.models.functions import Extract
        
        # Basic counts
        total_scans = ScanTC5.objects.count()
        completed_scans = ScanTC5.objects.filter(status='completed').count()
        running_scans = ScanTC5.objects.filter(status='running').count()
        failed_scans = ScanTC5.objects.filter(status='failed').count()
        
        # Vulnerability counts
        vuln_results = ScanResultTC5.objects.filter(status='vulnerable')
        total_vulnerabilities = vuln_results.count()
        
        vuln_by_severity = vuln_results.values('vulnerability_type__severity').annotate(
            count=Count('id')
        )
        
        severity_counts = {item['vulnerability_type__severity']: item['count'] for item in vuln_by_severity}
        
        # Vulnerability by type
        vuln_by_type = vuln_results.values('vulnerability_type__name').annotate(
            count=Count('id')
        )
        type_counts = {item['vulnerability_type__name']: item['count'] for item in vuln_by_type}
        
        # Success rate
        success_rate = 0
        if total_scans > 0:
            success_rate = (completed_scans / total_scans) * 100
        
        # Average scan duration
        completed_scan_durations = ScanTC5.objects.filter(
            status='completed',
            completed_at__isnull=False
        ).extra(
            select={'duration': 'EXTRACT(EPOCH FROM (completed_at - started_at))'}
        ).values_list('duration', flat=True)
        
        avg_duration = 0
        if completed_scan_durations:
            avg_duration = sum(completed_scan_durations) / len(completed_scan_durations)
        
        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'running_scans': running_scans,
            'failed_scans': failed_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': severity_counts.get('critical', 0),
            'high_vulnerabilities': severity_counts.get('high', 0),
            'medium_vulnerabilities': severity_counts.get('medium', 0),
            'low_vulnerabilities': severity_counts.get('low', 0),
            'vulnerability_by_type': type_counts,
            'scan_success_rate': round(success_rate, 2),
            'avg_scan_duration': round(avg_duration, 2)
        }
    
    def get_vulnerability_summary(self) -> List[Dict]:
        """Get vulnerability summary grouped by type"""
        from django.db.models import Count, Avg, Max
        
        summary = VulnerabilityTypeTC5.objects.annotate(
            result_count=Count('scanresulttc5'),
            avg_risk_score=Avg('scanresulttc5__risk_score'),
            latest_occurrence=Max('scanresulttc5__created_at')
        ).filter(result_count__gt=0)
        
        result = []
        for vuln_type in summary:
            # Get severity distribution for this vulnerability type
            severity_dist = ScanResultTC5.objects.filter(
                vulnerability_type=vuln_type,
                status='vulnerable'
            ).values('vulnerability_type__severity').annotate(
                count=Count('id')
            )
            
            severity_distribution = {item['vulnerability_type__severity']: item['count'] for item in severity_dist}
            
            result.append({
                'vulnerability_type': {
                    'id': vuln_type.id,
                    'name': vuln_type.name,
                    'severity': vuln_type.severity,
                    'description': vuln_type.description
                },
                'count': vuln_type.result_count,
                'severity_distribution': severity_distribution,
                'avg_risk_score': round(vuln_type.avg_risk_score or 0, 2),
                'latest_occurrence': vuln_type.latest_occurrence
            })
        
        return result