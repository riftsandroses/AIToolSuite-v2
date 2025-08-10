import requests
import time
import json
import logging
from typing import Dict, List, Tuple, Optional
from django.utils import timezone
from django.db import transaction
from api_4.models import RateLimitScan, ScanLog

logger = logging.getLogger(__name__)

class RateLimitScanner:
    """Core class for performing rate limiting vulnerability scans"""
    
    def __init__(self, scan_id: int, max_requests: int = 100, delay: float = 0.1, timeout: int = 30):
        self.scan_id = scan_id
        self.max_requests = max_requests
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        
    def get_apis_for_scan(self) -> List[Dict]:
        """Fetch APIs from api_orch_postmanapi table for the given scan_id"""
        from django.db import connection
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                       "query_params", "pre_request_script", "test_script"
                FROM api_orch_postmanapi 
                WHERE scan_id = %s
            """, [self.scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_access_token(self) -> Optional[str]:
        """Get JWT access token from api_orch_scantokens table"""
        from django.db import connection
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "access_token" FROM api_orch_scantokens 
                WHERE "scan_id" = %s AND "access_token" IS NOT NULL
                ORDER BY created_at DESC LIMIT 1
            """, [self.scan_id])
            
            result = cursor.fetchone()
            return result[0] if result else None
    
    def prepare_request(self, api_data: Dict, access_token: Optional[str]) -> Dict:
        """Prepare request parameters from API data"""
        headers = json.loads(api_data.get('headers', '{}'))
        body = json.loads(api_data.get('body', '{}'))
        auth = json.loads(api_data.get('authorization', '{}'))
        query_params = json.loads(api_data.get('query_params', '{}'))
        
        # Add JWT token if available
        if access_token:
            headers['Authorization'] = f'Bearer {access_token}'
        
        # Handle other authorization methods
        if auth and auth.get('type') == 'bearer' and auth.get('token'):
            headers['Authorization'] = f"Bearer {auth['token']}"
        elif auth and auth.get('type') == 'apikey':
            headers[auth.get('key', 'X-API-Key')] = auth.get('value', '')
        
        request_params = {
            'method': api_data['method'].upper(),
            'url': api_data['url'],
            'headers': headers,
            'timeout': self.timeout,
            'params': query_params if query_params else None,
        }
        
        if body and api_data['method'].upper() in ['POST', 'PUT', 'PATCH']:
            if headers.get('Content-Type') == 'application/json':
                request_params['json'] = body
            else:
                request_params['data'] = body
        
        return request_params
    
    def analyze_rate_limiting(self, responses: List[Tuple[int, float, Dict]]) -> Dict:
        """Analyze responses to detect rate limiting patterns"""
        total_requests = len(responses)
        status_codes = {}
        response_times = []
        rate_limit_headers = {}
        
        # Count status codes and collect response times
        for status_code, response_time, headers in responses:
            status_codes[status_code] = status_codes.get(status_code, 0) + 1
            response_times.append(response_time * 1000)  # Convert to ms
            
            # Look for rate limiting headers
            for header, value in headers.items():
                header_lower = header.lower()
                if any(rl_header in header_lower for rl_header in [
                    'rate-limit', 'x-rate-limit', 'x-ratelimit', 'retry-after'
                ]):
                    rate_limit_headers[header] = value
        
        # Determine if rate limiting is detected
        rate_limit_responses = status_codes.get(429, 0)  # Too Many Requests
        rate_limit_detected = rate_limit_responses > 0 or bool(rate_limit_headers)
        
        # Calculate vulnerability
        successful_requests = sum(count for code, count in status_codes.items() if 200 <= code < 400)
        success_rate = successful_requests / total_requests if total_requests > 0 else 0
        
        # Determine vulnerability and severity
        is_vulnerable = False
        severity = None
        description = ""
        recommendations = ""
        
        if not rate_limit_detected and success_rate > 0.8:
            is_vulnerable = True
            if total_requests >= 50:
                severity = 'high' if success_rate > 0.95 else 'medium'
            else:
                severity = 'medium'
            
            description = f"No rate limiting detected. {successful_requests}/{total_requests} requests succeeded."
            recommendations = "Implement rate limiting to prevent abuse and DoS attacks."
        
        elif rate_limit_detected and success_rate > 0.5:
            is_vulnerable = True
            severity = 'low'
            description = f"Rate limiting present but may be insufficient. {rate_limit_responses} rate limit responses out of {total_requests} requests."
            recommendations = "Review and strengthen rate limiting policies."
        
        return {
            'is_vulnerable': is_vulnerable,
            'severity': severity,
            'requests_sent': total_requests,
            'successful_requests': successful_requests,
            'rate_limit_detected': rate_limit_detected,
            'response_codes': status_codes,
            'response_times': response_times,
            'rate_limit_headers': rate_limit_headers,
            'vulnerability_description': description,
            'recommendations': recommendations,
        }
    
    def scan_single_api(self, api_data: Dict, access_token: Optional[str]) -> RateLimitScan:
        """Perform rate limiting scan on a single API"""
        
        # Create scan record
        scan_record = RateLimitScan.objects.create(
            scan_id=self.scan_id,
            api_id=api_data['id'],
            api_name=api_data['name'],
            api_url=api_data['url'],
            method=api_data['method'],
            status='running'
        )
        
        try:
            self.log(scan_record, 'info', f"Starting rate limit scan for {api_data['name']}")
            
            request_params = self.prepare_request(api_data, access_token)
            responses = []
            
            # Perform multiple requests
            for i in range(self.max_requests):
                try:
                    start_time = time.time()
                    response = self.session.request(**request_params)
                    response_time = time.time() - start_time
                    
                    responses.append((response.status_code, response_time, dict(response.headers)))
                    
                    self.log(
                        scan_record, 'debug',
                        f"Request {i+1}: {response.status_code} ({response_time:.3f}s)",
                        request_number=i+1,
                        response_code=response.status_code,
                        response_time=response_time
                    )
                    
                    # Stop if we hit rate limiting early
                    if response.status_code == 429:
                        self.log(scan_record, 'warning', f"Rate limit hit at request {i+1}")
                    
                    time.sleep(self.delay)
                    
                except requests.exceptions.RequestException as e:
                    self.log(scan_record, 'error', f"Request {i+1} failed: {str(e)}", request_number=i+1)
                    continue
            
            # Analyze results
            analysis = self.analyze_rate_limiting(responses)
            
            # Update scan record
            with transaction.atomic():
                for key, value in analysis.items():
                    setattr(scan_record, key, value)
                
                scan_record.status = 'completed'
                scan_record.scan_completed_at = timezone.now()
                scan_record.save()
            
            self.log(
                scan_record, 'info',
                f"Scan completed. Vulnerable: {analysis['is_vulnerable']}, "
                f"Severity: {analysis.get('severity', 'N/A')}"
            )
            
            return scan_record
            
        except Exception as e:
            self.log(scan_record, 'error', f"Scan failed: {str(e)}")
            scan_record.status = 'failed'
            scan_record.save()
            raise
    
    def log(self, scan: RateLimitScan, level: str, message: str, 
            request_number: Optional[int] = None, response_code: Optional[int] = None,
            response_time: Optional[float] = None):
        """Log scan events"""
        ScanLog.objects.create(
            scan=scan,
            level=level,
            message=message,
            request_number=request_number,
            response_code=response_code,
            response_time=response_time
        )
        
        # Also log to Django logger
        getattr(logger, level, logger.info)(f"Scan {scan.id}: {message}")
    
    def scan_all_apis(self) -> List[RateLimitScan]:
        """Scan all APIs for the given scan_id"""
        apis = self.get_apis_for_scan()
        if not apis:
            raise ValueError(f"No APIs found for scan_id {self.scan_id}")
        
        access_token = self.get_access_token()
        results = []
        
        for api_data in apis:
            try:
                result = self.scan_single_api(api_data, access_token)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to scan API {api_data['name']}: {str(e)}")
                continue
        
        return results