import jwt
import json
import base64
import hashlib
from django.utils import timezone
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class JWTUtilsTC4:
    """Utility class for JWT operations and analysis"""
    
    @staticmethod
    def safe_decode_jwt(token: str) -> tuple[Optional[Dict], Optional[Dict]]:
        """
        Safely decode JWT token without signature verification
        Returns (header, payload) or (None, None) if failed
        """
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            return header, payload
        except Exception as e:
            logger.error(f"JWT decode failed: {str(e)}")
            return None, None
    
    @staticmethod
    def create_none_algorithm_jwt(payload: Dict[str, Any]) -> Optional[str]:
        """
        Create JWT token with 'none' algorithm
        """
        try:
            header = {"alg": "none", "typ": "JWT"}
            
            # Base64URL encode header and payload
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            # None algorithm requires empty signature
            return f"{header_b64}.{payload_b64}."
            
        except Exception as e:
            logger.error(f"None algorithm JWT creation failed: {str(e)}")
            return None
    
    @staticmethod
    def create_jwt_with_secret(payload: Dict[str, Any], secret: str, algorithm: str = 'HS256') -> Optional[str]:
        """
        Create JWT token with given secret and algorithm
        """
        try:
            return jwt.encode(payload, secret, algorithm=algorithm)
        except Exception as e:
            logger.error(f"JWT creation with secret failed: {str(e)}")
            return None
    
    @staticmethod
    def is_token_expired(payload: Dict[str, Any]) -> bool:
        """
        Check if JWT token is expired based on 'exp' claim
        """
        try:
            exp = payload.get('exp')
            if not exp:
                return False
            
            exp_datetime = datetime.fromtimestamp(exp, timezone.utc)
            return exp_datetime < timezone.now()
            
        except Exception as e:
            logger.error(f"Token expiration check failed: {str(e)}")
            return False
    
    @staticmethod
    def extract_token_claims(payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract important claims from JWT payload
        """
        important_claims = {}
        
        # Standard claims
        standard_claims = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']
        for claim in standard_claims:
            if claim in payload:
                important_claims[claim] = payload[claim]
        
        # Common custom claims
        custom_claims = ['role', 'roles', 'permissions', 'scope', 'user_id', 'username', 
                        'email', 'admin', 'is_admin', 'user_type', 'privilege', 'level']
        for claim in custom_claims:
            if claim in payload:
                important_claims[claim] = payload[claim]
        
        return important_claims
    
    @staticmethod
    def generate_role_escalation_payloads(original_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate various role escalation payloads based on original payload
        """
        payloads = []
        base_payload = original_payload.copy()
        
        # Common role escalation attempts
        role_escalations = [
            {'role': 'admin'},
            {'role': 'administrator'},
            {'role': 'root'},
            {'role': 'superuser'},
            {'roles': ['admin']},
            {'roles': ['administrator', 'user']},
            {'is_admin': True},
            {'admin': True},
            {'user_type': 'admin'},
            {'user_type': 'administrator'},
            {'permissions': ['admin', 'read', 'write']},
            {'permissions': ['*']},
            {'scope': 'admin'},
            {'privilege': 'admin'},
            {'level': 'admin'},
            {'level': 9999},
            {'authority': 'admin'},
        ]
        
        for escalation in role_escalations:
            payload = base_payload.copy()
            payload.update(escalation)
            payloads.append(payload)
        
        # Try to escalate existing role/permission fields
        if 'role' in base_payload:
            payload = base_payload.copy()
            payload['role'] = 'admin'
            payloads.append(payload)
        
        if 'user_type' in base_payload:
            payload = base_payload.copy()
            payload['user_type'] = 'admin'
            payloads.append(payload)
        
        return payloads
    
    @staticmethod
    def analyze_jwt_security(header: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze JWT token for potential security issues
        """
        analysis = {
            'algorithm_issues': [],
            'payload_issues': [],
            'expiration_issues': [],
            'general_issues': [],
            'risk_score': 0
        }
        
        # Algorithm analysis
        alg = header.get('alg', '').lower()
        if alg == 'none':
            analysis['algorithm_issues'].append('Uses "none" algorithm - highly insecure')
            analysis['risk_score'] += 10
        elif alg.startswith('hs'):
            analysis['algorithm_issues'].append('Uses symmetric algorithm - vulnerable to secret brute force')
            analysis['risk_score'] += 3
        
        # Payload analysis
        if 'role' in payload or 'roles' in payload:
            analysis['payload_issues'].append('Contains role information - potential privilege escalation target')
            analysis['risk_score'] += 2
        
        if 'admin' in payload or 'is_admin' in payload:
            analysis['payload_issues'].append('Contains admin flags - high value target')
            analysis['risk_score'] += 3
        
        # Expiration analysis
        if 'exp' not in payload:
            analysis['expiration_issues'].append('No expiration time set - token valid indefinitely')
            analysis['risk_score'] += 5
        else:
            exp_time = payload.get('exp')
            current_time = timezone.now().timestamp()
            if exp_time - current_time > 86400:  # More than 24 hours
                analysis['expiration_issues'].append('Long expiration time - increases attack window')
                analysis['risk_score'] += 2
        
        # General security issues
        if len(payload) > 20:
            analysis['general_issues'].append('Large payload - may contain sensitive information')
            analysis['risk_score'] += 1
        
        sensitive_fields = ['password', 'secret', 'key', 'token', 'ssn', 'credit_card']
        for field in sensitive_fields:
            if any(field in str(key).lower() for key in payload.keys()):
                analysis['general_issues'].append(f'Potentially sensitive field detected: {field}')
                analysis['risk_score'] += 4
        
        return analysis


class DatabaseUtilsTC4:
    """Utility class for database operations related to JWT scanning"""
    
    @staticmethod
    def get_apis_by_scan_id(scan_id: int) -> List[Dict]:
        """
        Get APIs from api_orch_postmanapi table by scan_id
        """
        from django.db import connection
        
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                           "query_params", "pre_request_script", "test_script",
                           "original_url", "original_headers", "original_body", 
                           "original_query_params", "created_at", "updated_at", "scan_id"
                    FROM api_orch_postmanapi 
                    WHERE "scan_id" = %s
                    ORDER BY id
                """, [scan_id])
                
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get APIs for scan {scan_id}: {str(e)}")
            return []
    
    @staticmethod
    def get_jwt_token_by_scan_id(scan_id: int) -> Optional[str]:
        """
        Get JWT token from api_orch_scantokens table by scan_id
        """
        from django.db import connection
        
        try:
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
                
        except Exception as e:
            logger.error(f"Failed to get JWT token for scan {scan_id}: {str(e)}")
            return None


class SecurityUtilsTC4:
    """Security-related utility functions"""
    
    @staticmethod
    def get_common_jwt_secrets() -> List[str]:
        """
        Get list of common weak JWT secrets for testing
        """
        return [
            'secret',
            'password',
            '123456',
            'admin',
            'test',
            'key',
            'jwt',
            'token',
            'your-256-bit-secret',
            'supersecret',
            'mySecret',
            'jwt-secret',
            'secret-key',
            'your-secret',
            'my-jwt-secret',
            'change-me',
            'default',
            'qwerty',
            'password123',
            'admin123',
            'root',
            'toor',
            'guest',
            '12345',
            '1234567890',
            'abc123',
            'letmein',
            'welcome',
            'monkey',
            'dragon'
        ]
    
    @staticmethod
    def sanitize_response_body(body: str, max_length: int = 1000) -> str:
        """
        Sanitize response body for safe storage
        """
        if not body:
            return ""
        
        # Truncate if too long
        if len(body) > max_length:
            body = body[:max_length] + "... [truncated]"
        
        # Remove potential sensitive information patterns
        import re
        
        # Remove potential passwords, tokens, keys
        body = re.sub(r'"password"\s*:\s*"[^"]*"', '"password": "[REDACTED]"', body, flags=re.IGNORECASE)
        body = re.sub(r'"token"\s*:\s*"[^"]*"', '"token": "[REDACTED]"', body, flags=re.IGNORECASE)
        body = re.sub(r'"key"\s*:\s*"[^"]*"', '"key": "[REDACTED]"', body, flags=re.IGNORECASE)
        body = re.sub(r'"secret"\s*:\s*"[^"]*"', '"secret": "[REDACTED]"', body, flags=re.IGNORECASE)
        
        return body
    
    @staticmethod
    def calculate_vulnerability_severity(vulnerability_type: str, response_codes: Dict[str, int]) -> str:
        """
        Calculate vulnerability severity based on type and response behavior
        """
        original_code = response_codes.get('original', 200)
        forged_code = response_codes.get('forged', 401)
        
        # Critical vulnerabilities
        if vulnerability_type in ['none_algorithm', 'payload_manipulation'] and forged_code == original_code:
            return 'critical'
        
        # High vulnerabilities  
        if vulnerability_type == 'weak_secret' and forged_code == original_code:
            return 'high'
        
        if vulnerability_type == 'algorithm_confusion' and forged_code == original_code:
            return 'high'
        
        # Medium vulnerabilities
        if vulnerability_type == 'malformed_token_accepted' and forged_code not in [401, 403]:
            return 'medium'
        
        if vulnerability_type == 'expired_token_accepted' and forged_code == original_code:
            return 'medium'
        
        # Low severity for detected but not exploitable issues
        return 'low'