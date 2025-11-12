import json
import re
import requests
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urljoin
import logging

logger = logging.getLogger(__name__)

class SecurityCheckUtilsTC1:
    """Utility class for security checks and validations"""
    
    # Common sensitive endpoints patterns
    SENSITIVE_ENDPOINTS = [
        r'/admin',
        r'/user/profile',
        r'/account',
        r'/delete',
        r'/api/v\d+/users',
        r'/dashboard',
        r'/settings',
        r'/config',
        r'/backup',
        r'/export',
        r'/upload',
        r'/management'
    ]
    
    # Authentication header patterns
    AUTH_HEADERS = [
        'authorization',
        'x-api-key',
        'api-key',
        'x-auth-token',
        'access-token',
        'bearer',
        'x-access-token',
        'x-jwt-token'
    ]
    
    @classmethod
    def is_sensitive_endpoint(cls, url: str, method: str = 'GET') -> bool:
        """Check if endpoint is sensitive based on URL pattern and method"""
        if not url:
            return False
            
        # Parse URL to get path
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check against sensitive patterns
        for pattern in cls.SENSITIVE_ENDPOINTS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        # Methods that are typically sensitive
        if method.upper() in ['DELETE', 'PUT', 'PATCH']:
            return True
            
        # POST to certain paths
        if method.upper() == 'POST' and any(keyword in path for keyword in 
                                          ['/create', '/add', '/register', '/login', '/auth']):
            return True
            
        return False
    
    @classmethod
    def check_authentication_headers(cls, headers: Dict) -> Dict:
        """Analyze headers for authentication mechanisms"""
        if not headers:
            return {"has_auth": False, "auth_type": "none", "headers_found": []}
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        found_auth_headers = []
        auth_type = "none"
        
        for auth_header in cls.AUTH_HEADERS:
            if auth_header in headers_lower:
                found_auth_headers.append(auth_header)
                if 'bearer' in headers_lower.get(auth_header, '').lower():
                    auth_type = "bearer_token"
                elif 'basic' in headers_lower.get(auth_header, '').lower():
                    auth_type = "basic_auth"
                elif 'api' in auth_header:
                    auth_type = "api_key"
                else:
                    auth_type = "custom"
        
        return {
            "has_auth": len(found_auth_headers) > 0,
            "auth_type": auth_type,
            "headers_found": found_auth_headers
        }
    
    @classmethod
    def analyze_authorization_config(cls, auth_config: Dict) -> Dict:
        """Analyze authorization configuration"""
        if not auth_config:
            return {"type": "noauth", "strength": "none"}
        
        auth_type = auth_config.get('type', 'noauth')
        
        strength_mapping = {
            'noauth': 'none',
            'basic': 'weak',
            'bearer': 'medium',
            'oauth1': 'strong',
            'oauth2': 'strong',
            'jwt': 'strong',
            'apikey': 'medium'
        }
        
        return {
            "type": auth_type,
            "strength": strength_mapping.get(auth_type, 'unknown')
        }
    
    @classmethod
    def check_default_credentials(cls, body: Dict) -> bool:
        """Check for default or common credentials in request body"""
        if not body:
            return False
        
        body_str = json.dumps(body).lower() if isinstance(body, dict) else str(body).lower()
        
        default_patterns = [
            r'admin.*admin',
            r'password.*password',
            r'test.*test',
            r'demo.*demo',
            r'guest.*guest',
            r'user.*user',
            r'root.*root',
            r'123456',
            r'password123'
        ]
        
        for pattern in default_patterns:
            if re.search(pattern, body_str, re.IGNORECASE):
                return True
        
        return False
    
    @classmethod
    def extract_vulnerability_evidence(cls, api_data: Dict, analysis_result: Dict) -> Dict:
        """Extract and format evidence for vulnerability"""
        evidence = {
            "api_details": {
                "name": api_data.get('name', ''),
                "method": api_data.get('method', ''),
                "url": api_data.get('url', '')
            },
            "authentication_analysis": {},
            "security_issues": []
        }
        
        # Check headers
        headers = json.loads(api_data.get('headers', '{}'))
        auth_header_analysis = cls.check_authentication_headers(headers)
        evidence["authentication_analysis"]["headers"] = auth_header_analysis
        
        # Check authorization config
        auth_config = json.loads(api_data.get('authorization', '{}'))
        auth_config_analysis = cls.analyze_authorization_config(auth_config)
        evidence["authentication_analysis"]["config"] = auth_config_analysis
        
        # Check if endpoint is sensitive
        is_sensitive = cls.is_sensitive_endpoint(api_data.get('url', ''), api_data.get('method', 'GET'))
        evidence["authentication_analysis"]["is_sensitive_endpoint"] = is_sensitive
        
        # Check for default credentials
        body = json.loads(api_data.get('body', '{}'))
        has_default_creds = cls.check_default_credentials(body)
        evidence["authentication_analysis"]["has_default_credentials"] = has_default_creds
        
        # Security issues summary
        if not auth_header_analysis["has_auth"] and is_sensitive:
            evidence["security_issues"].append("Sensitive endpoint without authentication headers")
        
        if auth_config_analysis["strength"] == "none" and is_sensitive:
            evidence["security_issues"].append("Sensitive endpoint with no authentication configured")
        
        if auth_config_analysis["strength"] == "weak":
            evidence["security_issues"].append("Weak authentication method detected")
        
        if has_default_creds:
            evidence["security_issues"].append("Default or common credentials detected in request body")
        
        return evidence

class HTTPRequestUtilsTC1:
    """Utility class for making HTTP requests during security testing"""
    
    @staticmethod
    def make_request_without_auth(api_data: Dict) -> Dict:
        """Make HTTP request without authentication to test for vulnerabilities"""
        try:
            url = api_data.get('url', '')
            method = api_data.get('method', 'GET').upper()
            
            # Parse headers but remove authentication
            headers = json.loads(api_data.get('headers', '{}'))
            headers_clean = {k: v for k, v in headers.items() 
                           if k.lower() not in SecurityCheckUtilsTC1.AUTH_HEADERS}
            
            # Parse body
            body_data = json.loads(api_data.get('body', '{}'))
            request_body = None
            if body_data and body_data.get('mode') == 'raw':
                request_body = body_data.get('raw')
            
            # Make request with timeout
            response = requests.request(
                method=method,
                url=url,
                headers=headers_clean,
                data=request_body,
                timeout=10,
                verify=False,  # For testing environments
                allow_redirects=False
            )
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1000],  # Limit body size
                "success": True
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {
                "error": str(e),
                "success": False
            }
    
    @staticmethod
    def test_authentication_bypass(api_data: Dict) -> Dict:
        """Test various authentication bypass techniques"""
        results = []
        
        # Test 1: No authentication
        no_auth_result = HTTPRequestUtilsTC1.make_request_without_auth(api_data)
        if no_auth_result.get("success") and no_auth_result.get("status_code") == 200:
            results.append({
                "technique": "No Authentication",
                "status_code": no_auth_result["status_code"],
                "vulnerable": True,
                "details": "Endpoint accessible without authentication"
            })
        
        # Test 2: Empty authorization header
        # Test 3: Malformed authorization header
        # Add more bypass techniques here
        
        return {
            "bypass_tests": results,
            "total_tests": len(results),
            "vulnerabilities_found": len([r for r in results if r.get("vulnerable")])
        }

class ReportGeneratorTC1:
    """Utility class for generating security reports"""
    
    @staticmethod
    def generate_vulnerability_report(scan_results: List[Dict]) -> Dict:
        """Generate a comprehensive vulnerability report"""
        if not scan_results:
            return {"error": "No scan results provided"}
        
        report = {
            "summary": {
                "total_apis_scanned": len(scan_results),
                "vulnerabilities_by_severity": {},
                "vulnerabilities_by_type": {},
                "overall_risk_score": 0
            },
            "findings": [],
            "recommendations": [],
            "generated_at": "2025-08-14T00:00:00Z"
        }
        
        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        total_risk = 0
        
        for result in scan_results:
            severity = result.get("severity", "info")
            vuln_type = result.get("vulnerability_type", "other")
            
            # Count by severity
            if severity not in report["summary"]["vulnerabilities_by_severity"]:
                report["summary"]["vulnerabilities_by_severity"][severity] = 0
            report["summary"]["vulnerabilities_by_severity"][severity] += 1
            
            # Count by type
            if vuln_type not in report["summary"]["vulnerabilities_by_type"]:
                report["summary"]["vulnerabilities_by_type"][vuln_type] = 0
            report["summary"]["vulnerabilities_by_type"][vuln_type] += 1
            
            # Calculate risk
            total_risk += severity_weights.get(severity, 0)
            
            # Add to findings
            finding = {
                "api_name": result.get("api_name", "Unknown"),
                "vulnerability": result.get("title", "Unknown Vulnerability"),
                "severity": severity,
                "impact": result.get("impact", ""),
                "recommendation": result.get("recommendation", "")
            }
            report["findings"].append(finding)
        
        # Calculate overall risk score (0-100)
        max_possible_risk = len(scan_results) * 4
        report["summary"]["overall_risk_score"] = round((total_risk / max_possible_risk) * 100, 2) if max_possible_risk > 0 else 0
        
        # Generate recommendations
        report["recommendations"] = ReportGeneratorTC1._generate_recommendations(report["summary"])
        
        return report
    
    @staticmethod
    def _generate_recommendations(summary: Dict) -> List[str]:
        """Generate recommendations based on summary data"""
        recommendations = []
        
        vuln_by_severity = summary.get("vulnerabilities_by_severity", {})
        
        if vuln_by_severity.get("critical", 0) > 0:
            recommendations.append("Immediately address all critical vulnerabilities - these pose severe security risks")
        
        if vuln_by_severity.get("high", 0) > 0:
            recommendations.append("Prioritize fixing high-severity vulnerabilities within the next sprint")
        
        if summary.get("overall_risk_score", 0) > 70:
            recommendations.append("Overall security posture requires immediate attention - consider security audit")
        
        recommendations.extend([
            "Implement consistent authentication across all sensitive endpoints",
            "Regular security testing should be integrated into CI/CD pipeline",
            "Consider implementing API rate limiting and monitoring",
            "Ensure proper error handling that doesn't leak sensitive information"
        ])
        
        return recommendations