import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import requests
from django.conf import settings
import subprocess
import tempfile
import os
import uuid
from urllib.parse import urlparse, parse_qs

class PasswordPolicyAnalyzerTC3:
    """Analyzer for password policy vulnerabilities"""
    
    WEAK_PASSWORDS = [
        '123456', 'password', 'qwerty', 'abc123', '12345678',
        'welcome', 'admin', 'letmein', '123123', 'Password1',
        'password123', '1234567890', 'changeme', 'test', 'guest',
        '111111', 'dragon', 'sunshine', 'princess', 'football',
        'iloveyou', 'shadow', 'michael', 'ashley', 'computer',
        'jesus', 'ninja', 'mustang', 'password1', 'superman'
    ]
    
    COMMON_PASSWORD_PATTERNS = [
        r'^\d{4,8}$',  # Only numbers
        r'^[a-z]{4,8}$',  # Only lowercase letters
        r'^password\d*$',  # Password with optional numbers
        r'^admin\d*$',  # Admin with optional numbers
        r'^test\d*$',  # Test with optional numbers
        r'^user\d*$',  # User with optional numbers
        r'^guest\d*$',  # Guest with optional numbers
    ]
    
    @classmethod
    def is_weak_password(cls, password: str) -> Dict[str, Any]:
        """Check if a password is weak"""
        if not password:
            return {'weak': True, 'reason': 'Empty password'}
        
        # Check against common weak passwords
        if password.lower() in [p.lower() for p in cls.WEAK_PASSWORDS]:
            return {'weak': True, 'reason': 'Common weak password'}
        
        # Check against patterns
        for pattern in cls.COMMON_PASSWORD_PATTERNS:
            if re.match(pattern, password.lower()):
                return {'weak': True, 'reason': 'Matches weak pattern'}
        
        # Check length
        if len(password) < 8:
            return {'weak': True, 'reason': 'Too short (less than 8 characters)'}
        
        # Check complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity_score < 3:
            return {'weak': True, 'reason': 'Insufficient complexity'}
        
        return {'weak': False, 'reason': 'Strong password'}
    
    @classmethod
    def generate_test_payloads(cls, original_body: str) -> List[Dict[str, Any]]:
        """Generate test payloads with weak passwords"""
        payloads = []
        
        try:
            if original_body:
                body_data = json.loads(original_body) if isinstance(original_body, str) else original_body
                
                password_fields = ['password', 'pwd', 'pass', 'passwd', 'secret']
                
                for weak_password in cls.WEAK_PASSWORDS[:10]:  # Test top 10 weak passwords
                    test_payload = body_data.copy()
                    
                    # Find and replace password fields
                    for field in password_fields:
                        if field in str(body_data).lower():
                            cls._replace_password_in_payload(test_payload, field, weak_password)
                            break
                    
                    payloads.append({
                        'password': weak_password,
                        'payload': test_payload
                    })
            
        except (json.JSONDecodeError, TypeError):
            pass
        
        return payloads
    
    @classmethod
    def _replace_password_in_payload(cls, payload: Dict, field_hint: str, new_password: str):
        """Replace password field in payload"""
        def replace_recursive(obj, key_hint):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key_hint in key.lower():
                        obj[key] = new_password
                    elif isinstance(value, (dict, list)):
                        replace_recursive(value, key_hint)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        replace_recursive(item, key_hint)
        
        replace_recursive(payload, field_hint)


class HTTPRequestAnalyzerTC3:
    """Analyzer for HTTP requests and responses"""
    
    @staticmethod
    def analyze_response(response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP response for vulnerability indicators"""
        status_code = response_data.get('status_code', 0)
        response_body = response_data.get('response_body', '').lower()
        headers = response_data.get('headers', {})
        
        analysis = {
            'success_indicators': [],
            'failure_indicators': [],
            'security_headers': {},
            'vulnerability_score': 0.0
        }
        
        # Success indicators
        success_patterns = [
            'success', 'login successful', 'authenticated', 'welcome',
            'dashboard', 'profile', 'account', 'logout'
        ]
        
        failure_patterns = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error',
            'unauthorized', 'forbidden', 'denied'
        ]
        
        # Check for success/failure indicators
        for pattern in success_patterns:
            if pattern in response_body:
                analysis['success_indicators'].append(pattern)
        
        for pattern in failure_patterns:
            if pattern in response_body:
                analysis['failure_indicators'].append(pattern)
        
        # Check security headers
        security_headers = [
            'x-frame-options', 'x-xss-protection', 'x-content-type-options',
            'strict-transport-security', 'content-security-policy'
        ]
        
        for header in security_headers:
            if header in [h.lower() for h in headers.keys()]:
                analysis['security_headers'][header] = True
            else:
                analysis['security_headers'][header] = False
        
        # Calculate vulnerability score
        score = 0.0
        
        # Status code analysis
        if 200 <= status_code < 300:
            score += 0.3
        elif status_code in [401, 403]:
            score -= 0.2
        
        # Success/failure ratio
        if analysis['success_indicators'] and not analysis['failure_indicators']:
            score += 0.4
        elif analysis['failure_indicators'] and not analysis['success_indicators']:
            score -= 0.3
        
        # Security headers
        missing_headers = sum(1 for present in analysis['security_headers'].values() if not present)
        score += (missing_headers / len(security_headers)) * 0.3
        
        analysis['vulnerability_score'] = max(0.0, min(1.0, score))
        
        return analysis


class CLIToolsIntegrationTC3:
    """Integration with CLI security tools"""
    
    @staticmethod
    def run_nmap_scan(target: str) -> Dict[str, Any]:
        """Run nmap scan for port discovery"""
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            cmd = [
                'nmap', '-sV', '--script=vuln', '-oX', temp_filename, target
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300
            )
            
            if result.returncode == 0:
                with open(temp_filename, 'r') as f:
                    scan_output = f.read()
                
                os.unlink(temp_filename)
                return {'success': True, 'output': scan_output}
            else:
                os.unlink(temp_filename)
                return {'success': False, 'error': result.stderr}
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {'success': False, 'error': f'Nmap execution failed: {str(e)}'}
    
    @staticmethod
    def run_sqlmap_test(url: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Run sqlmap test for SQL injection"""
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            cmd = [
                'sqlmap', '-u', url, '--data', json.dumps(data),
                '--batch', '--level=3', '--risk=2', '--output-dir', temp_filename
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode == 0:
                output = result.stdout
                os.unlink(temp_filename)
                return {'success': True, 'output': output}
            else:
                os.unlink(temp_filename)
                return {'success': False, 'error': result.stderr}
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {'success': False, 'error': f'SQLMap execution failed: {str(e)}'}


class ReportGeneratorTC3:
    """Generate vulnerability reports"""
    
    @staticmethod
    def generate_executive_summary(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive summary of scan results"""
        total_vulnerabilities = len(scan_results)
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for result in scan_results:
            severity = result.get('severity', 'info')
            severity_counts[severity] += 1
        
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 7 +
            severity_counts['medium'] * 4 +
            severity_counts['low'] * 2 +
            severity_counts['info'] * 1
        ) / max(total_vulnerabilities, 1)
        
        risk_level = 'Low'
        if risk_score >= 8:
            risk_level = 'Critical'
        elif risk_score >= 6:
            risk_level = 'High'
        elif risk_score >= 4:
            risk_level = 'Medium'
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'severity_distribution': severity_counts,
            'overall_risk_score': round(risk_score, 2),
            'overall_risk_level': risk_level,
            'scan_timestamp': datetime.now().isoformat(),
            'recommendations': ReportGeneratorTC3._generate_recommendations(scan_results)
        }
    
    @staticmethod
    def _generate_recommendations(scan_results: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        vuln_types = set()
        for result in scan_results:
            vuln_types.add(result.get('vulnerability_type', ''))
        
        if 'weak_password_policy' in vuln_types:
            recommendations.append(
                'Implement strong password policy with minimum 12 characters, '
                'complexity requirements, and rate limiting'
            )
        
        if 'sql_injection' in vuln_types:
            recommendations.append(
                'Use parameterized queries and input validation to prevent SQL injection'
            )
        
        if 'xss' in vuln_types:
            recommendations.append(
                'Implement proper output encoding and Content Security Policy headers'
            )
        
        recommendations.extend([
            'Regular security assessments and penetration testing',
            'Security awareness training for development teams',
            'Implement security monitoring and incident response procedures'
        ])
        
        return recommendations

class SecurityAnalyzerTC5:
    """Utility class for security analysis functions"""
    
    @staticmethod
    def analyze_password_reset_patterns(response_body: str, headers: Dict) -> Dict:
        """Analyze response for password reset security patterns"""
        findings = {
            'token_patterns': [],
            'sensitive_info_exposure': [],
            'security_headers': {},
            'potential_issues': []
        }
        
        # Check for token patterns
        token_patterns = [
            r'token["\']?\s*:\s*["\']([^"\']+)["\']',
            r'reset[_-]?token["\']?\s*:\s*["\']([^"\']+)["\']',
            r'verification[_-]?code["\']?\s*:\s*["\']([^"\']+)["\']',
            r'otp["\']?\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in token_patterns:
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            for match in matches:
                findings['token_patterns'].append({
                    'pattern': pattern,
                    'token': match,
                    'length': len(match),
                    'is_predictable': SecurityAnalyzerTC5.is_token_predictable(match)
                })
        
        # Check for sensitive information exposure
        sensitive_patterns = [
            r'email["\']?\s*:\s*["\']([^"\']+@[^"\']+)["\']',
            r'phone["\']?\s*:\s*["\']([^"\']+)["\']',
            r'user[_-]?id["\']?\s*:\s*["\']?(\d+)["\']?',
            r'password["\']?\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            if matches:
                findings['sensitive_info_exposure'].extend(matches)
        
        # Check security headers
        security_headers = [
            'X-Rate-Limit-Limit',
            'X-Rate-Limit-Remaining',
            'X-CSRF-Token',
            'Set-Cookie',
            'Cache-Control',
            'X-Frame-Options',
            'Content-Security-Policy'
        ]
        
        for header in security_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                findings['security_headers'][header] = headers.get(header, 'Present')
            else:
                findings['security_headers'][header] = 'Missing'
        
        # Analyze potential security issues
        if not findings['security_headers'].get('X-Rate-Limit-Limit'):
            findings['potential_issues'].append('Missing rate limiting headers')
        
        if not findings['security_headers'].get('X-CSRF-Token'):
            findings['potential_issues'].append('Missing CSRF protection')
        
        for token_info in findings['token_patterns']:
            if token_info['length'] < 32:
                findings['potential_issues'].append(f'Short token detected: {token_info["length"]} characters')
            
            if token_info['is_predictable']:
                findings['potential_issues'].append('Potentially predictable token pattern')
        
        if findings['sensitive_info_exposure']:
            findings['potential_issues'].append('Sensitive information exposed in response')
        
        return findings
    
    @staticmethod
    def is_token_predictable(token: str) -> bool:
        """Check if a token follows predictable patterns"""
        # Check for sequential patterns
        if re.match(r'^\d+, token) and len(token) < 10:
            return True
        
        # Check for timestamp-based tokens
        if re.match(r'^\d{10,13}, token):  # Unix timestamp
            return True
        
        # Check for simple incrementing patterns
        if len(set(token)) < 3 and len(token) > 5:
            return True
        
        # Check for base64 encoded predictable data
        try:
            import base64
            decoded = base64.b64decode(token + '==')
            if len(decoded) < 16:  # Too short for secure random
                return True
        except:
            pass
        
        return False
    
    @staticmethod
    def analyze_url_parameters(url: str) -> Dict:
        """Analyze URL for security issues"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        findings = {
            'sensitive_params': [],
            'potential_issues': [],
            'scheme': parsed.scheme,
            'uses_https': parsed.scheme == 'https'
        }
        
        # Check for sensitive parameters in URL
        sensitive_param_names = [
            'token', 'reset_token', 'verification_code', 'otp',
            'password', 'secret', 'key', 'auth', 'session'
        ]
        
        for param_name, values in query_params.items():
            if any(sensitive in param_name.lower() for sensitive in sensitive_param_names):
                findings['sensitive_params'].append({
                    'param': param_name,
                    'values': values
                })
        
        # Security issues
        if not findings['uses_https']:
            findings['potential_issues'].append('Insecure HTTP protocol used')
        
        if findings['sensitive_params']:
            findings['potential_issues'].append('Sensitive parameters in URL')
        
        return findings
    
    @staticmethod
    def calculate_risk_score(vulnerability_data: Dict) -> float:
        """Calculate risk score based on vulnerability findings"""
        base_score = 0.0
        
        # Base score based on vulnerability confirmation
        if vulnerability_data.get('is_vulnerable', False):
            base_score = 5.0
        
        # Adjust based on confidence
        confidence = vulnerability_data.get('confidence', 0.0)
        base_score *= confidence
        
        # Adjust based on evidence
        evidence = vulnerability_data.get('evidence', [])
        if 'token_reuse_possible' in str(evidence):
            base_score += 2.0
        if 'predictable_token' in str(evidence):
            base_score += 1.5
        if 'missing_rate_limiting' in str(evidence):
            base_score += 1.0
        if 'sensitive_info_exposed' in str(evidence):
            base_score += 1.0
        if 'insecure_transmission' in str(evidence):
            base_score += 0.5
        
        # Cap at 10.0
        return min(base_score, 10.0)
    
    @staticmethod
    def generate_remediation_suggestions(findings: Dict) -> List[str]:
        """Generate remediation suggestions based on findings"""
        suggestions = []
        
        if 'missing_rate_limiting' in str(findings):
            suggestions.append('Implement rate limiting on password reset endpoints')
        
        if 'predictable_token' in str(findings):
            suggestions.append('Use cryptographically secure random token generation')
        
        if 'short_token' in str(findings):
            suggestions.append('Increase token length to at least 32 characters')
        
        if 'token_reuse' in str(findings):
            suggestions.append('Ensure tokens are single-use and expire quickly')
        
        if 'missing_csrf' in str(findings):
            suggestions.append('Implement CSRF protection for state-changing operations')
        
        if 'sensitive_info_exposed' in str(findings):
            suggestions.append('Remove sensitive information from API responses')
        
        if 'insecure_transmission' in str(findings):
            suggestions.append('Enforce HTTPS for all password reset operations')
        
        if not suggestions:
            suggestions.append('Continue monitoring for security best practices')
        
        return suggestions


class PayloadGeneratorTC5:
    """Generate test payloads for security testing"""
    
    @staticmethod
    def generate_password_reset_payloads(original_payload: Dict) -> List[Dict]:
        """Generate various payloads for password reset testing"""
        payloads = []
        
        if not original_payload:
            return payloads
        
        # Test with empty email
        empty_email_payload = original_payload.copy()
        if 'email' in empty_email_payload:
            empty_email_payload['email'] = ''
            payloads.append({
                'name': 'empty_email',
                'payload': empty_email_payload,
                'description': 'Test with empty email field'
            })
        
        # Test with invalid email
        invalid_email_payload = original_payload.copy()
        if 'email' in invalid_email_payload:
            invalid_email_payload['email'] = 'invalid-email'
            payloads.append({
                'name': 'invalid_email',
                'payload': invalid_email_payload,
                'description': 'Test with invalid email format'
            })
        
        # Test with SQL injection in email
        sql_injection_payload = original_payload.copy()
        if 'email' in sql_injection_payload:
            sql_injection_payload['email'] = "admin@example.com' OR '1'='1"
            payloads.append({
                'name': 'sql_injection',
                'payload': sql_injection_payload,
                'description': 'Test for SQL injection vulnerability'
            })
        
        # Test with very long email
        long_email_payload = original_payload.copy()
        if 'email' in long_email_payload:
            long_email_payload['email'] = 'a' * 1000 + '@example.com'
            payloads.append({
                'name': 'long_email',
                'payload': long_email_payload,
                'description': 'Test with excessively long email'
            })
        
        # Test with missing required fields
        for field in original_payload.keys():
            missing_field_payload = original_payload.copy()
            del missing_field_payload[field]
            payloads.append({
                'name': f'missing_{field}',
                'payload': missing_field_payload,
                'description': f'Test with missing {field} field'
            })
        
        return payloads
    
    @staticmethod
    def generate_headers_variations(original_headers: Dict) -> List[Dict]:
        """Generate header variations for testing"""
        variations = []
        
        # Test without authorization
        no_auth_headers = original_headers.copy()
        if 'Authorization' in no_auth_headers:
            del no_auth_headers['Authorization']
            variations.append({
                'name': 'no_authorization',
                'headers': no_auth_headers,
                'description': 'Test without authorization header'
            })
        
        # Test with invalid content type
        invalid_content_type = original_headers.copy()
        invalid_content_type['Content-Type'] = 'text/plain'
        variations.append({
            'name': 'invalid_content_type',
            'headers': invalid_content_type,
            'description': 'Test with invalid content type'
        })
        
        # Test with additional security headers
        security_headers = original_headers.copy()
        security_headers.update({
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '192.168.1.1',
            'X-Requested-With': 'XMLHttpRequest'
        })
        variations.append({
            'name': 'security_headers',
            'headers': security_headers,
            'description': 'Test with additional security headers'
        })
        
        return variations


class ReportGeneratorTC5:
    """Generate security scan reports"""
    
    @staticmethod
    def generate_executive_summary(scan_results: List[Dict]) -> Dict:
        """Generate executive summary of scan results"""
        total_apis = len(scan_results)
        vulnerable_apis = len([r for r in scan_results if r.get('status') == 'vulnerable'])
        secure_apis = len([r for r in scan_results if r.get('status') == 'secure'])
        error_apis = len([r for r in scan_results if r.get('status') == 'error'])
        
        risk_scores = [r.get('risk_score', 0) for r in scan_results if r.get('risk_score')]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        severity_distribution = {}
        for result in scan_results:
            if result.get('vulnerability_type', {}).get('severity'):
                severity = result['vulnerability_type']['severity']
                severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        return {
            'total_apis_tested': total_apis,
            'vulnerable_apis': vulnerable_apis,
            'secure_apis': secure_apis,
            'error_apis': error_apis,
            'vulnerability_rate': (vulnerable_apis / total_apis * 100) if total_apis > 0 else 0,
            'average_risk_score': round(avg_risk_score, 2),
            'severity_distribution': severity_distribution,
            'overall_security_posture': ReportGeneratorTC5._calculate_security_posture(
                vulnerable_apis, total_apis, avg_risk_score
            )
        }
    
    @staticmethod
    def _calculate_security_posture(vulnerable_apis: int, total_apis: int, avg_risk_score: float) -> str:
        """Calculate overall security posture"""
        if total_apis == 0:
            return 'Unknown'
        
        vulnerability_rate = vulnerable_apis / total_apis
        
        if vulnerability_rate == 0:
            return 'Excellent'
        elif vulnerability_rate < 0.1 and avg_risk_score < 3:
            return 'Good'
        elif vulnerability_rate < 0.3 and avg_risk_score < 6:
            return 'Fair'
        elif vulnerability_rate < 0.6 and avg_risk_score < 8:
            return 'Poor'
        else:
            return 'Critical'
    
    @staticmethod
    def generate_detailed_findings(scan_result: Dict) -> Dict:
        """Generate detailed findings for a single scan result"""
        return {
            'api_details': {
                'name': scan_result.get('api_name'),
                'url': scan_result.get('api_url'),
                'method': scan_result.get('api_method')
            },
            'vulnerability_details': {
                'type': scan_result.get('vulnerability_type', {}).get('name'),
                'severity': scan_result.get('vulnerability_type', {}).get('severity'),
                'description': scan_result.get('vulnerability_type', {}).get('description')
            },
            'assessment_results': {
                'status': scan_result.get('status'),
                'confidence': scan_result.get('confidence'),
                'risk_score': scan_result.get('risk_score'),
                'evidence': scan_result.get('evidence', []),
                'exploit_details': scan_result.get('exploit_details')
            },
            'remediation': {
                'suggestions': scan_result.get('remediation_suggestion'),
                'priority': ReportGeneratorTC5._calculate_priority(scan_result.get('risk_score', 0))
            }
        }
    
    @staticmethod
    def _calculate_priority(risk_score: float) -> str:
        """Calculate remediation priority based on risk score"""
        if risk_score >= 8:
            return 'Critical'
        elif risk_score >= 6:
            return 'High'
        elif risk_score >= 4:
            return 'Medium'
        elif risk_score >= 2:
            return 'Low'
        else:
            return 'Info'