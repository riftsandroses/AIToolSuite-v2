import re
import json
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import requests
from django.conf import settings
import subprocess
import tempfile
import os

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