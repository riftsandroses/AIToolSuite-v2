import re
import json
import hashlib
import random
import string
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class CouponPatternGeneratorTC3:
    """Generate coupon code patterns for testing"""
    
    @staticmethod
    def generate_common_patterns() -> List[str]:
        """Generate common coupon code patterns"""
        patterns = []
        
        # Basic number patterns
        for i in range(1, 101):
            patterns.extend([
                f'SAVE{i}',
                f'DISCOUNT{i}',
                f'OFF{i}',
                f'PROMO{i}'
            ])
        
        # Seasonal patterns
        seasons = ['SUMMER', 'WINTER', 'SPRING', 'FALL', 'AUTUMN']
        for season in seasons:
            for i in [10, 15, 20, 25, 30, 50]:
                patterns.append(f'{season}{i}')
        
        # Event-based patterns
        events = ['BLACK', 'CYBER', 'FLASH', 'WEEKEND', 'MONDAY']
        for event in events:
            for i in [10, 15, 20, 25, 30, 50]:
                patterns.append(f'{event}{i}')
        
        # User type patterns
        user_types = ['STUDENT', 'SENIOR', 'MILITARY', 'TEACHER', 'NURSE']
        for user_type in user_types:
            for i in [10, 15, 20]:
                patterns.append(f'{user_type}{i}')
        
        return patterns
    
    @staticmethod
    def generate_sequential_patterns(base_code: str) -> List[str]:
        """Generate sequential variations of a base code"""
        patterns = []
        
        # Extract numbers from base code
        numbers = re.findall(r'\d+', base_code)
        if numbers:
            base_num = int(numbers[0])
            base_text = re.sub(r'\d+', '{}', base_code)
            
            # Generate variations around the base number
            for delta in range(-10, 11):
                new_num = base_num + delta
                if new_num > 0:
                    patterns.append(base_text.format(new_num))
        
        # Generate letter variations
        letters = re.findall(r'[A-Z]+', base_code)
        if letters:
            for letter_group in letters:
                # Try common variations
                variations = [
                    letter_group + 'S',  # Plural
                    letter_group[:-1] if len(letter_group) > 1 else letter_group,  # Singular
                    letter_group + '2',  # Version 2
                    letter_group + 'X',  # Special
                ]
                
                for variation in variations:
                    new_code = base_code.replace(letter_group, variation, 1)
                    patterns.append(new_code)
        
        return patterns[:50]  # Limit to 50 patterns
    
    @staticmethod
    def generate_weak_patterns() -> List[str]:
        """Generate commonly weak coupon patterns"""
        return [
            'TEST', 'DEMO', 'ADMIN', 'DEBUG', 'DEFAULT',
            '123456', '000000', '111111', 'PASSWORD',
            'COUPON', 'PROMO', 'CODE', 'DISCOUNT',
            'FREE', 'GIFT', 'BONUS', 'SPECIAL',
            'VIP', 'MEMBER', 'LOYALTY', 'REWARD',
            'WELCOME', 'HELLO', 'START', 'BEGIN',
            'A', 'B', 'C', '1', '2', '3',
            'AAA', 'BBB', 'CCC', '111', '222', '333'
        ]


class ResponseAnalyzerTC3:
    """Analyze API responses for security patterns"""
    
    @staticmethod
    def analyze_coupon_response(status_code: int, response_text: str, 
                              request_data: Dict) -> Dict[str, Any]:
        """Analyze response for coupon-related security issues"""
        analysis = {
            'is_successful': False,
            'error_type': None,
            'information_disclosure': [],
            'timing_attack_possible': False,
            'hints_given': [],
            'confidence': 0.0
        }
        
        response_lower = response_text.lower()
        
        # Success indicators
        success_patterns = [
            r'discount\s+applied', r'coupon\s+applied', r'promo\s+applied',
            r'code\s+accepted', r'valid\s+code', r'successfully\s+applied',
            r'savings?:\s*\$?\d+', r'total:\s*\$?\d+', r'discounted',
            r'reduced\s+by', r'amount\s+saved'
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response_lower):
                analysis['is_successful'] = True
                analysis['confidence'] += 0.2
                break
        
        # Error analysis
        error_patterns = {
            'invalid_code': [r'invalid\s+code', r'code\s+not\s+found', r'unknown\s+code'],
            'expired_code': [r'expired', r'no\s+longer\s+valid', r'past\s+expiration'],
            'usage_limit': [r'already\s+used', r'limit\s+exceeded', r'maximum\s+usage'],
            'conditions_not_met': [r'minimum\s+order', r'not\s+eligible', r'requirements']
        }
        
        for error_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_lower):
                    analysis['error_type'] = error_type
                    analysis['confidence'] += 0.1
                    break
        
        # Information disclosure detection
        disclosure_patterns = [
            r'code\s+format', r'should\s+be\s+\d+\s+characters',
            r'valid\s+codes\s+start\s+with', r'example:\s*[A-Z0-9]+',
            r'try\s+[A-Z0-9]+', r'similar\s+codes?:\s*[A-Z0-9,\s]+'
        ]
        
        for pattern in disclosure_patterns:
            matches = re.findall(pattern, response_lower)
            if matches:
                analysis['information_disclosure'].extend(matches)
                analysis['confidence'] += 0.3
        
        # Timing attack detection (placeholder - would need timing data)
        if 'database' in response_lower or 'query' in response_lower:
            analysis['timing_attack_possible'] = True
        
        # Hints detection
        hint_patterns = [
            r'did\s+you\s+mean', r'suggestion', r'perhaps\s+you\s+meant',
            r'close\s+match', r'similar\s+code'
        ]
        
        for pattern in hint_patterns:
            matches = re.findall(pattern, response_lower)
            if matches:
                analysis['hints_given'].extend(matches)
                analysis['confidence'] += 0.2
        
        return analysis
    
    @staticmethod
    def detect_rate_limiting(responses: List[Dict]) -> Dict[str, Any]:
        """Detect rate limiting patterns"""
        rate_limit_analysis = {
            'rate_limited': False,
            'threshold_detected': None,
            'rate_limit_type': None,
            'bypass_possible': False,
            'recommendations': []
        }
        
        status_codes = [r.get('status_code', 0) for r in responses]
        rate_limit_responses = [code for code in status_codes if code == 429]
        
        if rate_limit_responses:
            rate_limit_analysis['rate_limited'] = True
            rate_limit_analysis['threshold_detected'] = len(responses) - len(rate_limit_responses) + 1
            
            # Check if rate limiting is consistent
            first_rate_limit_index = status_codes.index(429)
            if first_rate_limit_index < len(responses) * 0.5:
                rate_limit_analysis['rate_limit_type'] = 'aggressive'
            else:
                rate_limit_analysis['rate_limit_type'] = 'permissive'
        else:
            rate_limit_analysis['bypass_possible'] = True
            rate_limit_analysis['recommendations'].append('Implement rate limiting')
        
        return rate_limit_analysis


class SecurityMetricsTC3:
    """Calculate security metrics and scores"""
    
    @staticmethod
    def calculate_risk_score(vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score"""
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            confidence = vuln.get('confidence_score', 0.5)
            score = severity_weights.get(severity, 1) * confidence
            total_score += score
        
        # Normalize to 0-100 scale
        max_possible_score = len(vulnerabilities) * 10
        if max_possible_score > 0:
            return min(100, (total_score / max_possible_score) * 100)
        return 0
    
    @staticmethod
    def calculate_api_security_score(api_results: Dict) -> Dict[str, Any]:
        """Calculate security score for a single API"""
        score = 100  # Start with perfect score
        
        vulnerabilities = api_results.get('vulnerabilities', [])
        test_results = api_results.get('test_results', [])
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            deductions = {
                'critical': 40,
                'high': 25,
                'medium': 15,
                'low': 5,
                'info': 2
            }
            score -= deductions.get(severity, 2)
        
        # Deduct points for failed tests
        failed_tests = [t for t in test_results if t.get('status') == 'failed']
        score -= len(failed_tests) * 3
        
        # Bonus for passing security tests
        successful_tests = [t for t in test_results if t.get('status') == 'success']
        if len(successful_tests) > 5:
            score += 5
        
        score = max(0, min(100, score))
        
        return {
            'score': score,
            'grade': SecurityMetricsTC3._score_to_grade(score),
            'vulnerabilities_count': len(vulnerabilities),
            'tests_passed': len(successful_tests),
            'tests_failed': len(failed_tests)
        }
    
    @staticmethod
    def _score_to_grade(score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'


class ReportGeneratorTC3:
    """Generate security reports and summaries"""
    
    @staticmethod
    def generate_executive_summary(scan_data: Dict) -> Dict[str, Any]:
        """Generate executive summary for scan results"""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate risk level
        risk_score = SecurityMetricsTC3.calculate_risk_score(vulnerabilities)
        
        if risk_score >= 80:
            risk_level = 'Critical'
            action_required = 'Immediate'
        elif risk_score >= 60:
            risk_level = 'High'
            action_required = 'Within 24 hours'
        elif risk_score >= 40:
            risk_level = 'Medium'
            action_required = 'Within 1 week'
        elif risk_score >= 20:
            risk_level = 'Low'
            action_required = 'Within 1 month'
        else:
            risk_level = 'Minimal'
            action_required = 'As time permits'
        
        return {
            'overall_risk_level': risk_level,
            'risk_score': risk_score,
            'action_required': action_required,
            'total_vulnerabilities': len(vulnerabilities),
            'critical_count': severity_counts.get('critical', 0),
            'high_count': severity_counts.get('high', 0),
            'medium_count': severity_counts.get('medium', 0),
            'apis_tested': scan_data.get('total_apis', 0),
            'scan_duration': scan_data.get('duration', 0),
            'completion_status': scan_data.get('status', 'unknown')
        }
    
    @staticmethod
    def generate_remediation_plan(vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation plan"""
        # Sort by severity and confidence
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: (
                severity_order.get(v.get('severity', 'info'), 4),
                -v.get('confidence_score', 0)
            )
        )
        
        remediation_plan = []
        for i, vuln in enumerate(sorted_vulns[:20], 1):  # Top 20
            effort_estimate = ReportGeneratorTC3._estimate_remediation_effort(vuln)
            
            remediation_plan.append({
                'priority': i,
                'vulnerability_title': vuln.get('title', 'Unknown'),
                'severity': vuln.get('severity', 'info'),
                'api_affected': vuln.get('api_name', 'Unknown'),
                'estimated_effort': effort_estimate,
                'remediation_steps': vuln.get('remediation', 'No specific steps provided'),
                'business_impact': vuln.get('impact', 'Unknown impact'),
                'confidence_level': vuln.get('confidence_score', 0.5)
            })
        
        return remediation_plan
    
    @staticmethod
    def _estimate_remediation_effort(vulnerability: Dict) -> str:
        """Estimate effort required for remediation"""
        vuln_type = vulnerability.get('vulnerability_type', '')
        severity = vulnerability.get('severity', 'info')
        
        effort_matrix = {
            'coupon_bruteforce': {
                'critical': 'High (1-2 weeks)',
                'high': 'Medium (3-5 days)',
                'medium': 'Low (1-2 days)',
                'low': 'Low (1 day)',
                'info': 'Minimal (< 1 day)'
            },
            'rate_limit_bypass': {
                'critical': 'Medium (3-5 days)',
                'high': 'Medium (2-3 days)',
                'medium': 'Low (1 day)',
                'low': 'Low (< 1 day)',
                'info': 'Minimal (< 1 day)'
            },
            'code_reuse': {
                'critical': 'High (1-2 weeks)',
                'high': 'High (1 week)',
                'medium': 'Medium (3-5 days)',
                'low': 'Medium (2-3 days)',
                'info': 'Low (1 day)'
            },
            'code_stacking': {
                'critical': 'High (2-3 weeks)',
                'high': 'High (1-2 weeks)',
                'medium': 'Medium (1 week)',
                'low': 'Medium (3-5 days)',
                'info': 'Low (1-2 days)'
            }
        }
        
        return effort_matrix.get(vuln_type, {}).get(severity, 'Medium (3-5 days)')


class CacheManagerTC3:
    """Manage caching for scan results and statistics"""
    
    @staticmethod
    def cache_scan_results(scan_id: str, results: Dict, timeout: int = 3600):
        """Cache scan results"""
        cache_key = f'scan_results_{scan_id}'
        cache.set(cache_key, results, timeout)
    
    @staticmethod
    def get_cached_scan_results(scan_id: str) -> Optional[Dict]:
        """Get cached scan results"""
        cache_key = f'scan_results_{scan_id}'
        return cache.get(cache_key)
    
    @staticmethod
    def cache_vulnerability_summary(scan_id: str, summary: Dict, timeout: int = 1800):
        """Cache vulnerability summary"""
        cache_key = f'vuln_summary_{scan_id}'
        cache.set(cache_key, summary, timeout)
    
    @staticmethod
    def get_cached_vulnerability_summary(scan_id: str) -> Optional[Dict]:
        """Get cached vulnerability summary"""
        cache_key = f'vuln_summary_{scan_id}'
        return cache.get(cache_key)
    
    @staticmethod
    def invalidate_scan_cache(scan_id: str):
        """Invalidate all cache entries for a scan"""
        cache_keys = [
            f'scan_results_{scan_id}',
            f'vuln_summary_{scan_id}',
            f'scan_stats_{scan_id}'
        ]
        cache.delete_many(cache_keys)


class ConfigManagerTC3:
    """Manage configuration and settings"""
    
    DEFAULT_CONFIG = {
        'max_requests_per_second': 2,
        'timeout_seconds': 30,
        'retry_attempts': 3,
        'enable_ai_analysis': True,
        'ai_model': 'gpt-4o-mini',
        'max_concurrent_scans': 5,
        'scan_retention_days': 90,
        'rate_limit_threshold': 10,
        'confidence_threshold': 0.7
    }
    
    @staticmethod
    def get_config(key: str, default=None):
        """Get configuration value"""
        return getattr(settings, f'API6_{key.upper()}', 
                      ConfigManagerTC3.DEFAULT_CONFIG.get(key, default))
    
    @staticmethod
    def validate_scan_config(config_data: Dict) -> Dict[str, Any]:
        """Validate scan configuration"""
        errors = {}
        
        max_rps = config_data.get('max_requests_per_second', 2)
        if not isinstance(max_rps, int) or max_rps < 1 or max_rps > 10:
            errors['max_requests_per_second'] = 'Must be integer between 1 and 10'
        
        timeout = config_data.get('timeout_seconds', 30)
        if not isinstance(timeout, int) or timeout < 10 or timeout > 300:
            errors['timeout_seconds'] = 'Must be integer between 10 and 300'
        
        retries = config_data.get('retry_attempts', 3)
        if not isinstance(retries, int) or retries < 1 or retries > 5:
            errors['retry_attempts'] = 'Must be integer between 1 and 5'
        
        wordlist = config_data.get('custom_wordlist', [])
        if not isinstance(wordlist, list):
            errors['custom_wordlist'] = 'Must be a list of strings'
        elif len(wordlist) > 1000:
            errors['custom_wordlist'] = 'Cannot exceed 1000 entries'
        
        return errors


class LoggerTC3:
    """Centralized logging utility"""
    
    @staticmethod
    def log_scan_start(scan_id: str, total_apis: int, user_id: Optional[int] = None):
        """Log scan start"""
        logger.info(f"Scan {scan_id} started - APIs: {total_apis}, User: {user_id}")
    
    @staticmethod
    def log_scan_complete(scan_id: str, duration: float, vulnerabilities: int):
        """Log scan completion"""
        logger.info(f"Scan {scan_id} completed - Duration: {duration}s, Vulnerabilities: {vulnerabilities}")
    
    @staticmethod
    def log_scan_error(scan_id: str, error: str, api_name: Optional[str] = None):
        """Log scan error"""
        api_info = f" (API: {api_name})" if api_name else ""
        logger.error(f"Scan {scan_id} error{api_info}: {error}")
    
    @staticmethod
    def log_vulnerability_found(scan_id: str, vuln_type: str, severity: str, api_name: str):
        """Log vulnerability discovery"""
        logger.warning(f"Scan {scan_id} - {severity.upper()} {vuln_type} in {api_name}")
    
    @staticmethod
    def log_api_test(scan_id: str, api_name: str, test_type: str, result: str):
        """Log API test result"""
        logger.debug(f"Scan {scan_id} - {api_name} {test_type}: {result}")


class ValidationUtilsTC3:
    """Input validation utilities"""
    
    @staticmethod
    def validate_scan_id(scan_id: Any) -> bool:
        """Validate scan ID format"""
        if not isinstance(scan_id, (int, str)):
            return False
        
        try:
            int(scan_id)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_coupon_code(code: str) -> bool:
        """Validate coupon code format"""
        if not isinstance(code, str):
            return False
        
        # Basic validation: alphanumeric, 3-50 characters
        if not re.match(r'^[A-Z0-9]{3,50}$', code.upper()):
            return False
        
        return True
    
    @staticmethod
    def validate_api_url(url: str) -> bool:
        """Validate API URL format"""
        if not isinstance(url, str):
            return False
        
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$',  # path and query - FIXED: added missing closing parenthesis and $
            re.IGNORECASE
        )
        
        return url_pattern.match(url) is not None
    
    @staticmethod
    def sanitize_response_data(response_data: Any) -> Any:
        """Sanitize response data for storage"""
        if isinstance(response_data, str):
            # Truncate long responses
            if len(response_data) > 10000:
                response_data = response_data[:9997] + '...'
            
            # Remove potential sensitive data patterns
            sensitive_patterns = [
                r'password["\s:=]+[^\s"]+',
                r'token["\s:=]+[^\s"]+',
                r'key["\s:=]+[^\s"]+',
                r'secret["\s:=]+[^\s"]+'
            ]
            
            for pattern in sensitive_patterns:
                response_data = re.sub(pattern, '[REDACTED]', response_data, flags=re.IGNORECASE)
        
        elif isinstance(response_data, dict):
            # Recursively sanitize dictionary
            sanitized = {}
            for key, value in response_data.items():
                sanitized[key] = ValidationUtilsTC3.sanitize_response_data(value)
            response_data = sanitized
        
        elif isinstance(response_data, list):
            # Recursively sanitize list items
            response_data = [ValidationUtilsTC3.sanitize_response_data(item) for item in response_data]
        
        return response_data


class PerformanceMonitorTC3:
    """Monitor and track performance metrics"""
    
    @staticmethod
    def track_api_response_time(api_name: str, response_time: float):
        """Track API response time"""
        cache_key = f'api_response_times_{api_name}'
        times = cache.get(cache_key, [])
        times.append(response_time)
        
        # Keep only last 100 response times
        if len(times) > 100:
            times = times[-100:]
        
        cache.set(cache_key, times, 3600)  # 1 hour
    
    @staticmethod
    def get_api_performance_stats(api_name: str) -> Dict[str, float]:
        """Get performance statistics for an API"""
        cache_key = f'api_response_times_{api_name}'
        times = cache.get(cache_key, [])
        
        if not times:
            return {'avg_response_time': 0, 'min_response_time': 0, 'max_response_time': 0}
        
        return {
            'avg_response_time': sum(times) / len(times),
            'min_response_time': min(times),
            'max_response_time': max(times),
            'total_requests': len(times)
        }
    
    @staticmethod
    def track_scan_performance(scan_id: str, metric: str, value: float):
        """Track scan performance metric"""
        cache_key = f'scan_performance_{scan_id}'
        metrics = cache.get(cache_key, {})
        metrics[metric] = value
        cache.set(cache_key, metrics, 7200)  # 2 hours
    
    @staticmethod
    def get_scan_performance_summary(scan_id: str) -> Dict[str, Any]:
        """Get performance summary for a scan"""
        cache_key = f'scan_performance_{scan_id}'
        return cache.get(cache_key, {})