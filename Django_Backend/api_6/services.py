# services.py
import json
import random
import string
import time
import asyncio
import aiohttp
import openai
import re
import hashlib
import uuid
from decimal import Decimal
from typing import Dict, List, Any, Optional, Tuple
from django.utils import timezone
from django.conf import settings
from django.db import transaction
from asgiref.sync import sync_to_async
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Count, Q, Sum, Avg
from datetime import datetime, timedelta
from .models import (
    VulnerabilityScanTC1, VulnerabilityTestTC1,
    MassAccountTestResultTC1, ScanStatsTC1,
    ScanTC3, VulnerabilityTC3, 
    ScanResultTC3, ScanConfigTC3
)
from .utils.ai_generator import AIPayloadGeneratorTC1
from .utils.utils_tc3 import (
    CouponPatternGeneratorTC3,
    ResponseAnalyzerTC3,
    SecurityMetricsTC3,
    ReportGeneratorTC3,
    CacheManagerTC3,
    ConfigManagerTC3,
    LoggerTC3,
    ValidationUtilsTC3,
    PerformanceMonitorTC3,
)
import logging
from openai import OpenAI


logger = logging.getLogger(__name__)


class VulnerabilityTestServiceTC1:
    """Service for running mass account creation vulnerability tests"""

    def __init__(self):
        self.ai_generator = AIPayloadGeneratorTC1()

    async def start_scan(self, scan_id: int, test_types: List[str] = None, **options) -> VulnerabilityScanTC1:
        """Start a new vulnerability scan"""
        if test_types is None:
            test_types = ['mass_account_creation']

        # Get APIs from api_orch
        apis = await self._get_apis_for_scan(scan_id)
        if not apis:
            raise ValueError(f"No APIs found for scan_id {scan_id}")

        # Create scan record
        scan = await sync_to_async(VulnerabilityScanTC1.objects.create)(
            scan_id=scan_id,
            name=options.get('scan_name', f'Vulnerability Scan {scan_id}'),
            total_apis=len(apis),
            status='running'
        )

        # Create stats record
        await sync_to_async(ScanStatsTC1.objects.create)(scan=scan)

        # Start testing asynchronously
        asyncio.create_task(self._run_scan_tests(scan, apis, test_types, options))

        return scan

    async def _get_apis_for_scan(self, scan_id: int) -> List[Dict]:
        """Get APIs from api_orch_postmanapi table"""
        from django.db import connection

        def fetch():
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT "id", "name", "method", "url", "headers", "body", "authorization",
                           "query_params", "pre_request_script", "test_script", "created_at"
                    FROM api_orch_postmanapi
                    WHERE "scan_id" = %s
                """, [scan_id])
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]

        return await sync_to_async(fetch, thread_sensitive=True)()

    async def _get_jwt_token(self, scan_id: int) -> str:
        """Get JWT token from api_orch_scantokens table"""
        from django.db import connection

        def fetch():
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

        return await sync_to_async(fetch, thread_sensitive=True)()

    async def _run_scan_tests(self, scan: VulnerabilityScanTC1, apis: List[Dict],
                            test_types: List[str], options: Dict):
        """Run all tests for the scan"""
        try:
            jwt_token = await self._get_jwt_token(scan.scan_id)

            for api in apis:
                for test_type in test_types:
                    if test_type == 'mass_account_creation':
                        await self._test_mass_account_creation(scan, api, jwt_token, options)

            # Update scan status
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            await sync_to_async(scan.save)()

            # Update stats
            await self._update_scan_stats(scan)

        except Exception as e:
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            await sync_to_async(scan.save)()
            
            # Ensure stats are updated even for failed scans
            try:
                await self._update_scan_stats(scan)
            except Exception as stats_error:
                print(f"Failed to update scan stats for failed scan: {stats_error}")
            
            print(f"Scan failed: {str(e)}")

    async def _test_mass_account_creation(self, scan: VulnerabilityScanTC1,
                                          api: Dict, jwt_token: str, options: Dict):
        """Test for mass account creation vulnerability"""
        if not self._is_signup_api(api):
            return

        test = await sync_to_async(VulnerabilityTestTC1.objects.create)(
            scan=scan,
            api_id=api['id'],
            api_name=api['name'],
            api_url=api['url'],
            api_method=api['method'],
            test_type='mass_account_creation',
            test_name='Mass Account Creation Test',
            test_description='Test for automated account creation without proper verification',
            status='running',
            started_at=timezone.now()
        )

        try:
            result = await self._run_mass_account_test(api, jwt_token, options)

            # Create mass account result
            await sync_to_async(MassAccountTestResultTC1.objects.create)(
                test=test,
                **result['metrics']
            )

            # Update test with results
            test.status = 'vulnerable' if result['is_vulnerable'] else 'not_vulnerable'
            test.is_vulnerable = result['is_vulnerable']
            test.severity = result['severity']
            test.test_results = result['test_data']
            test.completed_at = timezone.now()
            test.execution_time_ms = result['execution_time_ms']
            await sync_to_async(test.save)()

            # Update scan counters
            scan.tested_apis += 1
            if result['is_vulnerable']:
                scan.vulnerabilities_found += 1
            await sync_to_async(scan.save)()

        except Exception as e:
            test.status = 'error'
            test.error_message = str(e)
            test.completed_at = timezone.now()
            await sync_to_async(test.save)()

    def _is_signup_api(self, api: Dict) -> bool:
        """Check if API is a signup/registration endpoint"""
        signup_indicators = [
            'signup', 'register', 'registration', 'create-account',
            'new-user', 'user/create', 'auth/register'
        ]

        url = api['url'].lower()
        name = api['name'].lower() if api['name'] else ''

        return any(indicator in url or indicator in name for indicator in signup_indicators)

    async def _run_mass_account_test(self, api: Dict, jwt_token: str, options: Dict) -> Dict:
        """Run the actual mass account creation test"""
        max_accounts = options.get('max_accounts_per_api', 5)
        timeout = options.get('timeout_seconds', 30)

        start_time = time.time()
        results = {
            'attempts': [],
            'successful': 0,
            'failed': 0,
            'rate_limited': 0,
            'response_times': [],
            'accounts_created': [],
            'failed_payloads': [],
            'has_verification': False,
            'has_captcha': False,
            'has_rate_limiting': False,
            'has_ip_restrictions': False
        }

        # Generate test payloads using AI
        payloads = await self._generate_signup_payloads(api, max_accounts)

        # Test each payload
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            for i, payload in enumerate(payloads):
                try:
                    attempt_start = time.time()
                    headers = self._prepare_headers(api, jwt_token)

                    async with session.request(
                        method=api['method'],
                        url=api['url'],
                        headers=headers,
                        json=payload,
                    ) as response:
                        response_time = (time.time() - attempt_start) * 1000
                        results['response_times'].append(response_time)

                        response_text = await response.text()

                        attempt_result = {
                            'payload': payload,
                            'status_code': response.status,
                            'response_time_ms': response_time,
                            'response_body': response_text[:1000]
                        }

                        results['attempts'].append(attempt_result)

                        if response.status in [200, 201]:
                            if self._is_successful_signup(response_text):
                                results['successful'] += 1
                                results['accounts_created'].append(payload)
                            else:
                                results['has_verification'] = True
                                results['failed'] += 1
                                results['failed_payloads'].append(payload)
                        elif response.status == 429:
                            results['rate_limited'] += 1
                            results['has_rate_limiting'] = True
                        else:
                            results['failed'] += 1
                            results['failed_payloads'].append(payload)

                        if 'captcha' in response_text.lower() or 'recaptcha' in response_text.lower():
                            results['has_captcha'] = True

                except Exception:
                    results['failed'] += 1
                    results['failed_payloads'].append(payload)

                await asyncio.sleep(0.5)

        execution_time_ms = int((time.time() - start_time) * 1000)

        is_vulnerable = self._analyze_mass_account_vulnerability(results)
        severity = self._determine_severity(results)

        return {
            'is_vulnerable': is_vulnerable,
            'severity': severity,
            'execution_time_ms': execution_time_ms,
            'test_data': results,
            'metrics': {
                'total_attempts': len(payloads),
                'successful_accounts': results['successful'],
                'failed_attempts': results['failed'],
                'rate_limited_attempts': results['rate_limited'],
                'has_email_verification': results['has_verification'],
                'has_phone_verification': False,
                'has_captcha': results['has_captcha'],
                'has_rate_limiting': results['has_rate_limiting'],
                'has_ip_restrictions': results['has_ip_restrictions'],
                'average_response_time_ms': sum(results['response_times']) / len(results['response_times']) if results['response_times'] else 0,
                'success_rate_percentage': (results['successful'] / len(payloads)) * 100 if payloads else 0,
                'accounts_per_minute': (results['successful'] / (execution_time_ms / 60000)) if execution_time_ms > 0 else 0,
                'generated_accounts': results['accounts_created'][:10],
                'failed_payloads': results['failed_payloads'][:5]
            }
        }

    async def _generate_signup_payloads(self, api: Dict, count: int) -> List[Dict]:
        try:
            body = json.loads(api.get('body') or '{}')
            if isinstance(body, dict) and 'raw' in body:
                body = json.loads(body['raw'])

            payloads = await self.ai_generator.generate_signup_payloads(body, count)
            if not payloads:
                payloads = self._generate_manual_payloads(body, count)
            return payloads

        except Exception:
            return self._generate_basic_payloads(count)

    def _generate_manual_payloads(self, base_payload: Dict, count: int) -> List[Dict]:
        payloads = []
        for i in range(count):
            payload = base_payload.copy()
            random_string = ''.join(random.choices(string.ascii_lowercase, k=8))
            if 'email' in payload:
                payload['email'] = f"test{random_string}@example.com"
            if 'username' in payload:
                payload['username'] = f"user{random_string}"
            if 'password' in payload:
                payload['password'] = f"Test123!{random_string[:4]}"
            if 'name' in payload:
                payload['name'] = f"Test User {i+1}"
            if 'phone' in payload:
                payload['phone'] = f"+1{random.randint(1000000000, 9999999999)}"
            payloads.append(payload)
        return payloads

    def _generate_basic_payloads(self, count: int) -> List[Dict]:
        payloads = []
        for i in range(count):
            random_string = ''.join(random.choices(string.ascii_lowercase, k=8))
            payload = {
                'email': f"test{random_string}@example.com",
                'username': f"user{random_string}",
                'password': f"Test123!{random_string[:4]}",
                'name': f"Test User {i+1}",
                'phone': f"+1{random.randint(1000000000, 9999999999)}"
            }
            payloads.append(payload)
        return payloads

    def _prepare_headers(self, api: Dict, jwt_token: str) -> Dict:
        headers = {}
        try:
            original_headers = json.loads(api.get('headers') or '{}')
            headers.update(original_headers)
        except Exception:
            pass
        if jwt_token:
            headers['Authorization'] = f'Bearer {jwt_token}'
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        return headers

    def _is_successful_signup(self, response_text: str) -> bool:
        success_indicators = [
            'success', 'created', 'welcome', 'registered', 'account created',
            'user id', 'token', 'verification', 'confirmation'
        ]
        response_lower = response_text.lower()
        return any(indicator in response_lower for indicator in success_indicators)

    def _analyze_mass_account_vulnerability(self, results: Dict) -> bool:
        if results['successful'] >= 3:
            return True
        if not results['has_rate_limiting'] and results['successful'] > 0:
            return True
        if not results['has_verification'] and not results['has_captcha'] and results['successful'] > 0:
            return True
        return False

    def _determine_severity(self, results: Dict) -> str:
        if results['successful'] >= 5 and not results['has_rate_limiting']:
            return 'high'
        elif results['successful'] >= 3:
            return 'medium'
        elif results['successful'] > 0:
            return 'low'
        else:
            return 'info'

    async def _update_scan_stats(self, scan: VulnerabilityScanTC1):
        """Update scan statistics - handles both completed and failed scans"""
        def get_or_create_stats():
            try:
                return ScanStatsTC1.objects.get(scan=scan)
            except ScanStatsTC1.DoesNotExist:
                return ScanStatsTC1.objects.create(scan=scan)
        
        stats = await sync_to_async(get_or_create_stats)()
        
        # Get all tests for this scan
        tests = await sync_to_async(list)(scan.tests.all())
        
        # Count vulnerabilities by severity
        for test in tests:
            if test.is_vulnerable:
                if test.severity == 'critical':
                    stats.critical_vulnerabilities += 1
                elif test.severity == 'high':
                    stats.high_vulnerabilities += 1
                elif test.severity == 'medium':
                    stats.medium_vulnerabilities += 1
                elif test.severity == 'low':
                    stats.low_vulnerabilities += 1
                else:
                    stats.info_vulnerabilities += 1

        # Count mass account tests
        mass_account_tests = [t for t in tests if t.test_type == 'mass_account_creation']
        stats.mass_account_tests = len(mass_account_tests)
        stats.mass_account_vulnerable = len([t for t in mass_account_tests if t.is_vulnerable])

        # Calculate performance metrics only for completed tests
        completed_tests = [t for t in tests if t.status in ['vulnerable', 'not_vulnerable']]
        if completed_tests:
            times = [t.execution_time_ms for t in completed_tests if t.execution_time_ms]
            if times:
                stats.average_response_time_ms = sum(times) / len(times)
            stats.test_success_rate = (len(completed_tests) / len(tests)) * 100 if tests else 0

        # API coverage
        stats.api_coverage_percentage = (scan.tested_apis / scan.total_apis) * 100 if scan.total_apis > 0 else 0
        
        # For failed scans, set some default values
        if scan.status == 'failed':
            stats.total_requests_sent = len(tests)
        
        await sync_to_async(stats.save)()


class ScanManagementServiceTC1:
    """Service for managing scans and retrieving results"""

    def get_vulnerability_summary(self) -> Dict:
        """Get vulnerability summary with error handling for missing stats"""
        try:
            # Basic counts
            total_scans = VulnerabilityScanTC1.objects.count()
            active_scans = VulnerabilityScanTC1.objects.filter(status__in=['pending', 'running']).count()
            completed_scans = VulnerabilityScanTC1.objects.filter(status='completed').count()
            failed_scans = VulnerabilityScanTC1.objects.filter(status='failed').count()

            # Test counts
            total_tests = VulnerabilityTestTC1.objects.count()
            vulnerable_tests = VulnerabilityTestTC1.objects.filter(is_vulnerable=True).count()

            # Vulnerabilities by severity - handle cases where severity might be null
            vulnerabilities_by_severity = VulnerabilityTestTC1.objects.filter(
                is_vulnerable=True
            ).exclude(severity__isnull=True).values('severity').annotate(count=Count('id'))
            severity_dict = {item['severity']: item['count'] for item in vulnerabilities_by_severity}

            # Vulnerabilities by type
            vulnerabilities_by_type = VulnerabilityTestTC1.objects.filter(
                is_vulnerable=True
            ).values('test_type').annotate(count=Count('id'))
            type_dict = {item['test_type']: item['count'] for item in vulnerabilities_by_type}

            # Get recent scans for the dashboard
            recent_scans = VulnerabilityScanTC1.objects.order_by('-created_at')[:5]

            # Calculate total vulnerabilities from scans (alternative method)
            total_vulns_from_scans = VulnerabilityScanTC1.objects.aggregate(
                total_vulns=Sum('vulnerabilities_found')
            )['total_vulns'] or 0

            return {
                'total_scans': total_scans,
                'active_scans': active_scans,
                'completed_scans': completed_scans,
                'failed_scans': failed_scans,
                'total_tests': total_tests,
                'vulnerable_tests': vulnerable_tests,
                'total_vulnerabilities': total_vulns_from_scans,
                'vulnerabilities_by_severity': severity_dict,
                'vulnerabilities_by_type': type_dict,
                'top_vulnerable_apis': [],
                'recent_scans': list(recent_scans.values('id', 'scan_id', 'name', 'status', 'created_at'))
            }

        except Exception as e:
            print(f"Error in get_vulnerability_summary: {str(e)}")
            # Return a basic summary even if there are errors
            return {
                'total_scans': VulnerabilityScanTC1.objects.count(),
                'active_scans': 0,
                'completed_scans': 0,
                'failed_scans': 0,
                'total_tests': 0,
                'vulnerable_tests': 0,
                'total_vulnerabilities': 0,
                'vulnerabilities_by_severity': {},
                'vulnerabilities_by_type': {},
                'top_vulnerable_apis': [],
                'recent_scans': []
            }

    def get_scan_stats(self, scan_id: int) -> Dict:
        """Get scan statistics with fallback if stats don't exist"""
        try:
            scan = VulnerabilityScanTC1.objects.get(scan_id=scan_id)
            
            # Try to get stats, create if they don't exist
            stats, created = ScanStatsTC1.objects.get_or_create(scan=scan)
            
            if created:
                # Calculate stats if they were just created
                self._calculate_scan_stats(scan, stats)
            
            return {
                'critical_vulnerabilities': stats.critical_vulnerabilities,
                'high_vulnerabilities': stats.high_vulnerabilities,
                'medium_vulnerabilities': stats.medium_vulnerabilities,
                'low_vulnerabilities': stats.low_vulnerabilities,
                'info_vulnerabilities': stats.info_vulnerabilities,
                'mass_account_tests': stats.mass_account_tests,
                'mass_account_vulnerable': stats.mass_account_vulnerable,
                'total_requests_sent': stats.total_requests_sent or 0,
                'average_response_time_ms': stats.average_response_time_ms,
                'total_execution_time_seconds': stats.total_execution_time_seconds,
                'test_success_rate': stats.test_success_rate,
                'api_coverage_percentage': stats.api_coverage_percentage,
                'vulnerability_breakdown': {
                    'critical': stats.critical_vulnerabilities,
                    'high': stats.high_vulnerabilities,
                    'medium': stats.medium_vulnerabilities,
                    'low': stats.low_vulnerabilities,
                    'info': stats.info_vulnerabilities,
                }
            }
            
        except VulnerabilityScanTC1.DoesNotExist:
            return {'error': 'Scan not found'}
        except Exception as e:
            print(f"Error getting scan stats: {str(e)}")
            return {'error': 'Failed to get scan statistics'}

    def _calculate_scan_stats(self, scan: VulnerabilityScanTC1, stats: ScanStatsTC1):
        """Calculate scan statistics manually"""
        try:
            tests = VulnerabilityTestTC1.objects.filter(scan=scan)
            
            # Count vulnerabilities by severity
            stats.critical_vulnerabilities = tests.filter(
                is_vulnerable=True, severity='critical'
            ).count()
            stats.high_vulnerabilities = tests.filter(
                is_vulnerable=True, severity='high'
            ).count()
            stats.medium_vulnerabilities = tests.filter(
                is_vulnerable=True, severity='medium'
            ).count()
            stats.low_vulnerabilities = tests.filter(
                is_vulnerable=True, severity='low'
            ).count()
            stats.info_vulnerabilities = tests.filter(
                is_vulnerable=True, severity='info'
            ).count()
            
            # Count mass account tests
            mass_account_tests = tests.filter(test_type='mass_account_creation')
            stats.mass_account_tests = mass_account_tests.count()
            stats.mass_account_vulnerable = mass_account_tests.filter(
                is_vulnerable=True
            ).count()
            
            # Calculate performance metrics
            completed_tests = tests.filter(status__in=['vulnerable', 'not_vulnerable'])
            if completed_tests.exists():
                avg_time = completed_tests.aggregate(
                    avg_time=Avg('execution_time_ms')
                )['avg_time']
                stats.average_response_time_ms = avg_time
                stats.test_success_rate = (completed_tests.count() / tests.count()) * 100
            
            # API coverage
            stats.api_coverage_percentage = (scan.tested_apis / scan.total_apis) * 100 if scan.total_apis > 0 else 0
            
            # Total requests
            stats.total_requests_sent = tests.count()
            
            stats.save()
            
        except Exception as e:
            print(f"Error calculating scan stats: {str(e)}")

    def get_scan_results_filtered(self, filters: Dict) -> List[VulnerabilityTestTC1]:
        """Get filtered scan results"""
        queryset = VulnerabilityTestTC1.objects.all()
        
        if scan_id := filters.get('scan_id'):
            queryset = queryset.filter(scan_id=scan_id)
        
        if test_type := filters.get('test_type'):
            queryset = queryset.filter(test_type=test_type)
        
        if status_filter := filters.get('status'):
            queryset = queryset.filter(status=status_filter)
        
        if severity := filters.get('severity'):
            queryset = queryset.filter(severity=severity)
        
        if is_vulnerable := filters.get('is_vulnerable'):
            queryset = queryset.filter(is_vulnerable=is_vulnerable)
        
        if api_method := filters.get('api_method'):
            queryset = queryset.filter(api_method=api_method)
        
        if date_from := filters.get('date_from'):
            queryset = queryset.filter(created_at__gte=date_from)
        
        if date_to := filters.get('date_to'):
            queryset = queryset.filter(created_at__lte=date_to)
        
        return queryset.order_by('-created_at')

    def get_scan_history(self, page: int = 1, page_size: int = 20, 
                        status: str = None, date_from: datetime = None, 
                        date_to: datetime = None) -> Dict:
        """Get paginated scan history"""
        queryset = VulnerabilityScanTC1.objects.all()
        
        if status:
            queryset = queryset.filter(status=status)
        
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        queryset = queryset.order_by('-created_at')
        
        paginator = Paginator(queryset, page_size)
        page_obj = paginator.get_page(page)
        
        return {
            'results': page_obj.object_list,
            'total_count': paginator.count,
            'total_pages': paginator.num_pages,
            'current_page': page,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous(),
        }


class CouponBruteForceServiceTC3:
    """Service for performing coupon/promo code brute-force attacks"""

    def __init__(self):
        self.client = OpenAI(api_key=getattr(settings, "OPENAI_API_KEY", None))
        # Use generator methods from utils
        self.common_patterns = CouponPatternGeneratorTC3.generate_common_patterns()
        self.common_codes = CouponPatternGeneratorTC3.generate_weak_patterns()

    async def execute_scan(self, scan_id: str, apis: List[Dict], access_token: str, config: ScanConfigTC3):
        scan = await self._get_scan(scan_id)

        try:
            scan.status = "in_progress"
            scan.start_time = timezone.now()
            scan.total_apis = len(apis)
            await self._save_scan(scan)

            semaphore = asyncio.Semaphore(max(1, getattr(config, "max_requests_per_second", 2)))

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=getattr(config, "timeout_seconds", 30))) as session:
                tasks = []
                for api in apis:
                    if self._is_coupon_related_api(api):
                        tasks.append(self._test_api_with_semaphore(semaphore, session, api, access_token, scan, config))
                # run tasks
                await asyncio.gather(*tasks, return_exceptions=True)

            scan.status = "completed"
            scan.end_time = timezone.now()
            await self._save_scan(scan)

        except Exception as e:
            logger.exception("Scan failed")
            scan.status = "failed"
            scan.end_time = timezone.now()
            await self._save_scan(scan)
            raise

    async def _test_api_with_semaphore(self, semaphore, session, api, token, scan, config):
        async with semaphore:
            # spacing requests out slightly
            await asyncio.sleep(1.0 / max(1, getattr(config, "max_requests_per_second", 2)))
            return await self._test_single_api(session, api, token, scan, config)

    async def _test_single_api(self, session, api: Dict, token: str, scan: ScanTC3, config: ScanConfigTC3):
        api_id = api.get("id")
        api_name = api.get("name", "<unknown>")
        api_url = api.get("url", "<unknown>")
        method = api.get("method", "GET").upper()

        vulnerabilities: List[Dict] = []
        results: List[Dict] = []

        try:
            coupon_params = await self._discover_coupon_parameters(session, api, token)
            if coupon_params:
                # Brute force
                bf = await self._test_brute_force_attack(session, api, token, coupon_params, config)
                results.extend(bf["results"]); vulnerabilities.extend(bf["vulnerabilities"])

                # Reuse test
                reuse = await self._test_code_reuse(session, api, token, coupon_params, config)
                results.extend(reuse["results"]); vulnerabilities.extend(reuse["vulnerabilities"])

                # Stacking test
                stacking = await self._test_code_stacking(session, api, token, coupon_params, config)
                results.extend(stacking["results"]); vulnerabilities.extend(stacking["vulnerabilities"])

                # Rate limits
                rl = await self._test_rate_limits(session, api, token, coupon_params, config)
                results.extend(rl["results"]); vulnerabilities.extend(rl["vulnerabilities"])

            # AI-assisted analysis
            if getattr(config, "enable_ai_analysis", False) and results:
                try:
                    ai_analysis = await self._perform_ai_analysis(api, results, getattr(config, "ai_model", "gpt-4o-mini"))
                    if isinstance(ai_analysis, dict) and ai_analysis.get("additional_vulnerabilities"):
                        vulnerabilities.extend(ai_analysis["additional_vulnerabilities"])
                except Exception:
                    logger.exception("AI analysis failed, continuing")

            # Persist results
            await self._save_test_results(scan, api_id, api_name, api_url, method, results, vulnerabilities)
            await self._update_scan_progress(scan)

        except Exception as e:
            logger.exception("Error testing API")
            error_result = {
                "test_type": "coupon_testing",
                "status": "error",
                "error_message": str(e),
                "request_data": {},
                "response_data": {},
                "findings": {},
            }
            await self._save_test_results(scan, api_id, api_name, api_url, method, [error_result], [])

    def _is_coupon_related_api(self, api: Dict) -> bool:
        api_indicators = [
            "coupon", "promo", "discount", "voucher", "code", "offer",
            "deal", "redeem", "apply", "cart", "checkout", "payment", "order", "purchase", "buy",
        ]
        api_text = f"{api.get('name','')} {api.get('url','')}".lower()
        return any(ind in api_text for ind in api_indicators)

    async def _discover_coupon_parameters(self, session, api: Dict, token: str) -> List[str]:
        headers = json.loads(api.get("headers", "{}") or "{}")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        body = {}
        api_body = api.get("body") or {}
        if isinstance(api_body, dict) and api_body.get("mode") == "raw":
            try:
                body = json.loads(api_body.get("raw", "{}"))
            except Exception:
                body = {}
        elif isinstance(api_body, dict):
            # direct body dict case (not raw)
            body = api_body

        coupon_params: List[str] = []

        if isinstance(body, dict):
            for k in body.keys():
                if any(p in k.lower() for p in ["coupon", "promo", "discount", "code", "voucher"]):
                    coupon_params.append(k)

        common_param_names = [
            "coupon_code", "promo_code", "discount_code", "voucher_code",
            "coupon", "promo", "code", "voucher", "offer_code",
        ]
        for param_name in common_param_names:
            if param_name in coupon_params:
                continue
            test_body = body.copy() if isinstance(body, dict) else {}
            test_body[param_name] = "TEST123"
            try:
                async with session.request(api.get("method", "POST"), api.get("url"), headers=headers, json=test_body) as resp:
                    if resp.status not in (400, 422):
                        coupon_params.append(param_name)
            except Exception:
                continue

        return coupon_params

    async def _test_brute_force_attack(self, session, api: Dict, token: str, coupon_params: List[str], config: ScanConfigTC3) -> Dict[str, Any]:
        results: List[Dict] = []
        vulnerabilities: List[Dict] = []

        headers = json.loads(api.get("headers", "{}") or "{}")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        base_body = {}
        api_body = api.get("body") or {}
        if isinstance(api_body, dict) and api_body.get("mode") == "raw":
            try:
                base_body = json.loads(api_body.get("raw", "{}"))
            except Exception:
                base_body = {}
        elif isinstance(api_body, dict):
            base_body = api_body

        # wordlist and patterns
        test_codes = list(self.common_codes) + list(getattr(config, "custom_wordlist", []))
        for pattern in self.common_patterns:
            # expand small set to avoid explosion; keep reasonable
            for num in (5, 10, 15, 20, 25, 30, 50):
                test_codes.append(pattern.replace("{num}", str(num)))

        successful_codes: List[str] = []

        # limit attempts for performance
        limit = min(len(test_codes), 50)
        for code in test_codes[:limit]:
            for param in coupon_params:
                test_body = base_body.copy() if isinstance(base_body, dict) else {}
                test_body[param] = code
                try:
                    start = time.time()
                    async with session.request(api.get("method", "POST"), api.get("url"), headers=headers, json=test_body) as resp:
                        response_time = time.time() - start
                        text = await resp.text()
                        PerformanceMonitorTC3.track_api_response_time(api.get("name", "<api>"), response_time)

                        analysis = ResponseAnalyzerTC3.analyze_coupon_response(resp.status, text, {param: code})
                        result = {
                            "test_type": "coupon_bruteforce",
                            "status": "success",
                            "response_time": response_time,
                            "status_code": resp.status,
                            "request_data": {param: code},
                            "response_data": {"text": text[:200]},
                            "findings": analysis,
                        }
                        results.append(result)
                        if analysis.get("is_successful"):
                            successful_codes.append(code)
                except Exception as e:
                    results.append({
                        "test_type": "coupon_bruteforce",
                        "status": "error",
                        "error_message": str(e),
                        "request_data": {param: code},
                        "response_data": {},
                        "findings": {},
                    })

        if successful_codes:
            vulnerabilities.append({
                "vulnerability_type": "coupon_bruteforce",
                "severity": "high",
                "title": "Weak Coupon Code Validation",
                "description": f"Found {len(successful_codes)} valid coupon codes through brute force attack",
                "impact": "Attackers can guess valid coupon codes, leading to unauthorized discounts",
                "remediation": "Implement strong coupon generation, enforce account-based and IP rate limits",
                "evidence": {"valid_codes": successful_codes},
                "confidence_score": 0.9,
                "cwe_id": "CWE-307",
                "owasp_category": "A04:2021 - Insecure Design",
            })

        return {"results": results, "vulnerabilities": vulnerabilities}

    async def _test_code_reuse(self, session, api: Dict, token: str, coupon_params: List[str], config: ScanConfigTC3) -> Dict[str, Any]:
        results: List[Dict] = []
        vulnerabilities: List[Dict] = []

        headers = json.loads(api.get("headers", "{}") or "{}")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        base_body = {}
        api_body = api.get("body") or {}
        if isinstance(api_body, dict) and api_body.get("mode") == "raw":
            try:
                base_body = json.loads(api_body.get("raw", "{}"))
            except Exception:
                base_body = {}
        elif isinstance(api_body, dict):
            base_body = api_body

        param = coupon_params[0]
        test_code = "SAVE10"
        reuse_attempts = []

        for attempt in range(3):
            test_body = base_body.copy() if isinstance(base_body, dict) else {}
            test_body[param] = test_code
            try:
                async with session.request(api.get("method", "POST"), api.get("url"), headers=headers, json=test_body) as resp:
                    text = await resp.text()
                    analysis = ResponseAnalyzerTC3.analyze_coupon_response(resp.status, text, {param: test_code})
                    reuse_attempts.append({"attempt": attempt + 1, "analysis": analysis, "status": resp.status})
                    PerformanceMonitorTC3.track_api_response_time(api.get("name", "<api>"), 0.0)
            except Exception as e:
                reuse_attempts.append({"attempt": attempt + 1, "error": str(e)})

        successes = [r for r in reuse_attempts if isinstance(r.get("analysis"), dict) and r["analysis"].get("is_successful")]
        if len(successes) > 1:
            vulnerabilities.append({
                "vulnerability_type": "code_reuse",
                "severity": "high",
                "title": "Coupon Code Reuse Allowed",
                "description": f"Coupon code '{test_code}' appears reusable across multiple attempts",
                "impact": "Repeated use of same coupon allows abuse",
                "remediation": "Mark coupon as used after successful redemption and bind to user/session",
                "evidence": {"code": test_code, "attempts": reuse_attempts},
                "confidence_score": 0.95,
                "cwe_id": "CWE-284",
                "owasp_category": "A01:2021 - Broken Access Control",
            })

        results.append({
            "test_type": "code_reuse",
            "status": "success",
            "request_data": {param: test_code},
            "response_data": {"reuse_attempts": reuse_attempts},
            "findings": {"reuse_possible": len(successes) > 1},
        })

        return {"results": results, "vulnerabilities": vulnerabilities}

    async def _test_code_stacking(self, session, api: Dict, token: str, coupon_params: List[str], config: ScanConfigTC3) -> Dict[str, Any]:
        results: List[Dict] = []
        vulnerabilities: List[Dict] = []

        headers = json.loads(api.get("headers", "{}") or "{}")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        base_body = {}
        api_body = api.get("body") or {}
        if isinstance(api_body, dict) and api_body.get("mode") == "raw":
            try:
                base_body = json.loads(api_body.get("raw", "{}"))
            except Exception:
                base_body = {}
        elif isinstance(api_body, dict):
            base_body = api_body

        param = coupon_params[0]
        codes = ["SAVE10", "WELCOME20", "STUDENT15"]
        stacked_body = base_body.copy() if isinstance(base_body, dict) else {}
        stacked_body[param] = ",".join(codes)

        try:
            async with session.request(api.get("method", "POST"), api.get("url"), headers=headers, json=stacked_body) as resp:
                text = await resp.text()
                analysis = ResponseAnalyzerTC3.analyze_coupon_response(resp.status, text, {param: ",".join(codes)})
                if analysis.get("is_successful"):
                    vulnerabilities.append({
                        "vulnerability_type": "code_stacking",
                        "severity": "high",
                        "title": "Coupon Code Stacking Vulnerability",
                        "description": "Multiple coupon codes can be applied in one transaction",
                        "impact": "Stacked discounts enable excessive savings",
                        "remediation": "Disallow stacking of coupons; enforce business rules server-side",
                        "evidence": {"codes": codes},
                        "confidence_score": 0.9,
                        "cwe_id": "CWE-284",
                        "owasp_category": "A04:2021 - Insecure Design",
                    })
                results.append({
                    "test_type": "code_stacking",
                    "status": "success",
                    "request_data": {param: ",".join(codes)},
                    "response_data": {"text": text[:300]},
                    "findings": {"stacking_possible": analysis.get("is_successful", False)},
                })
        except Exception as e:
            results.append({"test_type": "code_stacking", "status": "error", "error_message": str(e), "request_data": {param: ",".join(codes)}, "response_data": {}, "findings": {}})

        return {"results": results, "vulnerabilities": vulnerabilities}

    async def _test_rate_limits(self, session, api: Dict, token: str, coupon_params: List[str], config: ScanConfigTC3) -> Dict[str, Any]:
        results: List[Dict] = []
        vulnerabilities: List[Dict] = []

        headers = json.loads(api.get("headers", "{}") or "{}")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        param = coupon_params[0]
        rate_limit_responses: List[Dict] = []

        for i in range(20):
            test_body = {param: f"TEST{i:03d}"}
            try:
                start = time.time()
                async with session.request(api.get("method", "POST"), api.get("url"), headers=headers, json=test_body) as resp:
                    response_time = time.time() - start
                    text = await resp.text()
                    PerformanceMonitorTC3.track_api_response_time(api.get("name", "<api>"), response_time)
                    rate_limit_responses.append({"status_code": resp.status, "response_time": response_time, "text": text[:200]})
            except Exception as e:
                rate_limit_responses.append({"error": str(e)})
            await asyncio.sleep(0.1)

        rl_analysis = ResponseAnalyzerTC3.detect_rate_limiting(rate_limit_responses)
        if rl_analysis.get("bypass_possible"):
            vulnerabilities.append({
                "vulnerability_type": "rate_limit_bypass",
                "severity": "medium",
                "title": "Insufficient Rate Limiting",
                "description": "API did not present effective rate limits during rapid requests",
                "impact": "Allows brute-force attacks and abuse",
                "remediation": "Implement strict per-IP/user rate limits and throttling",
                "evidence": rl_analysis,
                "confidence_score": 0.8,
                "cwe_id": "CWE-307",
                "owasp_category": "A04:2021 - Insecure Design",
            })

        results.append({
            "test_type": "rate_limit_test",
            "status": "success",
            "request_data": {"rapid_requests": 20},
            "response_data": {"responses": rate_limit_responses},
            "findings": rl_analysis,
        })

        return {"results": results, "vulnerabilities": vulnerabilities}

    async def _perform_ai_analysis(self, api: Dict, results: List[Dict], model: str) -> Dict:
        if not self.client:
            return {}
        try:
            analysis_data = {
                "api_name": api.get("name", ""),
                "api_url": api.get("url", ""),
                "test_results": results[-10:],
            }
            prompt = f"Analyze these API security test results for coupon vulnerabilities:\nAPI: {analysis_data['api_name']} - {analysis_data['api_url']}\nResults: {json.dumps(analysis_data['test_results'], default=str)[:20000]}"
            response = self.client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
            )
            # Expecting JSON back
            try:
                return json.loads(response.choices[0].message.content)
            except Exception:
                return {}
        except Exception:
            logger.exception("AI analysis call failed")
            return {}

    async def _get_scan(self, scan_id: str) -> ScanTC3:
        from asgiref.sync import sync_to_async
        return await sync_to_async(ScanTC3.objects.get)(id=scan_id)

    async def _save_scan(self, scan: ScanTC3):
        from asgiref.sync import sync_to_async
        await sync_to_async(scan.save)()

    async def _save_test_results(self, scan: ScanTC3, api_id: Optional[int], api_name: str, api_url: str, method: str, results: List[Dict], vulnerabilities: List[Dict]):
        from asgiref.sync import sync_to_async

        for result_data in results:
            result = ScanResultTC3(
                scan=scan,
                api_id=api_id,
                api_name=api_name,
                api_url=api_url,
                api_method=method,
                test_type=result_data.get("test_type", "unknown"),
                status=result_data.get("status", "error"),
                response_time=result_data.get("response_time"),
                status_code=result_data.get("status_code"),
                request_data=result_data.get("request_data", {}),
                response_data=result_data.get("response_data", {}),
                findings=result_data.get("findings", {}),
                error_message=result_data.get("error_message"),
            )
            await sync_to_async(result.save)()

        for vuln_data in vulnerabilities:
            vulnerability = VulnerabilityTC3(
                scan=scan,
                api_id=api_id,
                api_name=api_name,
                api_url=api_url,
                vulnerability_type=vuln_data.get("vulnerability_type"),
                severity=vuln_data.get("severity"),
                title=vuln_data.get("title"),
                description=vuln_data.get("description"),
                impact=vuln_data.get("impact"),
                remediation=vuln_data.get("remediation"),
                evidence=vuln_data.get("evidence", {}),
                cwe_id=vuln_data.get("cwe_id"),
                owasp_category=vuln_data.get("owasp_category"),
                confidence_score=vuln_data.get("confidence_score", 0.0),
            )
            await sync_to_async(vulnerability.save)()

    async def _update_scan_progress(self, scan: ScanTC3):
        from asgiref.sync import sync_to_async
        scan.processed_apis += 1
        scan.vulnerabilities_found = await sync_to_async(lambda: scan.vulnerabilities.count())()
        await sync_to_async(scan.save)()


class APIOrchServiceTC3:
    """Service to retrieve APIs and tokens from api_orch tables"""

    @staticmethod
    def get_apis_by_scan_id(scan_id: int) -> List[Dict]:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                       "query_params", "pre_request_script", "test_script"
                FROM api_orch_postmanapi 
                WHERE "scan_id" = %s
            """, [scan_id])
            cols = [c[0] for c in cursor.description]
            rows = cursor.fetchall()
        return [dict(zip(cols, r)) for r in rows]

    @staticmethod
    def get_access_token_by_scan_id(scan_id: int) -> Optional[str]:
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
