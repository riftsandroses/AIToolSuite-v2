# services.py
import json
import random
import string
import time
import asyncio
import aiohttp
from typing import List, Dict, Any
from django.utils import timezone
from asgiref.sync import sync_to_async
from django.db.models import Count, Q, Sum, Avg
from datetime import datetime
from .models import (
    VulnerabilityScanTC1, VulnerabilityTestTC1,
    MassAccountTestResultTC1, ScanStatsTC1
)
from .utils.ai_generator import AIPayloadGeneratorTC1


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
            body = json.loads(api.get('body', '{}'))
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
            original_headers = json.loads(api.get('headers', '{}'))
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