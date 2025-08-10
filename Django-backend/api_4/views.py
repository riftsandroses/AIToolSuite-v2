# views.py
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.pagination import PageNumberPagination
from rest_framework import permissions, status
from rest_framework.response import Response
from django.db import connection
from django.conf import settings
from django.db.models import Q, Count, Avg
from django.utils import timezone
from .models import UnboundedPaginationScan, RateLimitScan, ScanLog
from .serializers import UnboundedPaginationScanSerializer, UnboundedPaginationResultSerializer, RateLimitScanSerializer, ScanRequestSerializer, ScanStatsSerializer, ScanLogSerializer
from .utils.analyzer_tester import ChatGPTAnalyzer, VulnerabilityTester
from .utils.rate_limit_scanner import RateLimitScanner
from .pagination import StandardResultsSetPagination
import json
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
import logging 


logger = logging.getLogger(__name__)


class UnboundedPaginationScanView(APIView):
    """
    API View to scan for unbounded pagination vulnerabilities
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """
        Main API endpoint to scan for unbounded pagination vulnerabilities
        """
        serializer = UnboundedPaginationScanSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Get APIs from api_orch_postmanapi table
            apis = self.get_apis_by_scan_id(scan_id)
            logger.info(f"Scan {scan_id}: Found {len(apis)} APIs to analyze")
            if not apis:
                return Response({
                    'error': 'No APIs found for the given scan_id',
                    'scan_id': scan_id
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Get authentication token
            auth_token = self.get_auth_token(scan_id)
            logger.info(f"Scan {scan_id}: Retrieved authentication token: {'Found' if auth_token else 'Not Found'}")
            if not auth_token:
                return Response({
                    'error': 'No authentication token found for the given scan_id',
                    'scan_id': scan_id
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Initialize ChatGPT analyzer
            chatgpt_analyzer = ChatGPTAnalyzer(settings.OPENAI_API_KEY)
            vulnerability_tester = VulnerabilityTester()
            
            results = []
            batch_size = 10  # Process APIs in batches of 10
            
            # Process APIs in batches
            logger.info(f"Scan {scan_id}: Starting analysis with batch size {batch_size}")
            for i in range(0, len(apis), batch_size):
                batch = apis[i:i + batch_size]
                logger.info(f"Scan {scan_id}: Processing batch {i//batch_size + 1}/{(len(apis)-1)//batch_size + 1} with {len(batch)} APIs")
                
                # Analyze batch with ChatGPT
                analysis_result = chatgpt_analyzer.analyze_apis_for_pagination(batch)
                logger.info(f"Scan {scan_id}: ChatGPT identified {len(analysis_result.get('vulnerable_apis', []))} potentially vulnerable APIs in this batch")
                
                # Test each potentially vulnerable API
                for vulnerable_api in analysis_result.get('vulnerable_apis', []):
                    api_url = vulnerable_api['url']
                    
                    # Find the original API data
                    original_api = next((api for api in batch if api['url'] == api_url), None)
                    if not original_api:
                        continue
                    
                    # Test each suspicious parameter
                    for param_info in vulnerable_api.get('parameters', []):
                        result = self.test_api_vulnerability(
                            original_api, 
                            auth_token, 
                            param_info, 
                            vulnerability_tester,
                            analysis_result.get('analysis_summary', '')
                        )
                        result['scan_id'] = scan_id
                        results.append(result)
            
            # Save results to database
            saved_results = []
            for result_data in results:
                scan_result = UnboundedPaginationScan.objects.create(**result_data)
                saved_results.append(UnboundedPaginationResultSerializer(scan_result).data)
            
            return Response({
                'message': f'Scan completed successfully. Tested {len(results)} potential vulnerabilities.',
                'scan_id': scan_id,
                'results': saved_results,
                'summary': {
                    'total_tested': len(results),
                    'vulnerable_count': len([r for r in results if r['is_vulnerable']]),
                    'error_count': len([r for r in results if r['error_message']])
                }
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                'error': f'An error occurred during scanning: {str(e)}',
                'scan_id': scan_id
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_apis_by_scan_id(self, scan_id: str) -> List[Dict]:
        """
        Fetch APIs from api_orch_postmanapi table using scan_id
        """
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "url", "method", "headers", "body", "query_params", "authorization"
                FROM api_orch_postmanapi
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            apis = []
            for row in cursor.fetchall():
                api_data = dict(zip(columns, row))
                
                # Parse JSON fields
                for field in ['headers', 'body', 'query_params', 'authorization']:
                    if api_data.get(field):
                        try:
                            if isinstance(api_data[field], str):
                                api_data[field] = json.loads(api_data[field])
                        except json.JSONDecodeError:
                            api_data[field] = {}
                
                apis.append(api_data)
            
            return apis
    
    def get_auth_token(self, scan_id: str) -> Optional[str]:
        """
        Fetch authentication token from api_orch_scantokens table
        """
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "access_token" 
                FROM api_orch_scantokens 
                WHERE "scan_id" = %s
            """, [scan_id])
            
            result = cursor.fetchone()
            return result[0] if result else None
    
    def test_api_vulnerability(self, original_api: Dict, auth_token: str, param_info: Dict, 
                             vulnerability_tester: VulnerabilityTester, analysis_summary: str) -> Dict:
        """
        Test a single API for unbounded pagination vulnerability
        """
        param_name = param_info['name']
        param_location = param_info['location']
        test_value = param_info['test_value']

        logger.info(f"Testing API {original_api['url']} for parameter {param_name} with value {test_value}")
        
        # Prepare curl command
        curl_command = vulnerability_tester.prepare_curl_command(
            url=original_api['url'],
            method=original_api.get('method', 'GET'),
            headers=original_api.get('headers', {}),
            body=original_api.get('body', {}),
            query_params=original_api.get('query_params', {}),
            auth_token=auth_token,
            test_param=param_name,
            test_value=test_value,
            param_location=param_location
        )
        
        # Execute the test
        test_result = vulnerability_tester.execute_vulnerability_test(curl_command)
        
        # Determine if vulnerable (no error and status code indicates success)
        is_vulnerable = bool(
            test_result['success'] and 
            test_result['status_code'] and 
            200 <= test_result['status_code'] < 400
        )
        
        logger.info(f"API {original_api['url']} vulnerability test result: {'VULNERABLE' if is_vulnerable else 'NOT VULNERABLE'}")
        logger.debug(f"Test details - Status: {test_result['status_code']}, Size: {test_result['response_size']}, Error: {test_result['error']}")

        return {
            'api_url': original_api['url'],
            'method': original_api.get('method', 'GET'),
            'headers': original_api.get('headers', {}),
            'body': original_api.get('body', {}),
            'query_params': original_api.get('query_params', {}),
            'authorization': original_api.get('authorization', {}),
            'is_vulnerable': is_vulnerable,
            'vulnerable_parameter': param_name,
            'test_value_used': test_value,
            'response_status_code': test_result['status_code'],
            'response_size': test_result['response_size'],
            'error_message': test_result['error'],
            'chatgpt_analysis': analysis_summary,
            'identified_parameters': [param_info]
        }


class ScanResultsView(APIView):
    """
    API View to get results for a specific scan
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, scan_id):
        """
        Get results for a specific scan
        """
        try:
            results = UnboundedPaginationScan.objects.filter(scan_id=scan_id)
            
            if not results.exists():
                return Response({
                    'error': 'No scan results found for the given scan_id',
                    'scan_id': scan_id
                }, status=status.HTTP_404_NOT_FOUND)
            
            serializer = UnboundedPaginationResultSerializer(results, many=True)
            
            return Response({
                'scan_id': scan_id,
                'results': serializer.data,
                'summary': {
                    'total_tested': results.count(),
                    'vulnerable_count': results.filter(is_vulnerable=True).count(),
                    'error_count': results.exclude(error_message__isnull=True).exclude(error_message='').count()
                }
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                'error': f'An error occurred while fetching results: {str(e)}',
                'scan_id': scan_id
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ScanResultsListView(ListAPIView):
    """
    API View to list all scan results with optional filtering
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UnboundedPaginationResultSerializer
    
    def get_queryset(self):
        """
        Optionally restricts the returned results by filtering against query parameters
        """
        queryset = UnboundedPaginationScan.objects.all().order_by('-created_at')
        
        # Filter by scan_id if provided
        scan_id = self.request.query_params.get('scan_id', None)
        if scan_id is not None:
            queryset = queryset.filter(scan_id=scan_id)
        
        # Filter by vulnerability status if provided
        is_vulnerable = self.request.query_params.get('is_vulnerable', None)
        if is_vulnerable is not None:
            if is_vulnerable.lower() == 'true':
                queryset = queryset.filter(is_vulnerable=True)
            elif is_vulnerable.lower() == 'false':
                queryset = queryset.filter(is_vulnerable=False)
        
        # Filter by API URL if provided
        api_url = self.request.query_params.get('api_url', None)
        if api_url is not None:
            queryset = queryset.filter(api_url__icontains=api_url)
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        """
        Override list method to add summary information
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # Calculate summary statistics
        total_count = queryset.count()
        vulnerable_count = queryset.filter(is_vulnerable=True).count()
        error_count = queryset.exclude(error_message__isnull=True).exclude(error_message='').count()
        
        return Response({
            'results': serializer.data,
            'summary': {
                'total_results': total_count,
                'vulnerable_count': vulnerable_count,
                'error_count': error_count,
                'success_rate': round((total_count - error_count) / total_count * 100, 2) if total_count > 0 else 0
            },
            'filters_applied': {
                'scan_id': request.query_params.get('scan_id'),
                'is_vulnerable': request.query_params.get('is_vulnerable'),
                'api_url': request.query_params.get('api_url')
            }
        })


class VulnerableAPIsView(APIView):
    """
    API View to get only vulnerable APIs from scans
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Get all vulnerable APIs, optionally filtered by scan_id
        """
        try:
            queryset = UnboundedPaginationScan.objects.filter(is_vulnerable=True).order_by('-created_at')
            
            # Filter by scan_id if provided
            scan_id = request.query_params.get('scan_id', None)
            if scan_id:
                queryset = queryset.filter(scan_id=scan_id)
            
            serializer = UnboundedPaginationResultSerializer(queryset, many=True)
            
            return Response({
                'vulnerable_apis': serializer.data,
                'count': queryset.count(),
                'scan_id_filter': scan_id
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                'error': f'An error occurred while fetching vulnerable APIs: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ScanStatsView(APIView):
    """
    API View to get statistics about scans
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Get comprehensive statistics about all scans
        """
        try:
            # Get all scan results
            all_results = UnboundedPaginationScan.objects.all()
            
            # Get unique scan IDs
            unique_scans = all_results.values('scan_id').distinct().count()
            
            # Calculate statistics
            total_apis_tested = all_results.count()
            vulnerable_apis = all_results.filter(is_vulnerable=True).count()
            apis_with_errors = all_results.exclude(error_message__isnull=True).exclude(error_message='').count()
            
            # Get scan-wise statistics
            scan_stats = []
            for scan_info in all_results.values('scan_id').distinct():
                scan_id = scan_info['scan_id']
                scan_results = all_results.filter(scan_id=scan_id)
                
                scan_stats.append({
                    'scan_id': scan_id,
                    'total_apis': scan_results.count(),
                    'vulnerable_apis': scan_results.filter(is_vulnerable=True).count(),
                    'error_count': scan_results.exclude(error_message__isnull=True).exclude(error_message='').count(),
                    'last_scan_date': scan_results.order_by('-created_at').first().created_at if scan_results.exists() else None
                })
            
            # Sort by last scan date
            scan_stats.sort(key=lambda x: x['last_scan_date'] or '', reverse=True)
            
            return Response({
                'overall_statistics': {
                    'total_scans': unique_scans,
                    'total_apis_tested': total_apis_tested,
                    'vulnerable_apis_found': vulnerable_apis,
                    'apis_with_errors': apis_with_errors,
                    'vulnerability_rate': round(vulnerable_apis / total_apis_tested * 100, 2) if total_apis_tested > 0 else 0,
                    'success_rate': round((total_apis_tested - apis_with_errors) / total_apis_tested * 100, 2) if total_apis_tested > 0 else 0
                },
                'scan_wise_statistics': scan_stats
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                'error': f'An error occurred while fetching statistics: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RateLimitScanView(APIView):
    """Main view to initiate rate limiting scans"""
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Start a new rate limiting scan"""
        serializer = ScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        scan_data = serializer.validated_data
        
        try:
            # Initialize scanner
            scanner = RateLimitScanner(
                scan_id=scan_data['scan_id'],
                max_requests=scan_data.get('max_requests', 100),
                delay=scan_data.get('delay_between_requests', 0.1),
                timeout=scan_data.get('timeout', 30)
            )
            
            # Start scan in background thread
            def run_scan():
                try:
                    results = scanner.scan_all_apis()
                    logger.info(f"Completed scan for scan_id {scan_data['scan_id']}: {len(results)} APIs scanned")
                except Exception as e:
                    logger.error(f"Scan failed for scan_id {scan_data['scan_id']}: {str(e)}")
            
            Thread(target=run_scan, daemon=True).start()
            
            return Response({
                'message': f"Rate limiting scan initiated for scan_id {scan_data['scan_id']}",
                'scan_id': scan_data['scan_id']
            }, status=status.HTTP_202_ACCEPTED)
            
        except ValueError as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Failed to initiate scan: {str(e)}")
            return Response({
                'error': 'Failed to initiate scan'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ScanResultsViewTC2(APIView):
    """View to retrieve scan results with filtering"""
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get(self, request):
        """Get filtered scan results"""
        queryset = RateLimitScan.objects.all().order_by('-scan_started_at')
        
        # Apply filters
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        
        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        vulnerable_only = request.query_params.get('vulnerable_only')
        if vulnerable_only and vulnerable_only.lower() == 'true':
            queryset = queryset.filter(is_vulnerable=True)
        
        severity_filter = request.query_params.get('severity')
        if severity_filter:
            queryset = queryset.filter(severity=severity_filter)
        
        api_name = request.query_params.get('api_name')
        if api_name:
            queryset = queryset.filter(api_name__icontains=api_name)
        
        # Pagination
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = RateLimitScanSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = RateLimitScanSerializer(queryset, many=True)
        return Response(serializer.data)

class ScanStatsViewTC2(APIView):
    """View to get scan statistics"""
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get comprehensive scan statistics"""
        
        # Base queryset with optional scan_id filter
        queryset = RateLimitScan.objects.all()
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        
        # Basic stats
        total_scans = queryset.count()
        vulnerable_apis = queryset.filter(is_vulnerable=True).count()
        
        # Status distribution
        scans_by_status = dict(
            queryset.values('status').annotate(count=Count('id')).values_list('status', 'count')
        )
        
        # Severity distribution
        scans_by_severity = dict(
            queryset.filter(severity__isnull=False)
            .values('severity').annotate(count=Count('id'))
            .values_list('severity', 'count')
        )
        
        # Average response time
        completed_scans = queryset.filter(status='completed')
        avg_response_time = 0
        if completed_scans.exists():
            total_time = sum([
                sum(scan.response_times) / len(scan.response_times) if scan.response_times else 0
                for scan in completed_scans
            ])
            avg_response_time = total_time / completed_scans.count() if completed_scans.count() > 0 else 0
        
        # Top vulnerable APIs
        top_vulnerable_apis = list(
            queryset.filter(is_vulnerable=True)
            .values('api_name', 'severity', 'api_url')
            .annotate(scan_count=Count('id'))
            .order_by('-scan_count', 'severity')[:10]
        )
        
        stats_data = {
            'total_scans': total_scans,
            'vulnerable_apis': vulnerable_apis,
            'scans_by_status': scans_by_status,
            'scans_by_severity': scans_by_severity,
            'avg_response_time': avg_response_time,
            'top_vulnerable_apis': top_vulnerable_apis,
        }
        
        serializer = ScanStatsSerializer(data=stats_data)
        serializer.is_valid(raise_exception=True)
        
        return Response(serializer.validated_data)

class ScanLogsViewTC2(APIView):
    """View to retrieve detailed scan logs"""
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get(self, request):
        """Get filtered scan logs"""
        queryset = ScanLog.objects.all().select_related('scan')
        
        # Apply filters
        scan_record_id = request.query_params.get('scan_record_id')
        if scan_record_id:
            queryset = queryset.filter(scan_id=scan_record_id)
        
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(scan__scan_id=scan_id)
        
        level = request.query_params.get('level')
        if level:
            queryset = queryset.filter(level=level)
        
        # Pagination
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = ScanLogSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = ScanLogSerializer(queryset, many=True)
        return Response(serializer.data)

class ScanDetailViewTC2(APIView):
    """View to get detailed information about a specific scan"""
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, scan_record_id):
        """Get detailed scan information including logs"""
        try:
            scan = RateLimitScan.objects.get(id=scan_record_id)
            serializer = RateLimitScanSerializer(scan)
            return Response(serializer.data)
        except RateLimitScan.DoesNotExist:
            return Response({
                'error': 'Scan record not found'
            }, status=status.HTTP_404_NOT_FOUND)