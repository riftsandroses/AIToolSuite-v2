# views.py
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.pagination import PageNumberPagination
from rest_framework import permissions, status
from rest_framework.response import Response
from django.db import connection
from django.http import HttpResponse
from django.conf import settings
from django.db.models import Q, Count, Avg
from django.utils import timezone
from .models import UnboundedPaginationScan, RateLimitScan, ScanLog, FileUploadScanResult, FileUploadTest, ScanSession
from .serializers import UnboundedPaginationScanSerializer, UnboundedPaginationResultSerializer, RateLimitScanSerializer, ScanRequestSerializer, ScanStatsSerializer, ScanLogSerializer, FileUploadScanResultSerializer, ScanSessionSerializer, FileUploadTestSerializer, ScanStatsSerializerTC3
from .utils.analyzer_tester import ChatGPTAnalyzer, VulnerabilityTester
from .utils.rate_limit_scanner import RateLimitScanner
from .pagination import StandardResultsSetPagination
from .services import FileUploadVulnerabilityScanner
from api_4.management.commands.generate_report import Command as ReportCommand
import json
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import threading
from threading import Thread
import logging 
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db import transaction
from django.db.models import Q, Count
from django.core.paginator import Paginator
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


class StartFileUploadScanViewTC3(APIView):
    """Start a file upload vulnerability scan for a given scan_id"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        scan_id = request.data.get('scan_id')
        
        if not scan_id:
            logger.warning("Start scan request missing scan_id")
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Check if scan is already running
            existing_session = ScanSession.objects.filter(
                scan_id=scan_id,
                status__in=['pending', 'running']
            ).first()
            
            if existing_session:
                return Response(
                    {'message': 'Scan is already running', 'session_id': existing_session.id},
                    status=status.HTTP_409_CONFLICT
                )
            
            logger.info(f"Starting file upload vulnerability scan for scan_id: {scan_id} by user: {request.user.username}")
            
            # Create scanner instance
            scanner = FileUploadVulnerabilityScanner(scan_id, request.user)
            
            # Start scan in background thread
            def run_scan():
                try:
                    scanner.start_scan()
                    logger.info(f"File upload vulnerability scan completed for scan_id: {scan_id}")
                except Exception as e:
                    logger.error(f"File upload vulnerability scan failed for scan_id: {scan_id}: {str(e)}")
            
            scan_thread = threading.Thread(target=run_scan)
            scan_thread.daemon = True
            scan_thread.start()
            
            return Response(
                {
                    'message': 'File upload vulnerability scan started',
                    'scan_id': scan_id,
                    'status': 'started'
                },
                status=status.HTTP_202_ACCEPTED
            )
            
        except Exception as e:
            logger.error(f"Error starting scan: {str(e)}")
            return Response(
                {'error': f'Failed to start scan: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanResultsViewTC3(APIView):
    """Get scan results with filtering and pagination"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        vulnerability_status = request.query_params.get('status')
        vulnerability_type = request.query_params.get('type')
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        
        if not scan_id:
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Build query filters
            filters = Q(scan_id=scan_id)
            
            if vulnerability_status:
                filters &= Q(status=vulnerability_status)
            
            if vulnerability_type:
                filters &= Q(vulnerability_type=vulnerability_type)
            
            # Get filtered results
            results = FileUploadScanResult.objects.filter(filters).order_by('-created_at')
            
            # Paginate results
            paginator = Paginator(results, page_size)
            page_obj = paginator.get_page(page)
            
            serializer = FileUploadScanResultSerializer(page_obj.object_list, many=True)
            
            logger.info(f"Retrieved {len(page_obj.object_list)} scan results for scan_id: {scan_id}")
            
            return Response({
                'results': serializer.data,
                'pagination': {
                    'current_page': page,
                    'total_pages': paginator.num_pages,
                    'total_results': paginator.count,
                    'page_size': page_size,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous()
                }
            })
            
        except Exception as e:
            logger.error(f"Error retrieving scan results: {str(e)}")
            return Response(
                {'error': f'Failed to retrieve results: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VulnerableApisViewTC3(APIView):
    """Get only vulnerable APIs from scan results"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        
        if not scan_id:
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            vulnerable_results = FileUploadScanResult.objects.filter(
                scan_id=scan_id,
                status='vulnerable'
            ).order_by('-created_at')
            
            serializer = FileUploadScanResultSerializer(vulnerable_results, many=True)
            
            logger.info(f"Retrieved {len(vulnerable_results)} vulnerable APIs for scan_id: {scan_id}")
            
            return Response({
                'vulnerable_apis': serializer.data,
                'count': len(vulnerable_results)
            })
            
        except Exception as e:
            logger.error(f"Error retrieving vulnerable APIs: {str(e)}")
            return Response(
                {'error': f'Failed to retrieve vulnerable APIs: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanStatsViewTC3(APIView):
    """Get statistics for a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        
        if not scan_id:
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get scan session info
            scan_session = ScanSession.objects.filter(scan_id=scan_id).first()
            
            # Get result statistics
            results = FileUploadScanResult.objects.filter(scan_id=scan_id)
            
            stats = {
                'scan_info': {
                    'scan_id': scan_id,
                    'status': scan_session.status if scan_session else 'unknown',
                    'started_at': scan_session.started_at if scan_session else None,
                    'completed_at': scan_session.completed_at if scan_session else None,
                    'total_apis': scan_session.total_apis if scan_session else 0,
                    'completed_apis': scan_session.completed_apis if scan_session else 0,
                },
                'vulnerability_summary': {
                    'total_tested': results.count(),
                    'vulnerable': results.filter(status='vulnerable').count(),
                    'suspicious': results.filter(status='suspicious').count(),
                    'safe': results.filter(status='safe').count(),
                    'errors': results.filter(status='error').count(),
                },
                'vulnerability_types': {
                    'webshell_upload': results.filter(vulnerability_type='webshell').count(),
                    'large_file_upload': results.filter(vulnerability_type='large_file').count(),
                    'unrestricted_files': results.filter(vulnerability_type='unrestricted').count(),
                    'multiple_issues': results.filter(vulnerability_type='mixed').count(),
                },
                'upload_capabilities': {
                    'accepts_uploads': results.filter(accepts_file_upload=True).count(),
                    'webshell_successful': results.filter(webshell_upload_success=True).count(),
                    'large_file_successful': results.filter(large_file_upload_success=True).count(),
                    'unrestricted_successful': results.filter(unrestricted_file_types=True).count(),
                }
            }
            
            logger.info(f"Generated statistics for scan_id: {scan_id}")
            
            return Response(stats)
            
        except Exception as e:
            logger.error(f"Error generating scan statistics: {str(e)}")
            return Response(
                {'error': f'Failed to generate statistics: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FileUploadTestDetailsViewTC3(APIView):
    """Get detailed test results for a specific scan result"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, result_id):
        try:
            scan_result = FileUploadScanResult.objects.get(id=result_id)
            upload_tests = FileUploadTest.objects.filter(scan_result=scan_result)
            
            result_serializer = FileUploadScanResultSerializer(scan_result)
            tests_serializer = FileUploadTestSerializer(upload_tests, many=True)
            
            logger.info(f"Retrieved detailed test results for scan result: {result_id}")
            
            return Response({
                'scan_result': result_serializer.data,
                'upload_tests': tests_serializer.data
            })
            
        except FileUploadScanResult.DoesNotExist:
            return Response(
                {'error': 'Scan result not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error retrieving test details: {str(e)}")
            return Response(
                {'error': f'Failed to retrieve test details: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanSessionViewTC3(APIView):
    """Get scan session information"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        
        if not scan_id:
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            scan_session = ScanSession.objects.get(scan_id=scan_id)
            serializer = ScanSessionSerializer(scan_session)
            
            logger.info(f"Retrieved scan session info for scan_id: {scan_id}")
            
            return Response(serializer.data)
            
        except ScanSession.DoesNotExist:
            return Response(
                {'error': 'Scan session not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error retrieving scan session: {str(e)}")
            return Response(
                {'error': f'Failed to retrieve scan session: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DeleteScanResultsViewTC3(APIView):
    """Delete scan results for a specific scan_id"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def delete(self, request):
        scan_id = request.data.get('scan_id')
        
        if not scan_id:
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            with transaction.atomic():
                # Delete all related data
                deleted_tests = FileUploadTest.objects.filter(scan_result__scan_id=scan_id).count()
                deleted_results = FileUploadScanResult.objects.filter(scan_id=scan_id).count()
                deleted_session = ScanSession.objects.filter(scan_id=scan_id).count()
                
                FileUploadTest.objects.filter(scan_result__scan_id=scan_id).delete()
                FileUploadScanResult.objects.filter(scan_id=scan_id).delete()
                ScanSession.objects.filter(scan_id=scan_id).delete()
                
                logger.info(f"Deleted scan data for scan_id: {scan_id} - Results: {deleted_results}, Tests: {deleted_tests}, Session: {deleted_session}")
                
                return Response({
                    'message': f'Successfully deleted scan data for scan_id: {scan_id}',
                    'deleted_counts': {
                        'results': deleted_results,
                        'tests': deleted_tests,
                        'session': deleted_session
                    }
                })
                
        except Exception as e:
            logger.error(f"Error deleting scan results: {str(e)}")
            return Response(
                {'error': f'Failed to delete scan results: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ExportScanResultsViewTC3(APIView):
    """Export scan results to JSON, HTML, or TXT format"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        export_format = request.query_params.get('format', 'json').lower()
        include_safe = request.query_params.get('include_safe', 'false').lower() == 'true'

        if not scan_id:
            return Response({'error': 'scan_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            scan_session = ScanSession.objects.filter(scan_id=scan_id).first()
            results = FileUploadScanResult.objects.filter(scan_id=scan_id).prefetch_related('upload_tests')

            if not include_safe:
                results = results.exclude(status='safe')

            if not results.exists():
                return Response({'error': 'No results found for given scan_id'}, status=status.HTTP_404_NOT_FOUND)

            report_cmd = ReportCommand()

            # Safely handle missing scan_session
            report_data = report_cmd._generate_report_data(scan_session, results) if scan_session else {
                'scan_info': {'scan_id': scan_id, 'status': 'unknown'},
                'summary': {},
                'vulnerability_breakdown': {},
                'vulnerable_apis': [],
                'recommendations': []
            }

            if export_format == 'html':
                output = report_cmd._format_html_report(report_data)
                return HttpResponse(output, content_type='text/html', headers={
                    'Content-Disposition': f'attachment; filename="file_upload_scan_{scan_id}.html"'
                })

            elif export_format == 'txt':
                output = report_cmd._format_text_report(report_data)
                return HttpResponse(output, content_type='text/plain', headers={
                    'Content-Disposition': f'attachment; filename="file_upload_scan_{scan_id}.txt"'
                })

            else:
                output = report_cmd._format_json_report(report_data)
                return HttpResponse(output, content_type='application/json', headers={
                    'Content-Disposition': f'attachment; filename="file_upload_scan_{scan_id}.json"'
                })

        except Exception as e:
            logger.error(f"Error exporting scan results: {str(e)}")
            return Response({'error': f'Failed to export scan results: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RetestVulnerableApisViewTC3(APIView):
    """Retest only the vulnerable APIs from a previous scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        original_scan_id = request.data.get('scan_id')
        new_scan_id = request.data.get('new_scan_id', original_scan_id)
        
        if not original_scan_id:
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get vulnerable APIs from original scan
            vulnerable_results = FileUploadScanResult.objects.filter(
                scan_id=original_scan_id,
                status='vulnerable'
            )
            
            if not vulnerable_results.exists():
                return Response(
                    {'message': 'No vulnerable APIs found in the original scan'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Create new scan session for retest
            retest_session = ScanSession.objects.create(
                scan_id=new_scan_id,
                user=request.user,
                status='running',
                total_apis=vulnerable_results.count()
            )
            
            logger.info(f"Starting retest of {vulnerable_results.count()} vulnerable APIs from scan_id: {original_scan_id}")
            
            # Start retest in background
            def run_retest():
                try:
                    scanner = FileUploadVulnerabilityScanner(new_scan_id, request.user)
                    jwt_token = scanner.get_jwt_token()
                    
                    retested_count = 0
                    for result in vulnerable_results:
                        # Reconstruct API data for retesting
                        api_data = {
                            'id': result.api_id,
                            'name': result.api_name,
                            'method': result.api_method,
                            'url': result.api_url,
                            'headers': '{}',  # Will need to be fetched from original source
                            'body': '{}',
                            'authorization': '{}',
                            'query_params': '{}'
                        }
                        
                        scanner.scan_api_for_file_upload(api_data, jwt_token)
                        retested_count += 1
                        
                        retest_session.completed_apis = retested_count
                        retest_session.save()
                    
                    retest_session.status = 'completed'
                    retest_session.completed_at = timezone.now()
                    retest_session.save()
                    
                    logger.info(f"Retest completed for scan_id: {new_scan_id}")
                    
                except Exception as e:
                    logger.error(f"Retest failed: {str(e)}")
                    retest_session.status = 'failed'
                    retest_session.save()
            
            retest_thread = threading.Thread(target=run_retest)
            retest_thread.daemon = True
            retest_thread.start()
            
            return Response({
                'message': 'Retest started for vulnerable APIs',
                'original_scan_id': original_scan_id,
                'new_scan_id': new_scan_id,
                'vulnerable_apis_count': vulnerable_results.count(),
                'status': 'started'
            }, status=status.HTTP_202_ACCEPTED)
            
        except Exception as e:
            logger.error(f"Error starting retest: {str(e)}")
            return Response(
                {'error': f'Failed to start retest: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )