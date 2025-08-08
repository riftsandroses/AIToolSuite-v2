# api_9/views.py
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q
from django.db import connection, transaction
from django.core.management import call_command
from django.apps import apps
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response
from .models import UnlistedEndpoints, SubdomainDiscovery, DocumentationEndpoint, VulnerableMethodScan, APIVersionCheck, EndpointCheckResult
from .serializers import EndpointDiscoverySerializer, UnlistedEndpointsSerializer, ScanRequestSerializer, SubdomainDiscoverySerializer, DocumentationScanSerializer, DocumentationEndpointSerializer, ScanRequestSerializer, VulnerableMethodScanSerializer, VersionCheckRequestSerializer, VersionCheckResponseSerializer, EndpointCheckSerializer, EndpointCheckResultSerializer
from .services import SubdomainDiscoveryService, run_documentation_scan, APIVersionEnumerator, TC6EndpointDiscoveryService
from .utils.prompts import TC1EndpointDiscoveryService
from .tasks import async_subdomain_discovery, scan_documentation_task
from AIToolSuite_prod.celery import app
from celery.result import AsyncResult
import asyncio
import logging


logger = logging.getLogger(__name__)

class DiscoverEndpointsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = EndpointDiscoverySerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid scan_id provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan_id = serializer.validated_data['scan_id']
    
        try:
            # Get URLs from api_orch_postmanapi table
            urls = self.get_urls_from_postmanapi(scan_id)
            if not urls:
                return Response(
                    {'error': f'No URLs found for scan_id: {scan_id}'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get JWT token from api_orch_scantokens table
            jwt_token = self.get_jwt_token(scan_id)
            if not jwt_token:
                return Response(
                    {'error': f'No JWT token found for scan_id: {scan_id}'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Initialize discovery service
            discovery_service = TC1EndpointDiscoveryService()
            
            all_discovered_endpoints = []
            existing_urls = set(urls)  # Convert to set for faster lookup
            
            # Process each URL
            for url in urls:
                try:
                    logger.info(f"Processing URL: {url}")
                    
                    # Get truncated URL from ChatGPT
                    truncated_url = discovery_service.get_truncated_url_from_chatgpt(url)
                    logger.info(f"Truncated URL: {truncated_url}")
                    
                    # Run feroxbuster to discover endpoints
                    discovered_endpoints = discovery_service.run_feroxbuster(truncated_url, jwt_token)
                    logger.info(f"Discovered {len(discovered_endpoints)} endpoints")
                    
                    # Filter out endpoints that already exist in the database
                    new_endpoints = []
                    for endpoint in discovered_endpoints:
                        endpoint_url = endpoint['url']
                        if endpoint_url not in existing_urls:
                            new_endpoints.append(endpoint)
                            existing_urls.add(endpoint_url)  # Add to set to avoid duplicates
                    
                    all_discovered_endpoints.extend(new_endpoints)
                    
                except Exception as e:
                    logger.error(f"Error processing URL {url}: {e}")
                    continue
            
            # Save new endpoints to database
            saved_endpoints = []
            for endpoint in all_discovered_endpoints:
                try:
                    unlisted_endpoint, created = UnlistedEndpoints.objects.get_or_create(
                        scan_id=scan_id,
                        endpoint_url=endpoint['url'],
                        defaults={
                            'method': endpoint.get('method', 'GET'),
                            'status_code': endpoint.get('status_code')
                        }
                    )
                    
                    if created:
                        saved_endpoints.append(unlisted_endpoint)
                        
                except Exception as e:
                    logger.error(f"Error saving endpoint {endpoint['url']}: {e}")
                    continue
            
            # Serialize response
            response_serializer = UnlistedEndpointsSerializer(saved_endpoints, many=True)
            
            return Response({
                'message': f'Discovery completed. Found {len(saved_endpoints)} new endpoints.',
                'scan_id': scan_id,
                'new_endpoints_count': len(saved_endpoints),
                'new_endpoints': response_serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Unexpected error in discover_endpoints: {e}")
            return Response(
                {'error': 'Internal server error occurred during endpoint discovery'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_urls_from_postmanapi(self, scan_id):
        """
        Get all URLs from api_orch_postmanapi table for given scan_id
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT DISTINCT url FROM api_orch_postmanapi WHERE scan_id = %s",
                    [scan_id]
                )
                rows = cursor.fetchall()
                return [row[0] for row in rows if row[0]]
        except Exception as e:
            logger.error(f"Error fetching URLs from postmanapi: {e}")
            return []

    def get_jwt_token(self, scan_id):
        """
        Get JWT token from api_orch_scantokens table for given scan_id
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT access_token FROM api_orch_scantokens WHERE scan_id = %s LIMIT 1",
                    [scan_id]
                )
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"Error fetching JWT token: {e}")
            return None

@method_decorator(csrf_exempt, name='dispatch')
class SubdomainDiscoveryAPIView(APIView):
    """
    API endpoint to discover subdomains for a given scan_id
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ScanRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Start async task
            task = async_subdomain_discovery.delay(scan_id)
            
            return Response({
                'message': 'Subdomain discovery started',
                'task_id': task.id,
                'scan_id': scan_id,
                'status': 'processing'
            }, status=status.HTTP_202_ACCEPTED)
            
        except Exception as e:
            return Response(
                {'error': f'Internal server error: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get(self, request):
        """Get discovered subdomains for a scan_id"""
        scan_id = request.query_params.get('scan_id')
        
        if not scan_id:
            return Response(
                {'error': 'scan_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        subdomains = SubdomainDiscovery.objects.filter(scan_id=scan_id)
        serializer = SubdomainDiscoverySerializer(subdomains, many=True)
        
        return Response({
            'scan_id': scan_id,
            'count': subdomains.count(),
            'subdomains': serializer.data
        })

class TaskStatusView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, task_id):
        try:
            # Force AsyncResult to use Django DB backend
            task_result = AsyncResult(task_id, app=app)
            
            if not task_result.backend:
                return Response(
                    {"error": "Task result backend is not configured"},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            response_data = {
                "task_id": task_id,
                "status": task_result.state,
            }

            if task_result.state == "PROGRESS":
                response_data.update({
                    "current": task_result.info.get("current", 0),
                    "total": task_result.info.get("total", 1),
                    "message": task_result.info.get("message", ""),
                })
            elif task_result.state == "SUCCESS":
                response_data["result"] = task_result.result
            elif task_result.state == "FAILURE":
                response_data["error"] = str(task_result.info)

            return Response(response_data)

        except Exception as e:
            return Response(
                {"error": f"Error checking task status: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class StartDocumentationScanView(APIView):
    """
    Start a documentation scan for the given scan_id
    POST /api/v1/scan-documentation/
    {
        "scan_id": "your_scan_id_here"
    }
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = DocumentationScanSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Option 1: Run synchronously (for immediate results)
            # Uncomment the next 3 lines if you want synchronous execution
            # loop = asyncio.new_event_loop()
            # asyncio.set_event_loop(loop)
            # result = loop.run_until_complete(run_documentation_scan(scan_id))
            
            # Option 2: Run asynchronously with Celery (recommended for production)
            task = scan_documentation_task.delay(scan_id)
            result = {
                "status": "started",
                "message": "Documentation scan started in background",
                "task_id": task.id,
                "scan_id": scan_id
            }
            
            return Response(result, status=status.HTTP_202_ACCEPTED)
            
        except Exception as e:
            logger.error(f"Failed to start documentation scan: {str(e)}")
            return Response(
                {"status": "error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class GetScanResultsView(APIView):
    """
    Get documentation scan results for a specific scan_id
    GET /api/v1/scan-results/{scan_id}/
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        endpoints = DocumentationEndpoint.objects.filter(scan_id=scan_id)
        
        # Add filtering options
        doc_type = request.GET.get('doc_type')
        status_filter = request.GET.get('status')
        
        if doc_type:
            endpoints = endpoints.filter(doc_type=doc_type)
        
        if status_filter:
            endpoints = endpoints.filter(status=status_filter)
        
        serializer = DocumentationEndpointSerializer(endpoints, many=True)
        
        return Response({
            "scan_id": scan_id,
            "total_results": endpoints.count(),
            "results": serializer.data
        })


class GetScanSummaryView(APIView):
    """
    Get summary statistics for a documentation scan
    GET /api/v1/scan-summary/{scan_id}/
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        endpoints = DocumentationEndpoint.objects.filter(scan_id=scan_id)
        
        if not endpoints.exists():
            return Response(
                {"error": "No scan results found for this scan_id"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get statistics
        stats = endpoints.aggregate(
            total_endpoints=Count('id'),
            success_count=Count('id', filter=Q(status='success')),
            forbidden_count=Count('id', filter=Q(status='forbidden')),
            unauthorized_count=Count('id', filter=Q(status='unauthorized')),
        )
        
        # Get breakdown by doc type
        doc_type_breakdown = list(
            endpoints.values('doc_type')
            .annotate(count=Count('id'))
            .order_by('-count')
        )
        
        # Get breakdown by status
        status_breakdown = list(
            endpoints.values('status', 'status_code')
            .annotate(count=Count('id'))
            .order_by('-count')
        )
        
        return Response({
            "scan_id": scan_id,
            "summary": stats,
            "doc_type_breakdown": doc_type_breakdown,
            "status_breakdown": status_breakdown,
            "latest_scan": endpoints.first().scan_timestamp if endpoints.exists() else None
        })


class VulnerableMethodsScanView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Initiate a scan for vulnerable HTTP methods based on scan_id
        """
        serializer = ScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid request data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Call the management command to perform the scan
            call_command('scan_vulnerable_methods', scan_id=scan_id)
            
            # Get the scan results
            scan_results = VulnerableMethodScan.objects.filter(scan_id=scan_id)
            results_serializer = VulnerableMethodScanSerializer(scan_results, many=True)
            
            return Response({
                'message': 'Scan completed successfully',
                'scan_id': scan_id,
                'total_vulnerabilities_found': scan_results.count(),
                'results': results_serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error during scan for scan_id {scan_id}: {str(e)}")
            return Response(
                {'error': 'Scan failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanResultsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        """
        Get scan results for a specific scan_id
        """
        try:
            scan_results = VulnerableMethodScan.objects.filter(scan_id=scan_id)
            if not scan_results.exists():
                return Response(
                    {'error': f'No scan results found for scan_id: {scan_id}'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            serializer = VulnerableMethodScanSerializer(scan_results, many=True)
            return Response({
                'scan_id': scan_id,
                'total_vulnerabilities': scan_results.count(),
                'results': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error retrieving scan results for {scan_id}: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve scan results', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class APIVersionEnumerationView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = VersionCheckRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        scan_id = serializer.validated_data['scan_id']
        use_openai = serializer.validated_data.get('use_openai', False)
        
        try:
            # Get the api_orch_postmanapi model dynamically
            PostmanAPI = apps.get_model('api_orch', 'postmanapi')
            
            # Fetch APIs for the given scan_id
            apis = PostmanAPI.objects.filter(scan_id=scan_id)
            
            if not apis.exists():
                return Response(
                    {'error': f'No APIs found for scan_id: {scan_id}'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Extract API URLs (adjust field name based on your model)
            api_urls = []
            for api in apis:
                # Assuming the model has a 'url' field - adjust as needed
                if hasattr(api, 'url') and api.url:
                    api_urls.append(api.url)
                elif hasattr(api, 'endpoint') and api.endpoint:
                    api_urls.append(api.endpoint)
                elif hasattr(api, 'api_url') and api.api_url:
                    api_urls.append(api.api_url)
            
            if not api_urls:
                return Response(
                    {'error': 'No valid API URLs found in the database'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Initialize version enumerator
            enumerator = APIVersionEnumerator(use_openai=use_openai)
            
            # Run async version enumeration
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                version_results = loop.run_until_complete(
                    enumerator.enumerate_versions_async(api_urls)
                )
            finally:
                loop.close()
            
            # Save results to database
            saved_results = []
            for result in version_results:
                version_check, created = APIVersionCheck.objects.update_or_create(
                    scan_id=scan_id,
                    original_api_url=result['original_api_url'],
                    version=result['version'],
                    defaults={
                        'is_accessible': result['is_accessible'],
                        'response_status_code': result['response_status_code'],
                        'response_time': result['response_time'],
                        'error_message': result['error_message']
                    }
                )
                saved_results.append(version_check)
            
            # Prepare response
            accessible_count = sum(1 for r in saved_results if r.is_accessible)
            response_data = {
                'scan_id': scan_id,
                'total_apis_checked': len(api_urls),
                'total_versions_found': len(saved_results),
                'accessible_versions': accessible_count,
                'results': saved_results
            }
            
            response_serializer = VersionCheckResponseSerializer(response_data)
            return Response(response_serializer.data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'An error occurred: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class APIVersionResultsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        """Get previous version enumeration results for a scan_id"""
        results = APIVersionCheck.objects.filter(scan_id=scan_id).order_by('-checked_at')
        
        if not results.exists():
            return Response(
                {'error': f'No version check results found for scan_id: {scan_id}'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        accessible_count = results.filter(is_accessible=True).count()
        unique_apis = results.values('original_api_url').distinct().count()
        
        response_data = {
            'scan_id': scan_id,
            'total_apis_checked': unique_apis,
            'total_versions_found': results.count(),
            'accessible_versions': accessible_count,
            'results': results
        }
        
        serializer = VersionCheckResponseSerializer(response_data)
        return Response(serializer.data, status=status.HTTP_200_OK)

class EndpointDiscoveryView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = EndpointCheckSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Initialize the discovery service
            discovery_service = TC6EndpointDiscoveryService()
            
            # Clear previous results for this scan_id
            EndpointCheckResult.objects.filter(scan_id=scan_id).delete()
            
            # Discover and check endpoints
            results = discovery_service.discover_and_check_endpoints(scan_id)
            
            if not results:
                return Response({
                    'message': f'No APIs found for scan_id: {scan_id}',
                    'scan_id': scan_id,
                    'total_checks': 0,
                    'accessible_endpoints': 0
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Save results to database
            with transaction.atomic():
                endpoint_objects = []
                for result in results:
                    endpoint_objects.append(EndpointCheckResult(**result))
                EndpointCheckResult.objects.bulk_create(endpoint_objects)
            
            # Prepare summary
            total_checks = len(results)
            accessible_count = sum(1 for r in results if r['is_accessible'])
            
            # Group results by endpoint type
            summary_by_type = {}
            for result in results:
                endpoint_type = result['endpoint_type']
                if endpoint_type not in summary_by_type:
                    summary_by_type[endpoint_type] = {
                        'total': 0,
                        'accessible': 0,
                        'endpoints': []
                    }
                summary_by_type[endpoint_type]['total'] += 1
                if result['is_accessible']:
                    summary_by_type[endpoint_type]['accessible'] += 1
                    summary_by_type[endpoint_type]['endpoints'].append({
                        'api_name': result['api_name'],
                        'endpoint_url': result['endpoint_url'],
                        'status_code': result['status_code'],
                        'response_time': result['response_time']
                    })
            
            return Response({
                'message': 'Endpoint discovery completed successfully',
                'scan_id': scan_id,
                'total_checks': total_checks,
                'accessible_endpoints': accessible_count,
                'summary_by_type': summary_by_type,
                'detailed_results': EndpointCheckResultSerializer(
                    EndpointCheckResult.objects.filter(scan_id=scan_id), 
                    many=True
                ).data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error in endpoint discovery for scan_id {scan_id}: {e}")
            return Response({
                'error': 'Internal server error during endpoint discovery',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class EndpointResultsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        """Get previously stored results for a scan_id"""
        results = EndpointCheckResult.objects.filter(scan_id=scan_id)
        
        if not results.exists():
            return Response({
                'message': f'No results found for scan_id: {scan_id}'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = EndpointCheckResultSerializer(results, many=True)
        
        # Generate summary
        total_checks = results.count()
        accessible_count = results.filter(is_accessible=True).count()
        
        return Response({
            'scan_id': scan_id,
            'total_checks': total_checks,
            'accessible_endpoints': accessible_count,
            'results': serializer.data
        }, status=status.HTTP_200_OK)