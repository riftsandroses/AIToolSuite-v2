from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics, filters
from rest_framework.pagination import PageNumberPagination
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Q, Count
from django.core.paginator import Paginator
from datetime import timedelta
from .models import ScanResultTC1, ScanSessionTC1, VulnerabilitySummaryTC1, ScanResultTC2, ScanSummaryTC2, TestCredentialTC2, ScanResultTC3, ScanSessionTC3, VulnerabilityTemplateTC3, JWTScanTC4, JWTVulnerabilityTC4, JWTScanLogTC4, JWTScanConfigTC4, JWTTokenAnalysisTC4
from .serializers import (
    ScanInitiateSerializerTC1, ScanResultSerializerTC1, ScanSessionSerializerTC1,
    VulnerabilitySummarySerializerTC1, ScanStatsSerializerTC1, ScanHistorySerializerTC1,
    ScanFilterSerializerTC1, ScanInitiateTC2Serializer, ScanResultTC2Serializer, ScanResultFilterTC2Serializer,
    ScanSummaryTC2Serializer, ScanStatusTC2Serializer, ScanStatsTC2Serializer,
    ScanHistoryTC2Serializer, VulnerabilitySummaryTC2Serializer, TestCredentialTC2Serializer,
    ScanInitiateSerializerTC3, ScanResultSerializerTC3, ScanResultListSerializerTC3,
    ScanResultFilterSerializerTC3, ScanSessionSerializerTC3, ScanStatsSerializerTC3,
    VulnerabilitySummarySerializerTC3, ScanHistorySerializerTC3, VulnerabilityTemplateSerializerTC3,
    JWTScanCreateSerializerTC4, JWTScanSerializerTC4, JWTScanDetailSerializerTC4,
    JWTVulnerabilitySerializerTC4, JWTVulnerabilitySummarySerializerTC4, JWTScanStatsSerializerTC4, 
    JWTVulnerabilityFilterSerializerTC4, JWTScanLogSerializerTC4, JWTTokenAnalysisSerializerTC4
)
from .services import APISecurityScannerTC1, APIOrchDataServiceTC1, CredentialStuffingServiceTC2, ScanAnalyticsServiceTC2, VulnerabilityScannerServiceTC3, ScanStatsServiceTC3, JWTScanServiceTC4
from .tasks import run_security_scan_async
import threading
import logging

logger = logging.getLogger(__name__)

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

class ScanInitiateViewTC1(APIView):
    """Initiate a security scan for APIs"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ScanInitiateSerializerTC1(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid input", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        scan_id = serializer.validated_data['scan_id']
        scan_config = serializer.validated_data.get('scan_config', {})

        try:
            # Create scan session immediately
            apis = APIOrchDataServiceTC1.get_apis_by_scan_id(scan_id)
            
            if not apis:
                return Response(
                    {"error": "No APIs found for the given scan_id"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            session, created = ScanSessionTC1.objects.update_or_create(
                scan_id=scan_id,
                defaults={
                    'total_apis': len(apis),
                    'completed_apis': 0,
                    'failed_apis': 0,
                    'vulnerabilities_found': 0,
                    'status': 'pending',
                    'created_by': request.user,
                    'scan_config': scan_config
                }
            )

            # Start async task
            task = run_security_scan_async.delay(scan_id, request.user.id, scan_config)
            
            return Response({
                'message': 'Scan initiated successfully',
                'scan_id': scan_id,
                'session_id': session.id,
                'task_id': task.id,
                'total_apis': len(apis),
                'status': 'pending'
            }, status=status.HTTP_202_ACCEPTED)

        except Exception as e:
            logger.error(f"Error in scan initiation: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
class ScanResultsViewTC1(APIView):
    """Get scan results with filtering capabilities"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get(self, request):
        # Validate filter parameters
        filter_serializer = ScanFilterSerializerTC1(data=request.query_params)
        if not filter_serializer.is_valid():
            return Response(
                {"error": "Invalid filter parameters", "details": filter_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            scanner = APISecurityScannerTC1(user=request.user)
            results = scanner.get_scan_results(filter_serializer.validated_data)

            # Apply pagination
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(results, request)
            
            if page is not None:
                serializer = ScanResultSerializerTC1(page, many=True)
                return paginator.get_paginated_response(serializer.data)

            serializer = ScanResultSerializerTC1(results, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting scan results: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanStatusViewTC1(APIView):
    """Get status of a specific scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            session = ScanSessionTC1.objects.get(scan_id=scan_id)
            serializer = ScanSessionSerializerTC1(session)
            
            # Add real-time progress data
            response_data = serializer.data
            response_data['real_time_progress'] = {
                'current_time': timezone.now().isoformat(),
                'estimated_completion': self._estimate_completion(session)
            }
            
            return Response(response_data, status=status.HTTP_200_OK)

        except ScanSessionTC1.DoesNotExist:
            return Response(
                {"error": f"Scan session not found for scan_id: {scan_id}"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error getting scan status: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _estimate_completion(self, session):
        if session.status in ['completed', 'failed', 'cancelled']:
            return None
        
        if session.completed_apis == 0:
            return "Calculating..."
        
        elapsed = timezone.now() - session.started_at
        rate = session.completed_apis / elapsed.total_seconds()
        remaining_apis = session.total_apis - session.completed_apis
        
        if rate > 0:
            estimated_seconds = remaining_apis / rate
            estimated_completion = timezone.now() + timezone.timedelta(seconds=estimated_seconds)
            return estimated_completion.isoformat()
        
        return "Unable to estimate"

class ScanStatsViewTC1(APIView):
    """Get overall scan statistics"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            scanner = APISecurityScannerTC1(user=request.user)
            stats = scanner.get_scan_stats()
            
            serializer = ScanStatsSerializerTC1(data=stats)
            serializer.is_valid(raise_exception=True)
            
            return Response(serializer.validated_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting scan stats: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanHistoryViewTC1(APIView):
    """Get scan history with summary"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get(self, request):
        try:
            # Get query parameters
            days = int(request.query_params.get('days', 30))
            status_filter = request.query_params.get('status')
            
            # Build queryset
            queryset = ScanSessionTC1.objects.all()
            
            # Filter by date range
            if days:
                start_date = timezone.now() - timezone.timedelta(days=days)
                queryset = queryset.filter(started_at__gte=start_date)
            
            # Filter by status
            if status_filter:
                queryset = queryset.filter(status=status_filter)
            
            queryset = queryset.order_by('-started_at')
            
            # Apply pagination
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            
            if page is not None:
                serializer = ScanHistorySerializerTC1(page, many=True)
                return paginator.get_paginated_response(serializer.data)

            serializer = ScanHistorySerializerTC1(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting scan history: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class VulnerabilitySummaryViewTC1(APIView):
    """Get vulnerability summary for a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id=None):
        try:
            if scan_id:
                # Get summary for specific scan
                summaries = VulnerabilitySummaryTC1.objects.filter(scan_id=scan_id)
                if not summaries.exists():
                    return Response(
                        {"error": f"No vulnerability summary found for scan_id: {scan_id}"},
                        status=status.HTTP_404_NOT_FOUND
                    )
            else:
                # Get summary for all scans (last 30 days)
                start_date = timezone.now() - timezone.timedelta(days=30)
                summaries = VulnerabilitySummaryTC1.objects.filter(created_at__gte=start_date)
            
            serializer = VulnerabilitySummarySerializerTC1(summaries, many=True)
            
            # Group data for better presentation
            grouped_data = {}
            for item in serializer.data:
                scan_id = item['scan_id']
                if scan_id not in grouped_data:
                    grouped_data[scan_id] = {
                        'scan_id': scan_id,
                        'vulnerabilities': [],
                        'total_count': 0
                    }
                grouped_data[scan_id]['vulnerabilities'].append({
                    'type': item['vulnerability_type'],
                    'severity': item['severity'],
                    'count': item['count']
                })
                grouped_data[scan_id]['total_count'] += item['count']
            
            return Response({
                'scan_summaries': list(grouped_data.values()),
                'raw_data': serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting vulnerability summary: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanResultDetailViewTC1(APIView):
    """Get detailed scan result by ID"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, result_id):
        try:
            result = ScanResultTC1.objects.get(id=result_id)
            serializer = ScanResultSerializerTC1(result)
            
            # Add additional context
            response_data = serializer.data
            response_data['related_results'] = self._get_related_results(result)
            
            return Response(response_data, status=status.HTTP_200_OK)

        except ScanResultTC1.DoesNotExist:
            return Response(
                {"error": f"Scan result not found with ID: {result_id}"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error getting scan result detail: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_related_results(self, result):
        """Get related scan results for the same API"""
        related = ScanResultTC1.objects.filter(
            api_id=result.api_id
        ).exclude(id=result.id).order_by('-scan_started_at')[:5]
        
        return ScanResultSerializerTC1(related, many=True).data

class ScanCancelViewTC1(APIView):
    """Cancel an ongoing scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, scan_id):
        try:
            session = ScanSessionTC1.objects.get(scan_id=scan_id)
            
            if session.status not in ['pending', 'scanning']:
                return Response(
                    {"error": f"Cannot cancel scan with status: {session.status}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            session.status = 'cancelled'
            session.completed_at = timezone.now()
            session.save()
            
            return Response(
                {"message": f"Scan {scan_id} cancelled successfully"},
                status=status.HTTP_200_OK
            )

        except ScanSessionTC1.DoesNotExist:
            return Response(
                {"error": f"Scan session not found for scan_id: {scan_id}"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error cancelling scan: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class DashboardViewTC1(APIView):
    """Get dashboard data with overview"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            scanner = APISecurityScannerTC1(user=request.user)
            
            # Get basic stats
            stats = scanner.get_scan_stats()
            
            # Get recent scans
            recent_scans = ScanSessionTC1.objects.order_by('-started_at')[:5]
            recent_scans_data = ScanSessionSerializerTC1(recent_scans, many=True).data
            
            # Get recent vulnerabilities
            recent_vulnerabilities = ScanResultTC1.objects.filter(
                status='completed'
            ).order_by('-scan_completed_at')[:10]
            recent_vuln_data = ScanResultSerializerTC1(recent_vulnerabilities, many=True).data
            
            # Get vulnerability trends (last 7 days)            
            last_week = timezone.now() - timedelta(days=7)
            trends = ScanResultTC1.objects.filter(
                scan_started_at__gte=last_week
            ).values('severity').annotate(count=Count('id'))
            
            return Response({
                'stats': stats,
                'recent_scans': recent_scans_data,
                'recent_vulnerabilities': recent_vuln_data,
                'vulnerability_trends': list(trends),
                'generated_at': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting dashboard data: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class TaskStatusViewTC1(APIView):
    """Get Celery task status"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, task_id):
        from celery.result import AsyncResult
        
        try:
            task = AsyncResult(task_id)
            
            response_data = {
                'task_id': task_id,
                'status': task.status,
                'ready': task.ready(),
            }
            
            if task.ready():
                if task.successful():
                    response_data['result'] = task.result
                else:
                    response_data['error'] = str(task.info)
            
            return Response(response_data)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to get task status: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanInitiateTC2View(APIView):
    """Initiate credential stuffing vulnerability scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ScanInitiateTC2Serializer(data=request.data)
        if serializer.is_valid():
            scan_id = serializer.validated_data['scan_id']
            
            try:
                service = CredentialStuffingServiceTC2()
                result = service.initiate_scan(scan_id, request.user)
                
                if 'error' in result:
                    return Response(result, status=status.HTTP_400_BAD_REQUEST)
                
                return Response(result, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"Error initiating scan: {str(e)}")
                return Response(
                    {'error': 'Failed to initiate scan', 'detail': str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanResultsTC2View(APIView):
    """Get scan results with filtering"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Apply filters
        queryset = ScanResultTC2.objects.all().order_by('-created_at')
        
        # Filter by query parameters
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        
        scan_status = request.query_params.get('scan_status')
        if scan_status:
            queryset = queryset.filter(scan_status=scan_status)
        
        vulnerability_found = request.query_params.get('vulnerability_found')
        if vulnerability_found is not None:
            queryset = queryset.filter(vulnerability_found=vulnerability_found.lower() == 'true')
        
        severity = request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        api_method = request.query_params.get('api_method')
        if api_method:
            queryset = queryset.filter(api_method__icontains=api_method)
        
        exploit_successful = request.query_params.get('exploit_successful')
        if exploit_successful is not None:
            queryset = queryset.filter(exploit_successful=exploit_successful.lower() == 'true')
        
        date_from = request.query_params.get('date_from')
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        
        date_to = request.query_params.get('date_to')
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        start = (page - 1) * page_size
        end = start + page_size
        
        total_count = queryset.count()
        results = queryset[start:end]
        
        serializer = ScanResultTC2Serializer(results, many=True)
        
        return Response({
            'count': total_count,
            'page': page,
            'page_size': page_size,
            'total_pages': (total_count + page_size - 1) // page_size,
            'results': serializer.data
        })
    
    def post(self, request):
        """Filter results using POST body"""
        filter_serializer = ScanResultFilterTC2Serializer(data=request.data)
        if not filter_serializer.is_valid():
            return Response(filter_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        filters = filter_serializer.validated_data
        queryset = ScanResultTC2.objects.all()
        
        # Apply filters
        if 'scan_id' in filters:
            queryset = queryset.filter(scan_id=filters['scan_id'])
        if 'scan_status' in filters:
            queryset = queryset.filter(scan_status=filters['scan_status'])
        if 'vulnerability_found' in filters:
            queryset = queryset.filter(vulnerability_found=filters['vulnerability_found'])
        if 'severity' in filters:
            queryset = queryset.filter(severity=filters['severity'])
        if 'api_method' in filters:
            queryset = queryset.filter(api_method__icontains=filters['api_method'])
        if 'exploit_successful' in filters:
            queryset = queryset.filter(exploit_successful=filters['exploit_successful'])
        if 'date_from' in filters:
            queryset = queryset.filter(created_at__gte=filters['date_from'])
        if 'date_to' in filters:
            queryset = queryset.filter(created_at__lte=filters['date_to'])
        
        queryset = queryset.order_by('-created_at')
        serializer = ScanResultTC2Serializer(queryset, many=True)
        
        return Response({
            'count': queryset.count(),
            'results': serializer.data
        })


class ScanStatusTC2View(APIView):
    """Get current status of a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            summary = ScanSummaryTC2.objects.get(scan_id=scan_id)
            
            # Calculate progress
            progress_percentage = 0
            if summary.total_apis > 0:
                progress_percentage = (summary.completed_apis / summary.total_apis) * 100
            
            # Estimate remaining time
            estimated_time = None
            if summary.scan_status == 'running' and summary.completed_apis > 0:
                elapsed_time = (timezone.now() - summary.started_at).total_seconds()
                avg_time_per_api = elapsed_time / summary.completed_apis
                remaining_apis = summary.pending_apis
                estimated_seconds = avg_time_per_api * remaining_apis
                estimated_time = f"{int(estimated_seconds // 60)}m {int(estimated_seconds % 60)}s"
            
            # Get current API being scanned
            current_api = None
            if summary.scan_status == 'running':
                running_result = ScanResultTC2.objects.filter(
                    scan_id=scan_id, 
                    scan_status='running'
                ).first()
                if running_result:
                    current_api = running_result.api_name
            
            elapsed_time = (timezone.now() - summary.started_at).total_seconds()
            elapsed_str = f"{int(elapsed_time // 3600)}h {int((elapsed_time % 3600) // 60)}m {int(elapsed_time % 60)}s"
            
            data = {
                'scan_id': scan_id,
                'status': summary.scan_status,
                'total_apis': summary.total_apis,
                'completed_apis': summary.completed_apis,
                'pending_apis': summary.pending_apis,
                'failed_apis': summary.failed_apis,
                'progress_percentage': round(progress_percentage, 2),
                'estimated_time_remaining': estimated_time,
                'current_api': current_api,
                'started_at': summary.started_at,
                'elapsed_time': elapsed_str
            }
            
            serializer = ScanStatusTC2Serializer(data)
            return Response(serializer.data)
            
        except ScanSummaryTC2.DoesNotExist:
            return Response(
                {'error': 'Scan not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


class ScanStatsTC2View(APIView):
    """Get overall scan statistics"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            stats = ScanAnalyticsServiceTC2.get_scan_stats()
            serializer = ScanStatsTC2Serializer(stats)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error fetching scan stats: {str(e)}")
            return Response(
                {'error': 'Failed to fetch statistics'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanHistoryTC2View(APIView):
    """Get scan history with pagination"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get query parameters
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        scan_status = request.query_params.get('status')
        days = int(request.query_params.get('days', 30))
        
        # Build queryset
        queryset = ScanSummaryTC2.objects.all()
        
        if scan_status:
            queryset = queryset.filter(scan_status=scan_status)
        
        # Filter by date range
        date_from = timezone.now() - timedelta(days=days)
        queryset = queryset.filter(created_at__gte=date_from)
        
        queryset = queryset.order_by('-started_at')
        
        # Pagination
        start = (page - 1) * page_size
        end = start + page_size
        total_count = queryset.count()
        summaries = queryset[start:end]
        
        # Prepare data
        history_data = []
        for summary in summaries:
            duration = None
            if summary.completed_at and summary.started_at:
                duration_seconds = (summary.completed_at - summary.started_at).total_seconds()
                duration = f"{int(duration_seconds // 60)}m {int(duration_seconds % 60)}s"
            
            history_data.append({
                'scan_id': summary.scan_id,
                'scan_status': summary.scan_status,
                'total_apis': summary.total_apis,
                'vulnerabilities_found': summary.total_vulnerabilities,
                'started_at': summary.started_at,
                'completed_at': summary.completed_at,
                'duration': duration,
                'created_by': summary.created_by.username if summary.created_by else None
            })
        
        serializer = ScanHistoryTC2Serializer(history_data, many=True)
        
        return Response({
            'count': total_count,
            'page': page,
            'page_size': page_size,
            'total_pages': (total_count + page_size - 1) // page_size,
            'results': serializer.data
        })


class VulnerabilitySummaryTC2View(APIView):
    """Get vulnerability summary for a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            summary = ScanAnalyticsServiceTC2.get_vulnerability_summary(scan_id)
            serializer = VulnerabilitySummaryTC2Serializer(summary)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error fetching vulnerability summary for scan {scan_id}: {str(e)}")
            return Response(
                {'error': 'Failed to fetch vulnerability summary'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanSummaryTC2View(APIView):
    """Get scan summary"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id=None):
        if scan_id:
            try:
                summary = ScanSummaryTC2.objects.get(scan_id=scan_id)
                serializer = ScanSummaryTC2Serializer(summary)
                return Response(serializer.data)
            except ScanSummaryTC2.DoesNotExist:
                return Response(
                    {'error': 'Scan summary not found'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # List all summaries
            summaries = ScanSummaryTC2.objects.all().order_by('-started_at')
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 20))
            
            start = (page - 1) * page_size
            end = start + page_size
            total_count = summaries.count()
            
            serializer = ScanSummaryTC2Serializer(summaries[start:end], many=True)
            
            return Response({
                'count': total_count,
                'page': page,
                'page_size': page_size,
                'total_pages': (total_count + page_size - 1) // page_size,
                'results': serializer.data
            })


class TestCredentialsTC2View(APIView):
    """Manage test credentials"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        credentials = TestCredentialTC2.objects.filter(is_active=True)
        serializer = TestCredentialTC2Serializer(credentials, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = TestCredentialTC2Serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanCancelTC2View(APIView):
    """Cancel a running scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, scan_id):
        try:
            summary = ScanSummaryTC2.objects.get(scan_id=scan_id)
            
            if summary.scan_status not in ['running', 'pending']:
                return Response(
                    {'error': 'Scan is not running or pending'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Mark as cancelled
            summary.scan_status = 'cancelled'
            summary.completed_at = timezone.now()
            summary.save()
            
            # Mark pending results as cancelled
            ScanResultTC2.objects.filter(
                scan_id=scan_id,
                scan_status__in=['pending', 'running']
            ).update(
                scan_status='cancelled',
                completed_at=timezone.now()
            )
            
            return Response({'message': 'Scan cancelled successfully'})
            
        except ScanSummaryTC2.DoesNotExist:
            return Response(
                {'error': 'Scan not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


class ScanResultDetailTC2View(APIView):
    """Get detailed scan result"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, result_id):
        try:
            result = ScanResultTC2.objects.get(id=result_id)
            serializer = ScanResultTC2Serializer(result)
            return Response(serializer.data)
        except ScanResultTC2.DoesNotExist:
            return Response(
                {'error': 'Scan result not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


class ScanInitiateViewTC3(APIView):
    """Initiate vulnerability scan for given scan_id"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ScanInitiateSerializerTC3(data=request.data)
        if serializer.is_valid():
            scan_id = serializer.validated_data['scan_id']
            vulnerability_types = serializer.validated_data.get('vulnerability_types', ['weak_password_policy'])
            config = serializer.validated_data.get('config', {})
            
            # Check if scan is already running
            existing_scan = ScanSessionTC3.objects.filter(
                scan_id=scan_id, 
                status__in=['running', 'pending']
            ).first()
            
            if existing_scan:
                return Response({
                    'error': 'Scan is already running for this scan_id',
                    'scan_session': ScanSessionSerializerTC3(existing_scan).data
                }, status=status.HTTP_409_CONFLICT)
            
            # Start scan in background thread
            scanner = VulnerabilityScannerServiceTC3()
            
            def run_scan():
                try:
                    scanner.initiate_scan(scan_id, vulnerability_types, config)
                except Exception as e:
                    print(f"Background scan failed: {str(e)}")
            
            thread = threading.Thread(target=run_scan)
            thread.daemon = True
            thread.start()
            
            # Return immediate response
            scan_session = ScanSessionTC3.objects.create(
                scan_id=scan_id,
                status='pending',
                scan_config={'vulnerability_types': vulnerability_types, **config}
            )
            
            return Response({
                'message': 'Scan initiated successfully',
                'scan_session': ScanSessionSerializerTC3(scan_session).data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanStatusViewTC3(APIView):
    """Get scan status and progress"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan_session = ScanSessionTC3.objects.get(scan_id=scan_id)
            return Response(ScanSessionSerializerTC3(scan_session).data)
        except ScanSessionTC3.DoesNotExist:
            return Response({
                'error': 'Scan session not found'
            }, status=status.HTTP_404_NOT_FOUND)


class ScanResultsViewTC3(APIView):
    """Get scan results with filtering"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Apply filters
        queryset = ScanResultTC3.objects.all()
        
        # Filter parameters
        scan_id = request.GET.get('scan_id')
        vulnerability_type = request.GET.get('vulnerability_type')
        severity = request.GET.get('severity')
        status_filter = request.GET.get('status')
        api_method = request.GET.get('api_method')
        exploit_successful = request.GET.get('exploit_successful')
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        if vulnerability_type:
            queryset = queryset.filter(vulnerability_type=vulnerability_type)
        if severity:
            queryset = queryset.filter(severity=severity)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if api_method:
            queryset = queryset.filter(api_method__icontains=api_method)
        if exploit_successful is not None:
            queryset = queryset.filter(exploit_successful=exploit_successful.lower() == 'true')
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        # Ordering
        queryset = queryset.order_by('-created_at')
        
        # Pagination
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 20))
        
        paginator = Paginator(queryset, page_size)
        page_obj = paginator.get_page(page)
        
        # Detailed view or list view
        detailed = request.GET.get('detailed', 'false').lower() == 'true'
        
        if detailed:
            serializer = ScanResultSerializerTC3(page_obj.object_list, many=True)
        else:
            serializer = ScanResultListSerializerTC3(page_obj.object_list, many=True)
        
        return Response({
            'results': serializer.data,
            'pagination': {
                'current_page': page,
                'total_pages': paginator.num_pages,
                'total_count': paginator.count,
                'page_size': page_size,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous()
            }
        })
    
    def patch(self, request):
        """Update scan result status"""
        result_id = request.data.get('id')
        new_status = request.data.get('status')
        
        if not result_id or not new_status:
            return Response({
                'error': 'ID and status are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            scan_result = ScanResultTC3.objects.get(id=result_id)
            scan_result.status = new_status
            scan_result.save()
            
            return Response(ScanResultSerializerTC3(scan_result).data)
        except ScanResultTC3.DoesNotExist:
            return Response({
                'error': 'Scan result not found'
            }, status=status.HTTP_404_NOT_FOUND)


class VulnerabilitySummaryViewTC3(APIView):
    """Get vulnerability summary for a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        stats_service = ScanStatsServiceTC3()
        summary = stats_service.get_vulnerability_summary(scan_id)
        
        if summary is None:
            return Response({
                'error': 'Scan not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = VulnerabilitySummarySerializerTC3(summary)
        return Response(serializer.data)


class ScanStatsViewTC3(APIView):
    """Get comprehensive scan statistics"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        stats_service = ScanStatsServiceTC3()
        stats = stats_service.get_scan_statistics()
        
        serializer = ScanStatsSerializerTC3(stats)
        return Response(serializer.data)


class ScanHistoryViewTC3(APIView):
    """Get scan history with pagination"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        queryset = ScanSessionTC3.objects.all().order_by('-started_at')
        
        # Filters
        status_filter = request.GET.get('status')
        scan_id = request.GET.get('scan_id')
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        
        # Pagination
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 20))
        
        paginator = Paginator(queryset, page_size)
        page_obj = paginator.get_page(page)
        
        serializer = ScanSessionSerializerTC3(page_obj.object_list, many=True)
        
        response_data = {
            'scan_sessions': serializer.data,
            'total_count': paginator.count,
            'page': page,
            'page_size': page_size,
            'total_pages': paginator.num_pages
        }
        
        return Response(ScanHistorySerializerTC3(response_data).data)


class VulnerabilityTemplatesViewTC3(APIView):
    """Manage vulnerability templates"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        templates = VulnerabilityTemplateTC3.objects.all()
        serializer = VulnerabilityTemplateSerializerTC3(templates, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = VulnerabilityTemplateSerializerTC3(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanResultDetailViewTC3(APIView):
    """Get detailed scan result"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, result_id):
        try:
            scan_result = ScanResultTC3.objects.get(id=result_id)
            serializer = ScanResultSerializerTC3(scan_result)
            return Response(serializer.data)
        except ScanResultTC3.DoesNotExist:
            return Response({
                'error': 'Scan result not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    def patch(self, request, result_id):
        try:
            scan_result = ScanResultTC3.objects.get(id=result_id)
            serializer = ScanResultSerializerTC3(scan_result, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except ScanResultTC3.DoesNotExist:
            return Response({
                'error': 'Scan result not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    def delete(self, request, result_id):
        try:
            scan_result = ScanResultTC3.objects.get(id=result_id)
            scan_result.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except ScanResultTC3.DoesNotExist:
            return Response({
                'error': 'Scan result not found'
            }, status=status.HTTP_404_NOT_FOUND)


class ScanCancelViewTC3(APIView):
    """Cancel running scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, scan_id):
        try:
            scan_session = ScanSessionTC3.objects.get(scan_id=scan_id)
            
            if scan_session.status not in ['running', 'pending']:
                return Response({
                    'error': f'Cannot cancel scan with status: {scan_session.status}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            scan_session.status = 'cancelled'
            scan_session.completed_at = timezone.now()
            scan_session.save()
            
            return Response({
                'message': 'Scan cancelled successfully',
                'scan_session': ScanSessionSerializerTC3(scan_session).data
            })
        except ScanSessionTC3.DoesNotExist:
            return Response({
                'error': 'Scan session not found'
            }, status=status.HTTP_404_NOT_FOUND)


class VulnerabilityTypesViewTC3(APIView):
    """Get available vulnerability types"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'vulnerability_types': [
                {
                    'key': choice[0],
                    'label': choice[1]
                }
                for choice in ScanResultTC3.VULNERABILITY_CHOICES
            ],
            'severity_levels': [
                {
                    'key': choice[0],
                    'label': choice[1]
                }
                for choice in ScanResultTC3.SEVERITY_CHOICES
            ],
            'status_options': [
                {
                    'key': choice[0],
                    'label': choice[1]
                }
                for choice in ScanResultTC3.STATUS_CHOICES
            ]
        })


class BulkScanResultsViewTC3(APIView):
    """Bulk operations on scan results"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def patch(self, request):
        """Bulk update scan results"""
        result_ids = request.data.get('ids', [])
        update_data = request.data.get('update_data', {})
        
        if not result_ids or not update_data:
            return Response({
                'error': 'IDs and update_data are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        updated_count = ScanResultTC3.objects.filter(
            id__in=result_ids
        ).update(**update_data)
        
        return Response({
            'message': f'Updated {updated_count} scan results',
            'updated_count': updated_count
        })
    
    def delete(self, request):
        """Bulk delete scan results"""
        result_ids = request.data.get('ids', [])
        
        if not result_ids:
            return Response({
                'error': 'IDs are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        deleted_count, _ = ScanResultTC3.objects.filter(
            id__in=result_ids
        ).delete()
        
        return Response({
            'message': f'Deleted {deleted_count} scan results',
            'deleted_count': deleted_count
        })


class ScanExportViewTC3(APIView):
    """Export scan results"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        """Export scan results as JSON"""
        try:
            scan_session = ScanSessionTC3.objects.get(scan_id=scan_id)
            scan_results = ScanResultTC3.objects.filter(scan_id=scan_id)
            
            export_data = {
                'scan_session': ScanSessionSerializerTC3(scan_session).data,
                'results': ScanResultSerializerTC3(scan_results, many=True).data,
                'export_timestamp': timezone.now().isoformat(),
                'total_vulnerabilities': scan_results.count()
            }
            
            response = Response(export_data)
            response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}_export.json"'
            return response
            
        except ScanSessionTC3.DoesNotExist:
            return Response({
                'error': 'Scan session not found'
            }, status=status.HTTP_404_NOT_FOUND)


class JWTScanCreateAPIViewTC4(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = JWTScanCreateSerializerTC4(data=request.data)
        if serializer.is_valid():
            scan_id = serializer.validated_data['scan_id']
            config_data = serializer.validated_data.get('config', {})
            
            try:
                # Start scan in background thread
                scan_service = JWTScanServiceTC4()
                
                def run_scan():
                    scan_service.start_scan(scan_id, request.user, config_data)
                
                thread = threading.Thread(target=run_scan)
                thread.daemon = True
                thread.start()
                
                return Response({
                    'message': f'JWT vulnerability scan started for scan_id {scan_id}',
                    'scan_id': scan_id,
                    'status': 'initiated'
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                return Response({
                    'error': f'Failed to start scan: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JWTScanListAPIViewTC4(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = JWTScanSerializerTC4
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['created_at', 'scan_id', 'status']
    ordering = ['-created_at']
    
    def get_queryset(self):
        return JWTScanTC4.objects.select_related('created_by', 'config').all()


class JWTScanDetailAPIViewTC4(generics.RetrieveAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = JWTScanDetailSerializerTC4
    lookup_field = 'scan_id'
    
    def get_queryset(self):
        return JWTScanTC4.objects.select_related('created_by', 'config').prefetch_related(
            'vulnerabilities', 'logs', 'token_analyses'
        ).all()


class JWTScanStatusAPIViewTC4(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = JWTScanTC4.objects.get(scan_id=scan_id)
            
            progress_percentage = 0
            if scan.total_apis > 0:
                progress_percentage = (scan.scanned_apis / scan.total_apis) * 100
            
            # Estimate completion time
            estimated_completion = None
            if scan.status == 'in_progress' and scan.scanned_apis > 0:
                elapsed_time = (timezone.now() - scan.created_at).total_seconds()
                time_per_api = elapsed_time / scan.scanned_apis
                remaining_apis = scan.total_apis - scan.scanned_apis
                estimated_seconds = remaining_apis * time_per_api
                estimated_completion = timezone.now() + timedelta(seconds=estimated_seconds)
            
            return Response({
                'scan_id': scan.scan_id,
                'status': scan.status,
                'status_display': scan.get_status_display(),
                'total_apis': scan.total_apis,
                'scanned_apis': scan.scanned_apis,
                'vulnerable_apis': scan.vulnerable_apis,
                'progress_percentage': round(progress_percentage, 2),
                'created_at': scan.created_at,
                'updated_at': scan.updated_at,
                'completed_at': scan.completed_at,
                'scan_duration': scan.scan_duration,
                'estimated_completion_time': estimated_completion
            })
            
        except JWTScanTC4.DoesNotExist:
            return Response({
                'error': f'Scan with ID {scan_id} not found'
            }, status=status.HTTP_404_NOT_FOUND)


class JWTScanStatsAPIViewTC4(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = JWTScanTC4.objects.get(scan_id=scan_id)
            
            # Get vulnerability statistics
            vulnerabilities_by_severity = JWTVulnerabilityTC4.objects.filter(
                scan=scan, is_vulnerable=True
            ).values('severity').annotate(count=Count('id'))
            
            vulnerabilities_by_type = JWTVulnerabilityTC4.objects.filter(
                scan=scan, is_vulnerable=True
            ).values('vulnerability_type').annotate(count=Count('id'))
            
            severity_stats = {item['severity']: item['count'] for item in vulnerabilities_by_severity}
            type_stats = {item['vulnerability_type']: item['count'] for item in vulnerabilities_by_type}
            
            progress_percentage = 0
            if scan.total_apis > 0:
                progress_percentage = (scan.scanned_apis / scan.total_apis) * 100
            
            # Estimate completion time
            estimated_completion = None
            if scan.status == 'in_progress' and scan.scanned_apis > 0:
                elapsed_time = (timezone.now() - scan.created_at).total_seconds()
                time_per_api = elapsed_time / scan.scanned_apis
                remaining_apis = scan.total_apis - scan.scanned_apis
                estimated_seconds = remaining_apis * time_per_api
                estimated_completion = timezone.now() + timedelta(seconds=estimated_seconds)
            
            serializer = JWTScanStatsSerializerTC4(data={
                'scan_id': scan.scan_id,
                'total_apis': scan.total_apis,
                'scanned_apis': scan.scanned_apis,
                'vulnerable_apis': scan.vulnerable_apis,
                'progress_percentage': round(progress_percentage, 2),
                'vulnerabilities_by_severity': severity_stats,
                'vulnerabilities_by_type': type_stats,
                'estimated_completion_time': estimated_completion
            })
            serializer.is_valid()
            return Response(serializer.data)
            
        except JWTScanTC4.DoesNotExist:
            return Response({
                'error': f'Scan with ID {scan_id} not found'
            }, status=status.HTTP_404_NOT_FOUND)


class JWTScanHistoryAPIViewTC4(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = JWTScanSerializerTC4
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['created_at', 'scan_id', 'completed_at']
    ordering = ['-created_at']
    
    def get_queryset(self):
        queryset = JWTScanTC4.objects.select_related('created_by').all()
        
        # Filter by date range if provided
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by user
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(created_by_id=user_id)
        
        return queryset


class JWTVulnerabilityListAPIViewTC4(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = JWTVulnerabilitySerializerTC4
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['created_at', 'severity', 'vulnerability_type']
    ordering = ['-created_at']
    
    def get_queryset(self):
        queryset = JWTVulnerabilityTC4.objects.select_related('scan').all()
        
        # Apply filters
        filter_serializer = JWTVulnerabilityFilterSerializerTC4(data=self.request.query_params)
        if filter_serializer.is_valid():
            filters = filter_serializer.validated_data
            
            if 'scan_id' in filters:
                queryset = queryset.filter(scan__scan_id=filters['scan_id'])
            
            if 'severity' in filters:
                queryset = queryset.filter(severity=filters['severity'])
            
            if 'vulnerability_type' in filters:
                queryset = queryset.filter(vulnerability_type=filters['vulnerability_type'])
            
            if 'is_vulnerable' in filters:
                queryset = queryset.filter(is_vulnerable=filters['is_vulnerable'])
            
            if 'api_method' in filters:
                queryset = queryset.filter(api_method__iexact=filters['api_method'])
            
            if 'date_from' in filters:
                queryset = queryset.filter(created_at__gte=filters['date_from'])
            
            if 'date_to' in filters:
                queryset = queryset.filter(created_at__lte=filters['date_to'])
        
        return queryset


class JWTVulnerabilitySummaryAPIViewTC4(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Overall statistics
        total_scans = JWTScanTC4.objects.count()
        total_apis_scanned = JWTScanTC4.objects.aggregate(
            total=Count('scanned_apis')
        )['total'] or 0
        total_vulnerabilities = JWTVulnerabilityTC4.objects.filter(is_vulnerable=True).count()
        
        # Vulnerability breakdown by type
        vulnerability_by_type = dict(
            JWTVulnerabilityTC4.objects.filter(is_vulnerable=True)
            .values('vulnerability_type')
            .annotate(count=Count('id'))
            .values_list('vulnerability_type', 'count')
        )
        
        # Vulnerability breakdown by severity
        vulnerability_by_severity = dict(
            JWTVulnerabilityTC4.objects.filter(is_vulnerable=True)
            .values('severity')
            .annotate(count=Count('id'))
            .values_list('severity', 'count')
        )
        
        # Recent scans
        recent_scans = JWTScanTC4.objects.select_related('created_by').order_by('-created_at')[:10]
        
        data = {
            'total_scans': total_scans,
            'total_apis_scanned': total_apis_scanned,
            'total_vulnerabilities': total_vulnerabilities,
            'vulnerability_by_type': vulnerability_by_type,
            'vulnerability_by_severity': vulnerability_by_severity,
            'recent_scans': JWTScanSerializerTC4(recent_scans, many=True).data
        }
        
        return Response(data)


class JWTVulnerabilityDetailAPIViewTC4(generics.RetrieveAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = JWTVulnerabilitySerializerTC4
    queryset = JWTVulnerabilityTC4.objects.select_related('scan').all()


class JWTScanLogsAPIViewTC4(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = JWTScanLogSerializerTC4
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['timestamp', 'level']
    ordering = ['-timestamp']
    
    def get_queryset(self):
        scan_id = self.kwargs.get('scan_id')
        queryset = JWTScanLogTC4.objects.filter(scan__scan_id=scan_id)
        
        # Filter by log level
        level = self.request.query_params.get('level')
        if level:
            queryset = queryset.filter(level=level)
        
        return queryset


class JWTTokenAnalysisListAPIViewTC4(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = JWTTokenAnalysisSerializerTC4
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['created_at']
    ordering = ['-created_at']
    
    def get_queryset(self):
        scan_id = self.kwargs.get('scan_id')
        return JWTTokenAnalysisTC4.objects.filter(scan__scan_id=scan_id)


class JWTScanDeleteAPIViewTC4(generics.DestroyAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'scan_id'
    
    def get_queryset(self):
        return JWTScanTC4.objects.all()
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.status == 'in_progress':
            return Response({
                'error': 'Cannot delete scan that is currently in progress'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        self.perform_destroy(instance)
        return Response({
            'message': f'Scan {instance.scan_id} deleted successfully'
        }, status=status.HTTP_200_OK)


class JWTScannerAutoStatusAPIViewTC4(APIView):
    """Get status of the auto-scanner service"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get auto-service status"""
        try:
            from .startup_service import get_auto_service_status
            status = get_auto_service_status()
            
            return Response({
                'auto_service': status,
                'message': 'Auto JWT Scanner is running' if status['running'] else 'Auto JWT Scanner is stopped',
                'timestamp': timezone.now()
            })
            
        except Exception as e:
            return Response({
                'error': f'Failed to get auto-service status: {str(e)}',
                'auto_service': {'running': False}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """Control auto-service (start/stop)"""
        action = request.data.get('action', '').lower()
        
        try:
            from .startup_service import start_jwt_scanner_auto, stop_jwt_scanner_auto
            
            if action == 'start':
                success = start_jwt_scanner_auto()
                return Response({
                    'message': 'Auto-service started' if success else 'Failed to start auto-service',
                    'success': success
                })
            
            elif action == 'stop':
                stop_jwt_scanner_auto()
                return Response({
                    'message': 'Auto-service stopped',
                    'success': True
                })
            
            else:
                return Response({
                    'error': 'Invalid action. Use "start" or "stop"'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            return Response({
                'error': f'Failed to control auto-service: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)