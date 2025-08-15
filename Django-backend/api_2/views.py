from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Q, Count
from datetime import timedelta
from .models import ScanResultTC1, ScanSessionTC1, VulnerabilitySummaryTC1
from .serializers import (
    ScanInitiateSerializerTC1, ScanResultSerializerTC1, ScanSessionSerializerTC1,
    VulnerabilitySummarySerializerTC1, ScanStatsSerializerTC1, ScanHistorySerializerTC1,
    ScanFilterSerializerTC1
)
from .services import APISecurityScannerTC1, APIOrchDataServiceTC1
from .tasks import run_security_scan_async
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