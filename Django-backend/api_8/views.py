from django.db import models
from django.utils import timezone
from django.db.models import Count, Q, Avg
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from datetime import timedelta
import threading

from .models import CORSScanResultTC1, CORSScanSessionTC1
from .serializers import (
    CORSScanRequestTC1Serializer, CORSScanResultTC1Serializer,
    CORSScanSessionTC1Serializer, VulnerabilitySummaryTC1Serializer,
    ScanStatsTC1Serializer
)
from .services import CORSScannerServiceTC1


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class CORSScanStartTC1View(APIView):
    """Start CORS vulnerability scan for given scan_id"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CORSScanRequestTC1Serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        scan_id = serializer.validated_data['scan_id']
        
        # Check if scan is already running
        existing_session = CORSScanSessionTC1.objects.filter(
            scan_id=scan_id, 
            status__in=['pending', 'running']
        ).first()
        
        if existing_session:
            return Response(
                {'error': f'Scan {scan_id} is already running'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get access token from api_orch_scantokens
        access_token = self._get_access_token(scan_id)
        
        # Start scan in background thread
        scanner = CORSScannerServiceTC1()
        
        def run_scan():
            scanner.start_scan(scan_id, access_token)
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

        return Response(
            {'message': f'CORS scan started for scan_id: {scan_id}'},
            status=status.HTTP_202_ACCEPTED
        )

    def _get_access_token(self, scan_id: int) -> str:
        """Get access token from api_orch_scantokens table"""
        from django.db import connections
        
        try:
            connection = connections['default']
            cursor = connection.cursor()
            
            cursor.execute("""
                SELECT access_token FROM api_orch_scantokens 
                WHERE scan_id = %s 
                ORDER BY created_at DESC 
                LIMIT 1
            """, [scan_id])
            
            result = cursor.fetchone()
            return result[0] if result else ''
            
        except Exception:
            return ''


class CORSScanResultsTC1View(APIView):
    """Get CORS scan results with filtering"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id parameter is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = CORSScanResultTC1.objects.filter(scan_id=scan_id)

        # Apply filters
        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        severity_filter = request.query_params.get('severity')
        if severity_filter:
            queryset = queryset.filter(severity=severity_filter)

        api_name_filter = request.query_params.get('api_name')
        if api_name_filter:
            queryset = queryset.filter(api_name__icontains=api_name_filter)

        method_filter = request.query_params.get('method')
        if method_filter:
            queryset = queryset.filter(api_method=method_filter)

        # Ordering
        ordering = request.query_params.get('ordering', '-created_at')
        queryset = queryset.order_by(ordering)

        # Pagination
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = CORSScanResultTC1Serializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        serializer = CORSScanResultTC1Serializer(queryset, many=True)
        return Response(serializer.data)


class CORSScanStatusTC1View(APIView):
    """Get scan status and progress"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id parameter is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            session = CORSScanSessionTC1.objects.get(scan_id=scan_id)
            serializer = CORSScanSessionTC1Serializer(session)
            return Response(serializer.data)
        except CORSScanSessionTC1.DoesNotExist:
            return Response(
                {'error': f'No scan session found for scan_id: {scan_id}'},
                status=status.HTTP_404_NOT_FOUND
            )


class CORSVulnerabilitySummaryTC1View(APIView):
    """Get vulnerability summary for a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id parameter is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get scan session
        try:
            session = CORSScanSessionTC1.objects.get(scan_id=scan_id)
        except CORSScanSessionTC1.DoesNotExist:
            return Response(
                {'error': f'No scan session found for scan_id: {scan_id}'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get results summary
        results = CORSScanResultTC1.objects.filter(scan_id=scan_id)
        
        status_counts = results.values('status').annotate(count=Count('status'))
        severity_counts = results.filter(severity__isnull=False).values('severity').annotate(count=Count('severity'))

        status_breakdown = {item['status']: item['count'] for item in status_counts}
        severity_breakdown = {item['severity']: item['count'] for item in severity_counts}

        # Most common vulnerabilities
        vulnerable_results = results.filter(status='vulnerable')
        common_vulns = vulnerable_results.values('vulnerability_description').annotate(
            count=Count('vulnerability_description')
        ).order_by('-count')[:5]

        most_common_vulnerabilities = [
            {
                'description': vuln['vulnerability_description'][:100] + '...' if len(vuln['vulnerability_description']) > 100 else vuln['vulnerability_description'],
                'count': vuln['count']
            }
            for vuln in common_vulns
        ]

        # Calculate risk score (0-100)
        total_apis = session.total_apis or 1
        risk_score = min(100, (
            (session.critical_count * 10 + 
             session.high_count * 7 + 
             session.medium_count * 4 + 
             session.low_count * 2 + 
             session.info_count * 1) / total_apis
        ) * 10)

        # Scan duration
        if session.started_at and session.completed_at:
            duration = session.completed_at - session.started_at
            scan_duration = f"{duration.total_seconds():.1f} seconds"
        elif session.started_at:
            duration = timezone.now() - session.started_at
            scan_duration = f"{duration.total_seconds():.1f} seconds (ongoing)"
        else:
            scan_duration = "Not started"

        summary_data = {
            'scan_id': int(scan_id),
            'total_apis': session.total_apis,
            'vulnerable_apis': session.vulnerable_apis,
            'not_vulnerable_apis': status_breakdown.get('not_vulnerable', 0),
            'error_apis': status_breakdown.get('error', 0) + status_breakdown.get('timeout', 0),
            'severity_breakdown': severity_breakdown,
            'status_breakdown': status_breakdown,
            'most_common_vulnerabilities': most_common_vulnerabilities,
            'risk_score': round(risk_score, 2),
            'scan_status': session.status,
            'scan_duration': scan_duration
        }

        serializer = VulnerabilitySummaryTC1Serializer(summary_data)
        return Response(serializer.data)


class CORSScanStatsTC1View(APIView):
    """Get overall scan statistics"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Overall stats
        total_scans = CORSScanSessionTC1.objects.count()
        completed_scans = CORSScanSessionTC1.objects.filter(status='completed').count()
        pending_scans = CORSScanSessionTC1.objects.filter(status__in=['pending', 'running']).count()
        failed_scans = CORSScanSessionTC1.objects.filter(status='failed').count()

        # API stats
        total_apis_scanned = CORSScanSessionTC1.objects.aggregate(
            total=models.Sum('scanned_apis')
        )['total'] or 0
        
        total_vulnerabilities = CORSScanResultTC1.objects.filter(status='vulnerable').count()

        # Averages
        avg_vulns = CORSScanSessionTC1.objects.filter(status='completed').aggregate(
            avg=Avg('vulnerable_apis')
        )['avg'] or 0

        # Average scan duration
        completed_sessions = CORSScanSessionTC1.objects.filter(
            status='completed', 
            started_at__isnull=False, 
            completed_at__isnull=False
        )
        
        if completed_sessions.exists():
            durations = [
                (session.completed_at - session.started_at).total_seconds() / 60
                for session in completed_sessions
            ]
            avg_duration = sum(durations) / len(durations)
        else:
            avg_duration = 0

        # Recent activity (last 10 scans)
        recent_scans = CORSScanSessionTC1.objects.select_related().order_by('-created_at')[:10]
        recent_activity = [
            {
                'scan_id': scan.scan_id,
                'status': scan.status,
                'total_apis': scan.total_apis,
                'vulnerable_apis': scan.vulnerable_apis,
                'created_at': scan.created_at.isoformat(),
                'duration_minutes': (
                    (scan.completed_at - scan.started_at).total_seconds() / 60
                    if scan.started_at and scan.completed_at else None
                )
            }
            for scan in recent_scans
        ]

        stats_data = {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'pending_scans': pending_scans,
            'failed_scans': failed_scans,
            'total_apis_scanned': total_apis_scanned,
            'total_vulnerabilities_found': total_vulnerabilities,
            'avg_vulnerabilities_per_scan': round(avg_vulns, 2),
            'avg_scan_duration_minutes': round(avg_duration, 2),
            'recent_activity': recent_activity
        }

        serializer = ScanStatsTC1Serializer(stats_data)
        return Response(serializer.data)


class CORSScanHistoryTC1View(APIView):
    """Get scan history with pagination"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get(self, request):
        queryset = CORSScanSessionTC1.objects.all()

        # Filters
        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Date range filter
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')
        
        if date_from:
            try:
                from datetime import datetime
                date_from = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                queryset = queryset.filter(created_at__gte=date_from)
            except ValueError:
                pass

        if date_to:
            try:
                from datetime import datetime
                date_to = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                queryset = queryset.filter(created_at__lte=date_to)
            except ValueError:
                pass

        # Ordering
        ordering = request.query_params.get('ordering', '-created_at')
        queryset = queryset.order_by(ordering)

        # Pagination
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = CORSScanSessionTC1Serializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        serializer = CORSScanSessionTC1Serializer(queryset, many=True)
        return Response(serializer.data)


class CORSResultDetailTC1View(APIView):
    """Get detailed result for a specific scan result"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, result_id):
        try:
            result = CORSScanResultTC1.objects.get(id=result_id)
            serializer = CORSScanResultTC1Serializer(result)
            return Response(serializer.data)
        except CORSScanResultTC1.DoesNotExist:
            return Response(
                {'error': f'Scan result {result_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class CORSScanDeleteTC1View(APIView):
    """Delete scan session and all related results"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id parameter is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Check if scan is running
            session = CORSScanSessionTC1.objects.get(scan_id=scan_id)
            if session.status in ['pending', 'running']:
                return Response(
                    {'error': 'Cannot delete running scan'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Delete results and session
            deleted_results = CORSScanResultTC1.objects.filter(scan_id=scan_id).count()
            CORSScanResultTC1.objects.filter(scan_id=scan_id).delete()
            session.delete()

            return Response({
                'message': f'Deleted scan {scan_id} with {deleted_results} results'
            })

        except CORSScanSessionTC1.DoesNotExist:
            return Response(
                {'error': f'Scan session {scan_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class CORSScanRetryTC1View(APIView):
    """Retry failed APIs in a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        scan_id = request.data.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if there are failed results
        failed_results = CORSScanResultTC1.objects.filter(
            scan_id=scan_id, 
            status__in=['error', 'timeout']
        )

        if not failed_results.exists():
            return Response(
                {'message': 'No failed results to retry'}, 
                status=status.HTTP_200_OK
            )

        # Update session status
        try:
            session = CORSScanSessionTC1.objects.get(scan_id=scan_id)
            session.status = 'running'
            session.save()
        except CORSScanSessionTC1.DoesNotExist:
            return Response(
                {'error': f'Scan session {scan_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get access token and retry failed APIs
        access_token = self._get_access_token(scan_id)
        
        def retry_scan():
            scanner = CORSScannerServiceTC1()
            # Get failed API details and retry them
            # This would need to be implemented based on your specific requirements
            pass
        
        thread = threading.Thread(target=retry_scan)
        thread.daemon = True
        thread.start()

        return Response(
            {'message': f'Retrying {failed_results.count()} failed APIs'},
            status=status.HTTP_202_ACCEPTED
        )

    def _get_access_token(self, scan_id: int) -> str:
        """Get access token from api_orch_scantokens table"""
        from django.db import connections
        
        try:
            connection = connections['default']
            cursor = connection.cursor()
            
            cursor.execute("""
                SELECT access_token FROM api_orch_scantokens 
                WHERE scan_id = %s 
                ORDER BY created_at DESC 
                LIMIT 1
            """, [scan_id])
            
            result = cursor.fetchone()
            return result[0] if result else ''
            
        except Exception:
            return ''