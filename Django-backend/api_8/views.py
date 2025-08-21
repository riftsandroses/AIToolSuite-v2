import logging
import threading
from datetime import timedelta

from django.db import models, connection
from django.db.models import Count, Q, Avg
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework import status, generics, filters
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework_simplejwt.authentication import JWTAuthentication

from django_filters.rest_framework import DjangoFilterBackend

from .models import (
    CORSScanResultTC1, CORSScanSessionTC1,
    ScanTC2, VulnerabilityTC2, ScanHistoryTC2, ScanMetricsTC2,
    ScanTC3, VulnerabilityTC3, ScanHistoryTC3, ScanStatsTC3
)

from .serializers import (
    CORSScanRequestTC1Serializer, CORSScanResultTC1Serializer,
    CORSScanSessionTC1Serializer, VulnerabilitySummaryTC1Serializer,
    ScanStatsTC1Serializer, ScanCreateSerializerTC2,
    ScanSerializerTC2, ScanStatusSerializerTC2, ScanStatsSerializerTC2,
    VulnerabilitySerializerTC2, VulnerabilitySummarySerializerTC2,
    ScanResultsSerializerTC2, VulnerabilityFilterSerializerTC2,
    ScanHistorySerializerTC2, ScanRequestSerializerTC3, ScanSerializerTC3,
    ScanSummarySerializerTC3, VulnerabilitySerializerTC3,
    VulnerabilitySummarySerializerTC3, ScanFilterSerializerTC3,
    ScanHistorySerializerTC3, ScanStatsSerializerTC3
)

from .services import (
    CORSScannerServiceTC1, TLSScanServiceTC2, ScanAnalyticsServiceTC2,
    VulnerabilityScannerServiceTC3
)


logger = logging.getLogger(__name__)


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


class StandardResultsSetPaginationTC2(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

class InitiateTLSScanViewTC2(APIView):
    """
    Initiate a new TLS security scan for the given scan_id
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ScanCreateSerializerTC2(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Get JWT token from api_orch_scantokens
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT access_token FROM api_orch_scantokens 
                    WHERE scan_id = %s ORDER BY created_at DESC LIMIT 1
                """, [scan_id])
                
                token_result = cursor.fetchone()
                if not token_result:
                    return Response(
                        {'error': f'No access token found for scan_id: {scan_id}'}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
            
            # Check if scan already exists
            existing_scan = ScanTC2.objects.filter(scan_id=scan_id).first()
            if existing_scan and existing_scan.status in ['pending', 'running']:
                return Response(
                    {'error': 'Scan already in progress for this scan_id'},
                    status=status.HTTP_409_CONFLICT
                )
            
            # Initialize scan
            scan_service = TLSScanServiceTC2()
            scan, apis = scan_service.initiate_scan(scan_id, request.user)
            
            # Start scan in background thread
            scan_thread = threading.Thread(
                target=self._execute_scan_background,
                args=(scan, apis, scan_service)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
            return Response({
                'message': 'TLS security scan initiated successfully',
                'scan_id': str(scan.id),
                'original_scan_id': scan_id,
                'total_apis': scan.total_apis,
                'status': scan.status
            }, status=status.HTTP_201_CREATED)
            
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Failed to initiate scan: {str(e)}")
            return Response(
                {'error': 'Failed to initiate scan'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _execute_scan_background(self, scan, apis, scan_service):
        """Execute the actual scanning in background"""
        try:
            scan.status = 'running'
            scan.save()
            
            for api_data in apis:
                try:
                    vulnerabilities = scan_service.perform_tls_analysis(api_data, scan)
                    logger.info(f"Scanned API {api_data[0]}, found {len(vulnerabilities)} vulnerabilities")
                except Exception as e:
                    logger.error(f"Failed to scan API {api_data[0]}: {str(e)}")
                    continue
            
            scan_service.finalize_scan(scan)
            logger.info(f"TLS scan {scan.id} completed successfully")
            
        except Exception as e:
            logger.error(f"Background scan failed: {str(e)}")
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.save()

class ScanStatusViewTC2(APIView):
    """
    Get the current status of a scan
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        scan = get_object_or_404(ScanTC2, id=scan_id)
        serializer = ScanStatusSerializerTC2(scan)
        return Response(serializer.data)

class ScanResultsViewTC2(APIView):
    """
    Get scan results with filtering capabilities
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPaginationTC2
    
    def get(self, request, scan_id):
        scan = get_object_or_404(ScanTC2, id=scan_id)
        
        # Get vulnerabilities queryset
        vulnerabilities = scan.vulnerabilities.all()
        
        # Apply filters
        filter_serializer = VulnerabilityFilterSerializerTC2(data=request.query_params)
        filters_applied = {}
        
        if filter_serializer.is_valid():
            filters = filter_serializer.validated_data
            
            if filters.get('severity'):
                vulnerabilities = vulnerabilities.filter(severity__in=filters['severity'])
                filters_applied['severity'] = filters['severity']
            
            if filters.get('status'):
                vulnerabilities = vulnerabilities.filter(status__in=filters['status'])
                filters_applied['status'] = filters['status']
            
            if filters.get('api_method'):
                vulnerabilities = vulnerabilities.filter(api_method__iexact=filters['api_method'])
                filters_applied['api_method'] = filters['api_method']
            
            if filters.get('api_url_contains'):
                vulnerabilities = vulnerabilities.filter(api_url__icontains=filters['api_url_contains'])
                filters_applied['api_url_contains'] = filters['api_url_contains']
            
            if filters.get('confidence_score_min'):
                vulnerabilities = vulnerabilities.filter(confidence_score__gte=filters['confidence_score_min'])
                filters_applied['confidence_score_min'] = filters['confidence_score_min']
            
            if filters.get('date_from'):
                vulnerabilities = vulnerabilities.filter(created_at__gte=filters['date_from'])
                filters_applied['date_from'] = filters['date_from']
            
            if filters.get('date_to'):
                vulnerabilities = vulnerabilities.filter(created_at__lte=filters['date_to'])
                filters_applied['date_to'] = filters['date_to']
            
            if filters.get('has_exploit') is not None:
                if filters['has_exploit']:
                    vulnerabilities = vulnerabilities.exclude(exploit_details='')
                else:
                    vulnerabilities = vulnerabilities.filter(exploit_details='')
                filters_applied['has_exploit'] = filters['has_exploit']
        
        # Pagination
        paginator = self.pagination_class()
        paginated_vulnerabilities = paginator.paginate_queryset(vulnerabilities, request)
        
        # Serialize data
        scan_serializer = ScanSerializerTC2(scan)
        vuln_serializer = VulnerabilitySerializerTC2(paginated_vulnerabilities, many=True)
        
        response_data = {
            'scan': scan_serializer.data,
            'vulnerabilities': vuln_serializer.data,
            'total_vulnerabilities': scan.vulnerabilities.count(),
            'filtered_count': vulnerabilities.count(),
            'filters_applied': filters_applied
        }
        
        return paginator.get_paginated_response(response_data)

class VulnerabilitySummaryViewTC2(APIView):
    """
    Get a summary of vulnerabilities across all scans
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPaginationTC2
    
    def get(self, request):
        vulnerabilities = VulnerabilityTC2.objects.select_related('scan').all()
        
        # Apply filters similar to scan results
        filter_serializer = VulnerabilityFilterSerializerTC2(data=request.query_params)
        
        if filter_serializer.is_valid():
            filters = filter_serializer.validated_data
            
            if filters.get('severity'):
                vulnerabilities = vulnerabilities.filter(severity__in=filters['severity'])
            
            if filters.get('status'):
                vulnerabilities = vulnerabilities.filter(status__in=filters['status'])
            
            # Add scan_id filter
            scan_id = request.query_params.get('scan_id')
            if scan_id:
                vulnerabilities = vulnerabilities.filter(scan__scan_id=scan_id)
            
            # Add search functionality
            search = request.query_params.get('search')
            if search:
                vulnerabilities = vulnerabilities.filter(
                    Q(title__icontains=search) |
                    Q(api_name__icontains=search) |
                    Q(api_url__icontains=search) |
                    Q(description__icontains=search)
                )
        
        # Order by severity and creation date
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        case_statements = ' '.join([f"WHEN severity='{s}' THEN {i}" for i, s in enumerate(severity_order)])
        vulnerabilities = vulnerabilities.extra(
            select={'severity_order': f"CASE {case_statements} END"}
        ).order_by('severity_order', '-created_at')
        
        # Pagination
        paginator = self.pagination_class()
        paginated_vulnerabilities = paginator.paginate_queryset(vulnerabilities, request)
        
        serializer = VulnerabilitySummarySerializerTC2(paginated_vulnerabilities, many=True)
        return paginator.get_paginated_response(serializer.data)

class ScanStatsViewTC2(APIView):
    """
    Get comprehensive scan statistics and analytics
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        analytics_service = ScanAnalyticsServiceTC2()
        stats = analytics_service.get_scan_statistics()
        
        serializer = ScanStatsSerializerTC2(stats)
        return Response(serializer.data)

class ScanHistoryViewTC2(APIView):
    """
    Get scan history and audit trail
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPaginationTC2
    
    def get(self, request, scan_id=None):
        if scan_id:
            scan = get_object_or_404(ScanTC2, id=scan_id)
            history = scan.history.all()
        else:
            history = ScanHistoryTC2.objects.select_related('scan').all()
        
        # Filter by action type
        action = request.query_params.get('action')
        if action:
            history = history.filter(action__icontains=action)
        
        # Filter by date range
        date_from = request.query_params.get('date_from')
        if date_from:
            history = history.filter(timestamp__gte=date_from)
        
        date_to = request.query_params.get('date_to')
        if date_to:
            history = history.filter(timestamp__lte=date_to)
        
        # Pagination
        paginator = self.pagination_class()
        paginated_history = paginator.paginate_queryset(history, request)
        
        serializer = ScanHistorySerializerTC2(paginated_history, many=True)
        return paginator.get_paginated_response(serializer.data)

class VulnerabilityDetailViewTC2(APIView):
    """
    Get detailed information about a specific vulnerability
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, vulnerability_id):
        vulnerability = get_object_or_404(VulnerabilityTC2, id=vulnerability_id)
        serializer = VulnerabilitySerializerTC2(vulnerability)
        return Response(serializer.data)
    
    def patch(self, request, vulnerability_id):
        """Update vulnerability status"""
        vulnerability = get_object_or_404(VulnerabilityTC2, id=vulnerability_id)
        
        allowed_updates = ['status', 'recommendation', 'exploit_details']
        update_data = {k: v for k, v in request.data.items() if k in allowed_updates}
        
        serializer = VulnerabilitySerializerTC2(vulnerability, data=update_data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ScanListViewTC2(APIView):
    """
    List all scans with filtering and search
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPaginationTC2
    
    def get(self, request):
        scans = ScanTC2.objects.select_related('created_by').prefetch_related('metrics').all()
        
        # Filter by status
        status_filter = request.query_params.get('status')
        if status_filter:
            scans = scans.filter(status=status_filter)
        
        # Filter by scan_id
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            scans = scans.filter(scan_id=scan_id)
        
        # Filter by date range
        date_from = request.query_params.get('date_from')
        if date_from:
            scans = scans.filter(started_at__gte=date_from)
        
        date_to = request.query_params.get('date_to')
        if date_to:
            scans = scans.filter(started_at__lte=date_to)
        
        # Order by creation date (newest first)
        scans = scans.order_by('-started_at')
        
        # Pagination
        paginator = self.pagination_class()
        paginated_scans = paginator.paginate_queryset(scans, request)
        
        serializer = ScanSerializerTC2(paginated_scans, many=True)
        return paginator.get_paginated_response(serializer.data)

class CancelScanViewTC2(APIView):
    """
    Cancel a running scan
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, scan_id):
        scan = get_object_or_404(ScanTC2, id=scan_id)
        
        if scan.status not in ['pending', 'running']:
            return Response(
                {'error': 'Can only cancel pending or running scans'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan.status = 'cancelled'
        scan.completed_at = timezone.now()
        scan.save()
        
        # Log cancellation
        ScanHistoryTC2.objects.create(
            scan=scan,
            action='scan_cancelled',
            description=f'Scan cancelled by {request.user.username}',
            details={'cancelled_by': request.user.username}
        )
        
        return Response({
            'message': 'Scan cancelled successfully',
            'scan_id': str(scan.id),
            'status': scan.status
        })

class StartScanAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ScanRequestSerializerTC3(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        scan_id = serializer.validated_data['scan_id']
        
        # Check if scan already exists
        if ScanTC3.objects.filter(scan_id=scan_id).exists():
            return Response(
                {'error': 'Scan already exists for this scan_id'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Start scan in background
            scanner = VulnerabilityScannerServiceTC3()
            
            def run_scan():
                try:
                    result = scanner.scan_apis_for_vulnerabilities(scan_id)
                    logger.info(f"Scan {scan_id} completed: {result}")
                except Exception as e:
                    logger.error(f"Background scan failed: {str(e)}")
            
            thread = threading.Thread(target=run_scan)
            thread.daemon = True
            thread.start()
            
            return Response({
                'message': 'Vulnerability scan started',
                'scan_id': scan_id,
                'status': 'RUNNING'
            }, status=status.HTTP_202_ACCEPTED)
            
        except Exception as e:
            logger.error(f"Failed to start scan: {str(e)}")
            return Response(
                {'error': 'Failed to start scan'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanStatusAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(scan_id=scan_id)
            
            # Calculate progress percentage
            progress = 0
            if scan.total_apis > 0:
                progress = (scan.scanned_apis / scan.total_apis) * 100
            
            return Response({
                'scan_id': scan.scan_id,
                'status': scan.status,
                'progress': round(progress, 2),
                'total_apis': scan.total_apis,
                'scanned_apis': scan.scanned_apis,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'started_at': scan.started_at,
                'completed_at': scan.completed_at
            })
            
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class ScanResultsAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(scan_id=scan_id)
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Apply filters
        filter_serializer = ScanFilterSerializerTC3(data=request.query_params)
        filter_serializer.is_valid()
        
        vulnerabilities = scan.vulnerabilities.all()
        
        # Apply filters
        if filter_serializer.is_valid():
            filters = filter_serializer.validated_data
            
            if filters.get('severity'):
                vulnerabilities = vulnerabilities.filter(severity=filters['severity'])
            
            if filters.get('vulnerability_type'):
                vulnerabilities = vulnerabilities.filter(
                    vulnerability_type=filters['vulnerability_type']
                )
            
            if filters.get('api_method'):
                vulnerabilities = vulnerabilities.filter(api_method=filters['api_method'])
            
            if filters.get('date_from'):
                vulnerabilities = vulnerabilities.filter(
                    discovered_at__gte=filters['date_from']
                )
            
            if filters.get('date_to'):
                vulnerabilities = vulnerabilities.filter(
                    discovered_at__lte=filters['date_to']
                )
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        start = (page - 1) * page_size
        end = start + page_size
        
        total_vulnerabilities = vulnerabilities.count()
        vulnerabilities = vulnerabilities[start:end]
        
        serializer = VulnerabilitySerializerTC3(vulnerabilities, many=True)
        
        return Response({
            'scan_id': scan.scan_id,
            'scan_status': scan.status,
            'total_vulnerabilities': total_vulnerabilities,
            'page': page,
            'page_size': page_size,
            'results': serializer.data
        })

class VulnerabilitySummaryAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id=None):
        if scan_id:
            # Summary for specific scan
            try:
                scan = ScanTC3.objects.get(scan_id=scan_id)
                vulnerabilities = scan.vulnerabilities.all()
            except ScanTC3.DoesNotExist:
                return Response(
                    {'error': 'Scan not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Overall summary across all scans
            vulnerabilities = VulnerabilityTC3.objects.all()
        
        # Count by severity
        severity_counts = vulnerabilities.values('severity').annotate(
            count=Count('severity')
        )
        
        counts = {
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        
        for item in severity_counts:
            key = f"{item['severity'].lower()}_count"
            counts[key] = item['count']
        
        # Count by vulnerability type
        type_counts = {}
        for vuln_type in vulnerabilities.values_list('vulnerability_type', flat=True).distinct():
            type_counts[vuln_type] = vulnerabilities.filter(vulnerability_type=vuln_type).count()
        
        # Recent vulnerabilities (last 7 days)
        recent_date = timezone.now() - timedelta(days=7)
        recent_vulnerabilities = vulnerabilities.filter(
            discovered_at__gte=recent_date
        ).order_by('-discovered_at')[:10]
        
        summary_data = {
            'total_vulnerabilities': vulnerabilities.count(),
            'vulnerability_types': type_counts,
            'recent_vulnerabilities': VulnerabilitySerializerTC3(recent_vulnerabilities, many=True).data,
            **counts
        }
        
        serializer = VulnerabilitySummarySerializerTC3(data=summary_data)
        serializer.is_valid()
        
        return Response(serializer.data)

class ScanStatsAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(scan_id=scan_id)
            stats = scan.stats
            
            serializer = ScanStatsSerializerTC3(stats)
            return Response({
                'scan_id': scan.scan_id,
                'scan_status': scan.status,
                'stats': serializer.data
            })
            
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except ScanStatsTC3.DoesNotExist:
            return Response(
                {'error': 'Scan statistics not available'},
                status=status.HTTP_404_NOT_FOUND
            )

class ScanHistoryAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(scan_id=scan_id)
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        history = scan.history.all().order_by('-tested_at')
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size
        
        total_records = history.count()
        history = history[start:end]
        
        serializer = ScanHistorySerializerTC3(history, many=True)
        
        return Response({
            'scan_id': scan.scan_id,
            'total_records': total_records,
            'page': page,
            'page_size': page_size,
            'results': serializer.data
        })

class AllScansAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Filter by status if provided
        status_filter = request.query_params.get('status')
        scans = ScanTC3.objects.all()
        
        if status_filter:
            scans = scans.filter(status=status_filter.upper())
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        start = (page - 1) * page_size
        end = start + page_size
        
        total_scans = scans.count()
        scans = scans[start:end]
        
        serializer = ScanSummarySerializerTC3(scans, many=True)
        
        return Response({
            'total_scans': total_scans,
            'page': page,
            'page_size': page_size,
            'results': serializer.data
        })

class VulnerabilityDetailAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, vulnerability_id):
        try:
            vulnerability = VulnerabilityTC3.objects.get(id=vulnerability_id)
            serializer = VulnerabilitySerializerTC3(vulnerability)
            return Response(serializer.data)
            
        except VulnerabilityTC3.DoesNotExist:
            return Response(
                {'error': 'Vulnerability not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class DeleteScanAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(scan_id=scan_id)
            
            # Only allow deletion of completed or failed scans
            if scan.status in ['RUNNING', 'PENDING']:
                return Response(
                    {'error': 'Cannot delete running or pending scan'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            scan.delete()
            return Response({
                'message': 'Scan deleted successfully',
                'scan_id': scan_id
            })
            
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class CancelScanAPIViewTC3(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(scan_id=scan_id)
            
            if scan.status not in ['RUNNING', 'PENDING']:
                return Response(
                    {'error': 'Can only cancel running or pending scans'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            scan.status = 'CANCELLED'
            scan.completed_at = timezone.now()
            scan.save()
            
            return Response({
                'message': 'Scan cancelled successfully',
                'scan_id': scan_id,
                'status': scan.status
            })
            
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
