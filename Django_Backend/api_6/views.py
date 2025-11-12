# views.py
from rest_framework import status, generics
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.renderers import JSONRenderer
from rest_framework_csv.renderers import CSVRenderer
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator
from django.db.models import Q, Avg, Count
from django.utils import timezone
from django.http import HttpResponse
from django.http import JsonResponse
from datetime import datetime, timedelta
from typing import Dict, Any
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from threading import Thread
from rest_framework import filters
import csv
import io
import asyncio
from .models import (
    VulnerabilityScanTC1, VulnerabilityTestTC1, 
    MassAccountTestResultTC1, ScanStatsTC1,
    ScanTC3, VulnerabilityTC3, 
    ScanResultTC3, ScanConfigTC3, 
    CouponTestCaseTC3
)
from .serializers import (
    ScanStartRequestSerializerTC1, VulnerabilityScanSerializerTC1,
    VulnerabilityScanListSerializerTC1, VulnerabilityTestSerializerTC1,
    VulnerabilityTestFilterSerializerTC1, VulnerabilitySummarySerializerTC1,
    ScanHistorySerializerTC1, ScanStatsSerializerTC1,
    ScanTC3ListSerializer, ScanTC3DetailSerializer, 
    ScanCreateTC3Serializer, VulnerabilityTC3Serializer, 
    ScanResultTC3Serializer, VulnerabilitySummaryTC3Serializer,
    ScanStatsTC3Serializer, ScanHistoryTC3Serializer, 
    CouponTestCaseTC3Serializer
)
from .services import VulnerabilityTestServiceTC1, ScanManagementServiceTC1, CouponBruteForceServiceTC3, APIOrchServiceTC3
from .tasks import run_vulnerability_scan_task
import logging


logger = logging.getLogger(__name__)


class VulnerabilityScanStartTC1(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ScanStartRequestSerializerTC1(data=request.data)
        if serializer.is_valid():
            try:
                scan_id = serializer.validated_data['scan_id']

                # Prevent duplicate scans
                if VulnerabilityScanTC1.objects.filter(scan_id=scan_id).exists():
                    return Response(
                        {'error': 'Scan already exists for this scan_id'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Create the scan record in "pending" state
                scan = VulnerabilityScanTC1.objects.create(
                    scan_id=scan_id,
                    name=serializer.validated_data.get('scan_name', f'Scan {scan_id}'),
                    status='pending'
                )

                # Trigger Celery task
                run_vulnerability_scan_task.delay(
                    scan_id,
                    serializer.validated_data.get('test_types'),
                    max_accounts_per_api=serializer.validated_data.get('max_accounts_per_api'),
                    timeout_seconds=serializer.validated_data.get('timeout_seconds')
                )

                # Return scan info immediately
                response_serializer = VulnerabilityScanSerializerTC1(scan)
                return Response(response_serializer.data, status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response(
                    {'error': f'Failed to start scan: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VulnerabilityScanStatusTC1(APIView):
    """Get status of a vulnerability scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = get_object_or_404(VulnerabilityScanTC1, scan_id=scan_id)
            serializer = VulnerabilityScanSerializerTC1(scan)
            return Response(serializer.data)
        except Exception as e:
            return Response(
                {'error': 'Scan not found'}, 
                status=status.HTTP_200_OK
            )


class VulnerabilityScanStopTC1(APIView):
    """Stop a running vulnerability scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, scan_id):
        try:
            scan = get_object_or_404(VulnerabilityScanTC1, scan_id=scan_id)
            
            if scan.status not in ['pending', 'running']:
                return Response(
                    {'error': 'Scan is not active'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            scan.status = 'cancelled'
            scan.completed_at = timezone.now()
            scan.save()
            
            serializer = VulnerabilityScanSerializerTC1(scan)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {'error': 'Failed to stop scan'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# views.py (only showing the updated VulnerabilitySummaryTC1 view)
class VulnerabilitySummaryTC1(APIView):
    """Get overall vulnerability summary"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            service = ScanManagementServiceTC1()
            summary = service.get_vulnerability_summary()
            
            # Convert recent scans to proper format
            recent_scans_data = []
            for scan in summary.get('recent_scans', []):
                recent_scans_data.append({
                    'id': scan['id'],
                    'scan_id': scan['scan_id'],
                    'name': scan['name'],
                    'status': scan['status'],
                    'created_at': scan['created_at']
                })
            
            response_data = {
                'total_scans': summary['total_scans'],
                'active_scans': summary['active_scans'],
                'completed_scans': summary['completed_scans'],
                'failed_scans': summary['failed_scans'],
                'total_tests': summary['total_tests'],
                'vulnerable_tests': summary['vulnerable_tests'],
                'total_vulnerabilities': summary['total_vulnerabilities'],
                'vulnerabilities_by_severity': summary['vulnerabilities_by_severity'],
                'vulnerabilities_by_type': summary['vulnerabilities_by_type'],
                'top_vulnerable_apis': summary['top_vulnerable_apis'],
                'recent_scans': recent_scans_data
            }
            
            return Response(response_data)
            
        except Exception as e:
            print(f"Error in VulnerabilitySummaryTC1: {str(e)}")
            return Response(
                {'error': 'Failed to fetch summary', 'details': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanResultsFilteredTC1(APIView):
    """Get filtered scan results"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        filter_serializer = VulnerabilityTestFilterSerializerTC1(data=request.query_params)
        if filter_serializer.is_valid():
            try:
                # Build query based on filters
                queryset = VulnerabilityTestTC1.objects.all()
                
                if scan_id := filter_serializer.validated_data.get('scan_id'):
                    queryset = queryset.filter(scan_id=scan_id)
                
                if test_type := filter_serializer.validated_data.get('test_type'):
                    queryset = queryset.filter(test_type=test_type)
                
                if status_filter := filter_serializer.validated_data.get('status'):
                    queryset = queryset.filter(status=status_filter)
                
                if severity := filter_serializer.validated_data.get('severity'):
                    queryset = queryset.filter(severity=severity)
                
                if is_vulnerable := filter_serializer.validated_data.get('is_vulnerable'):
                    queryset = queryset.filter(is_vulnerable=is_vulnerable)
                
                if api_method := filter_serializer.validated_data.get('api_method'):
                    queryset = queryset.filter(api_method=api_method)
                
                if date_from := filter_serializer.validated_data.get('date_from'):
                    queryset = queryset.filter(created_at__gte=date_from)
                
                if date_to := filter_serializer.validated_data.get('date_to'):
                    queryset = queryset.filter(created_at__lte=date_to)
                
                queryset = queryset.order_by('-created_at')
                
                # Pagination
                page = int(request.query_params.get('page', 1))
                page_size = min(int(request.query_params.get('page_size', 20)), 100)
                
                paginator = Paginator(queryset, page_size)
                page_obj = paginator.get_page(page)
                
                serializer = VulnerabilityTestSerializerTC1(page_obj.object_list, many=True)
                
                return Response({
                    'results': serializer.data,
                    'total_count': paginator.count,
                    'total_pages': paginator.num_pages,
                    'current_page': page,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous(),
                })
                
            except Exception as e:
                print(f"Error in ScanResultsFilteredTC1: {str(e)}")
                return Response(
                    {'error': 'Failed to fetch results', 'details': str(e)}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            return Response(
                filter_serializer.errors, 
                status=status.HTTP_400_BAD_REQUEST
            )


class ScanStatsTC1(APIView):
    """Get scan statistics"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            service = ScanManagementServiceTC1()
            stats_data = service.get_scan_stats(scan_id)
            
            if 'error' in stats_data:
                return Response(
                    {'error': stats_data['error']}, 
                    status=status.HTTP_200_OK if stats_data['error'] == 'Scan not found' 
                    else status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            return Response(stats_data)
                
        except Exception as e:
            return Response(
                {'error': 'Failed to get scan statistics', 'details': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanHistoryTC1(APIView):
    """Get paginated scan history"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        filter_serializer = ScanHistorySerializerTC1(data=request.query_params)
        if filter_serializer.is_valid():
            try:
                service = ScanManagementServiceTC1()
                history = service.get_scan_history(**filter_serializer.validated_data)
                
                serializer = VulnerabilityScanListSerializerTC1(history['results'], many=True)
                
                return Response({
                    'results': serializer.data,
                    'total_count': history['total_count'],
                    'total_pages': history['total_pages'],
                    'current_page': history['current_page'],
                    'has_next': history['has_next'],
                    'has_previous': history['has_previous'],
                })
                
            except Exception as e:
                return Response(
                    {'error': 'Failed to fetch history', 'details': str(e)}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            return Response(
                filter_serializer.errors, 
                status=status.HTTP_400_BAD_REQUEST
            )


class VulnerabilityTestDetailTC1(APIView):
    """Get detailed vulnerability test results"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, test_id):
        try:
            test = get_object_or_404(VulnerabilityTestTC1, id=test_id)
            serializer = VulnerabilityTestSerializerTC1(test)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {'error': 'Test not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


class ScanListTC1(APIView):
    """List all scans with basic info"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            # Query parameters
            status_filter = request.query_params.get('status')
            page = int(request.query_params.get('page', 1))
            page_size = min(int(request.query_params.get('page_size', 20)), 100)
            
            # Build queryset
            queryset = VulnerabilityScanTC1.objects.all()
            
            if status_filter:
                queryset = queryset.filter(status=status_filter)
            
            queryset = queryset.order_by('-created_at')
            
            # Paginate
            paginator = Paginator(queryset, page_size)
            page_obj = paginator.get_page(page)
            
            serializer = VulnerabilityScanListSerializerTC1(page_obj.object_list, many=True)
            
            return Response({
                'results': serializer.data,
                'total_count': paginator.count,
                'total_pages': paginator.num_pages,
                'current_page': page,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous(),
            })
            
        except Exception as e:
            return Response(
                {'error': 'Failed to fetch scans'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VulnerabilityExportTC1(APIView):
    """Export vulnerability results"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    renderer_classes = [JSONRenderer, CSVRenderer]
    
    def get(self, request, scan_id):
        try:
            print(f"Export request received for scan_id: {scan_id}, format: {request.query_params.get('format')}")
            
            # Check if scan exists
            try:
                scan = VulnerabilityScanTC1.objects.get(scan_id=scan_id)
                print(f"Scan found: {scan.id}, status: {scan.status}")
            except VulnerabilityScanTC1.DoesNotExist:
                print(f"Scan {scan_id} not found in database")
                return Response(
                    {'error': f'Scan with ID {scan_id} not found'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check if scan has any tests
            test_count = scan.tests.count()
            print(f"Scan has {test_count} tests")
            
            if test_count == 0:
                return Response(
                    {'error': f'Scan {scan_id} has no test results to export'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            export_format = request.query_params.get('format', 'json')
            print(f"Export format: {export_format}")
            
            if export_format == 'csv':
                print("Generating CSV export...")
                return self._export_csv(scan)
            elif export_format == 'json':
                print("Generating JSON export...")
                serializer = VulnerabilityScanSerializerTC1(scan)
                response = Response(serializer.data)
                response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}_results.json"'
                response['Content-Type'] = 'application/json'
                return response
            else:
                return Response(
                    {'error': 'Unsupported format. Use "json" or "csv".'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            print(f"Export failed with error: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response(
                {'error': 'Export failed', 'details': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _export_csv(self, scan):
        """Export results as CSV"""
        print(f"Creating CSV for scan {scan.scan_id} with {scan.tests.count()} tests")
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="scan_{scan.scan_id}_results.csv"'
        
        writer = csv.writer(response)
        
        # Write header row
        writer.writerow([
            'API Name', 'API URL', 'HTTP Method', 'Test Type', 
            'Status', 'Severity', 'Is Vulnerable', 
            'Execution Time (ms)', 'Started At', 'Completed At',
            'Error Message'
        ])
        
        # Write data rows
        for test in scan.tests.all():
            print(f"Adding test to CSV: {test.api_name}")
            writer.writerow([
                test.api_name or '',
                test.api_url or '',
                test.api_method or '',
                test.test_type or '',
                test.status or '',
                test.severity or '',
                'Yes' if test.is_vulnerable else 'No',
                test.execution_time_ms or '',
                test.started_at.isoformat() if test.started_at else '',
                test.completed_at.isoformat() if test.completed_at else '',
                test.error_message or ''
            ])
        
        print("CSV export completed successfully")
        return response


class ScanReportsTC1(APIView):
    """Generate scan reports"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = get_object_or_404(VulnerabilityScanTC1, scan_id=scan_id)
            
            # Generate comprehensive report
            report = {
                'scan_info': {
                    'id': str(scan.id),
                    'scan_id': scan.scan_id,
                    'name': scan.name,
                    'status': scan.status,
                    'started_at': scan.started_at,
                    'completed_at': scan.completed_at,
                    'duration_minutes': self._calculate_duration(scan),
                    'total_apis': scan.total_apis,
                    'tested_apis': scan.tested_apis,
                    'vulnerabilities_found': scan.vulnerabilities_found
                },
                'executive_summary': self._generate_executive_summary(scan),
                'vulnerability_breakdown': self._generate_vulnerability_breakdown(scan),
                'detailed_findings': self._generate_detailed_findings(scan),
                'recommendations': self._generate_recommendations(scan)
            }
            
            return Response(report)
            
        except Exception as e:
            return Response(
                {'error': 'Report generation failed'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _calculate_duration(self, scan):
        """Calculate scan duration in minutes"""
        if scan.completed_at and scan.started_at:
            delta = scan.completed_at - scan.started_at
            return round(delta.total_seconds() / 60, 2)
        return None
    
    def _generate_executive_summary(self, scan):
        """Generate executive summary"""
        vulnerable_tests = scan.tests.filter(is_vulnerable=True)
        
        summary = {
            'total_vulnerabilities': vulnerable_tests.count(),
            'risk_level': 'Low',
            'key_findings': [],
            'impact_assessment': ''
        }
        
        # Determine risk level based on vulnerabilities
        critical_count = vulnerable_tests.filter(severity='critical').count()
        high_count = vulnerable_tests.filter(severity='high').count()
        medium_count = vulnerable_tests.filter(severity='medium').count()
        
        if critical_count > 0:
            summary['risk_level'] = 'Critical'
        elif high_count > 0:
            summary['risk_level'] = 'High'
        elif medium_count > 0:
            summary['risk_level'] = 'Medium'
        
        # Key findings
        mass_account_vulns = vulnerable_tests.filter(test_type='mass_account_creation')
        if mass_account_vulns.exists():
            summary['key_findings'].append({
                'type': 'Mass Account Creation',
                'count': mass_account_vulns.count(),
                'severity': 'High'
            })
        
        return summary
    
    def _generate_vulnerability_breakdown(self, scan):
        """Generate vulnerability breakdown by type and severity"""
        tests = scan.tests.filter(is_vulnerable=True)
        
        breakdown = {
            'by_severity': {
                'critical': tests.filter(severity='critical').count(),
                'high': tests.filter(severity='high').count(),
                'medium': tests.filter(severity='medium').count(),
                'low': tests.filter(severity='low').count(),
                'info': tests.filter(severity='info').count(),
            },
            'by_type': {}
        }
        
        # Count by test type
        test_types = tests.values_list('test_type', flat=True).distinct()
        for test_type in test_types:
            breakdown['by_type'][test_type] = tests.filter(test_type=test_type).count()
        
        return breakdown
    
    def _generate_detailed_findings(self, scan):
        """Generate detailed findings"""
        findings = []
        
        vulnerable_tests = scan.tests.filter(is_vulnerable=True).order_by('-severity')
        
        for test in vulnerable_tests:
            finding = {
                'id': str(test.id),
                'api_name': test.api_name,
                'api_url': test.api_url,
                'test_type': test.test_type,
                'severity': test.severity,
                'description': test.test_description,
                'evidence': self._format_evidence(test),
                'remediation': self._get_remediation_advice(test.test_type)
            }
            findings.append(finding)
        
        return findings
    
    def _format_evidence(self, test):
        """Format evidence for the finding"""
        evidence = []
        
        if hasattr(test, 'mass_account_result'):
            result = test.mass_account_result
            evidence.append(f"Successfully created {result.successful_accounts} accounts")
            if not result.has_rate_limiting:
                evidence.append("No rate limiting detected")
            if not result.has_email_verification:
                evidence.append("No email verification required")
        
        return evidence
    
    def _get_remediation_advice(self, test_type):
        """Get remediation advice for test type"""
        remediation_map = {
            'mass_account_creation': [
                "Implement rate limiting per IP address",
                "Add email verification requirement",
                "Implement CAPTCHA for account creation",
                "Add device fingerprinting",
                "Monitor for bulk account creation patterns"
            ]
        }
        
        return remediation_map.get(test_type, ["Review security controls for this endpoint"])
    
    def _generate_recommendations(self, scan):
        """Generate general recommendations"""
        return [
            "Implement comprehensive rate limiting across all endpoints",
            "Add multi-factor authentication for sensitive operations",
            "Regular security testing and vulnerability assessments",
            "Monitor API usage patterns for anomalies",
            "Implement proper input validation and sanitization"
        ]


class StandardResultsSetPaginationTC3(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class ScanCreateTC3View(APIView):
    """Create and start a new security scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ScanCreateTC3Serializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan_id = serializer.validated_data['scan_id']
        
        # Check if scan already exists and is running
        existing_scan = ScanTC3.objects.filter(
            scan_id=scan_id,
            status__in=['pending', 'in_progress']
        ).first()
        
        if existing_scan:
            return Response(
                {'error': f'Scan {scan_id} is already running'},
                status=status.HTTP_409_CONFLICT
            )
        
        try:
            # Get APIs and token from api_orch
            apis = APIOrchServiceTC3.get_apis_by_scan_id(scan_id)
            access_token = APIOrchServiceTC3.get_access_token_by_scan_id(scan_id)
            
            if not apis:
                return Response(
                    {'error': f'No APIs found for scan_id {scan_id}'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Create scan record
            scan = ScanTC3.objects.create(
                scan_id=scan_id,
                user=request.user,
                total_apis=len(apis)
            )
            
            # Create scan config
            config = ScanConfigTC3.objects.create(
                scan=scan,
                max_requests_per_second=serializer.validated_data.get('max_requests_per_second', 2),
                timeout_seconds=serializer.validated_data.get('timeout_seconds', 30),
                retry_attempts=serializer.validated_data.get('retry_attempts', 3),
                enable_ai_analysis=serializer.validated_data.get('enable_ai_analysis', True),
                ai_model=serializer.validated_data.get('ai_model', 'gpt-4o-mini'),
                custom_wordlist=serializer.validated_data.get('custom_wordlist', []),
                excluded_endpoints=serializer.validated_data.get('excluded_endpoints', [])
            )
            
            # Start scan in background
            def run_scan():
                try:
                    service = CouponBruteForceServiceTC3()
                    asyncio.run(service.execute_scan(str(scan.id), apis, access_token, config))
                except Exception as e:
                    logger.error(f"Scan execution failed: {str(e)}")
                    scan.status = 'failed'
                    scan.save()
            
            scan_thread = Thread(target=run_scan)
            scan_thread.daemon = True
            scan_thread.start()
            
            return Response({
                'message': 'Scan started successfully',
                'scan_id': str(scan.id),
                'total_apis': len(apis),
                'status': 'pending'
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Failed to start scan: {str(e)}")
            return Response(
                {'error': 'Failed to start scan', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanListTC3View(APIView):
    """List all scans with pagination and filtering"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPaginationTC3
    
    def get(self, request):
        queryset = ScanTC3.objects.all()
        
        # Apply filters
        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        scan_id_filter = request.query_params.get('scan_id')
        if scan_id_filter:
            queryset = queryset.filter(scan_id=scan_id_filter)
        
        # Pagination
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)
        
        serializer = ScanTC3ListSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class ScanDetailTC3View(APIView):
    """Get detailed information about a specific scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(id=scan_id)
            serializer = ScanTC3DetailSerializer(scan)
            return Response(serializer.data)
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ScanStatusTC3View(APIView):
    """Get current status of a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(id=scan_id)
            
            data = {
                'scan_id': str(scan.id),
                'status': scan.status,
                'progress_percentage': (scan.processed_apis / scan.total_apis * 100) if scan.total_apis > 0 else 0,
                'processed_apis': scan.processed_apis,
                'total_apis': scan.total_apis,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'start_time': scan.start_time,
                'estimated_completion': self._calculate_eta(scan) if scan.status == 'in_progress' else None
            }
            
            return Response(data)
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def _calculate_eta(self, scan):
        """Calculate estimated time of completion"""
        if not scan.start_time or scan.processed_apis == 0:
            return None
        
        elapsed_time = (timezone.now() - scan.start_time).total_seconds()
        avg_time_per_api = elapsed_time / scan.processed_apis
        remaining_apis = scan.total_apis - scan.processed_apis
        eta_seconds = remaining_apis * avg_time_per_api
        
        return timezone.now() + timezone.timedelta(seconds=eta_seconds)


class VulnerabilityListTC3View(APIView):
    """List vulnerabilities with filtering and pagination"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPaginationTC3
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['severity', 'vulnerability_type', 'scan']
    search_fields = ['title', 'description', 'api_name']
    ordering_fields = ['created_at', 'severity', 'confidence_score']
    
    def get(self, request):
        queryset = VulnerabilityTC3.objects.all()
        
        # Apply filters
        severity = request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        vulnerability_type = request.query_params.get('vulnerability_type')
        if vulnerability_type:
            queryset = queryset.filter(vulnerability_type=vulnerability_type)
        
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(scan__id=scan_id)
        
        # Search
        search = request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(description__icontains=search) |
                Q(api_name__icontains=search)
            )
        
        # Ordering
        ordering = request.query_params.get('ordering', '-created_at')
        queryset = queryset.order_by(ordering)
        
        # Pagination
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)
        
        serializer = VulnerabilityTC3Serializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class VulnerabilitySummaryTC3View(APIView):
    """Get vulnerability summary for a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(id=scan_id)
            vulnerabilities = scan.vulnerabilities.all()
            
            # Count by severity
            severity_counts = vulnerabilities.values('severity').annotate(count=Count('id'))
            severity_dict = {item['severity']: item['count'] for item in severity_counts}
            
            # Count by type
            type_counts = vulnerabilities.values('vulnerability_type').annotate(count=Count('id'))
            type_dict = {item['vulnerability_type']: item['count'] for item in type_counts}
            
            # Most common vulnerability
            most_common = vulnerabilities.values('vulnerability_type').annotate(
                count=Count('id')
            ).order_by('-count').first()
            
            # Risk score calculation (weighted by severity)
            risk_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
            risk_score = sum(
                severity_dict.get(severity, 0) * weight 
                for severity, weight in risk_weights.items()
            ) / max(len(vulnerabilities), 1)
            
            # Remediation priority (critical and high severity first)
            priority_vulns = vulnerabilities.filter(
                severity__in=['critical', 'high']
            ).order_by('severity', '-confidence_score')[:5]
            
            data = {
                'scan_id': scan.id,
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': severity_dict.get('critical', 0),
                'high_count': severity_dict.get('high', 0),
                'medium_count': severity_dict.get('medium', 0),
                'low_count': severity_dict.get('low', 0),
                'info_count': severity_dict.get('info', 0),
                'vulnerability_types': type_dict,
                'most_common_vulnerability': most_common['vulnerability_type'] if most_common else None,
                'risk_score': round(risk_score, 2),
                'remediation_priority': [
                    {
                        'title': v.title,
                        'severity': v.severity,
                        'api_name': v.api_name,
                        'confidence_score': v.confidence_score
                    } for v in priority_vulns
                ]
            }
            
            serializer = VulnerabilitySummaryTC3Serializer(data)
            return Response(serializer.data)
            
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ScanResultsTC3View(APIView):
    """List scan results with filtering"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPaginationTC3
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(id=scan_id)
            queryset = scan.results.all()
            
            # Apply filters
            test_type = request.query_params.get('test_type')
            if test_type:
                queryset = queryset.filter(test_type=test_type)
            
            status_filter = request.query_params.get('status')
            if status_filter:
                queryset = queryset.filter(status=status_filter)
            
            api_name = request.query_params.get('api_name')
            if api_name:
                queryset = queryset.filter(api_name__icontains=api_name)
            
            # Ordering
            ordering = request.query_params.get('ordering', '-tested_at')
            queryset = queryset.order_by(ordering)
            
            # Pagination
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            
            serializer = ScanResultTC3Serializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)
            
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ScanStatsTC3View(APIView):
    """Get overall scanning statistics"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Basic counts
        total_scans = ScanTC3.objects.count()
        active_scans = ScanTC3.objects.filter(status__in=['pending', 'in_progress']).count()
        completed_scans = ScanTC3.objects.filter(status='completed').count()
        failed_scans = ScanTC3.objects.filter(status='failed').count()
        
        # Vulnerability statistics
        total_vulnerabilities = VulnerabilityTC3.objects.count()
        avg_vulnerabilities_per_scan = VulnerabilityTC3.objects.values('scan').annotate(
            count=Count('id')
        ).aggregate(avg=Avg('count'))['avg'] or 0
        
        # Most vulnerable APIs
        most_vulnerable_apis = VulnerabilityTC3.objects.values('api_name').annotate(
            vulnerability_count=Count('id')
        ).order_by('-vulnerability_count')[:10]
        
        # Success rate
        scan_success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
        
        # Average scan duration
        completed_scans_with_duration = ScanTC3.objects.filter(
            status='completed',
            start_time__isnull=False,
            end_time__isnull=False
        )
        
        avg_scan_duration = 0
        if completed_scans_with_duration.exists():
            durations = []
            for scan in completed_scans_with_duration:
                duration = (scan.end_time - scan.start_time).total_seconds()
                durations.append(duration)
            avg_scan_duration = sum(durations) / len(durations)
        
        data = {
            'total_scans': total_scans,
            'active_scans': active_scans,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'avg_vulnerabilities_per_scan': round(avg_vulnerabilities_per_scan, 2),
            'most_vulnerable_apis': list(most_vulnerable_apis),
            'scan_success_rate': round(scan_success_rate, 2),
            'avg_scan_duration': round(avg_scan_duration, 2)
        }
        
        serializer = ScanStatsTC3Serializer(data)
        return Response(serializer.data)


class ScanHistoryTC3View(APIView):
    """Get scan history with filtering"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPaginationTC3
    
    def get(self, request):
        queryset = ScanTC3.objects.all()
        
        # Date range filtering
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            queryset = queryset.filter(created_at__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__lte=end_date)
        
        # Status filtering
        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # User filtering
        user_id = request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Ordering
        queryset = queryset.order_by('-created_at')
        
        # Pagination
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)
        
        serializer = ScanHistoryTC3Serializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class ScanCancelTC3View(APIView):
    """Cancel a running scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(id=scan_id)
            
            if scan.status not in ['pending', 'in_progress']:
                return Response(
                    {'error': 'Scan cannot be cancelled in current status'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            scan.status = 'cancelled'
            scan.end_time = timezone.now()
            scan.save()
            
            return Response({
                'message': 'Scan cancelled successfully',
                'scan_id': str(scan.id)
            })
            
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class VulnerabilityDetailTC3View(APIView):
    """Get detailed information about a specific vulnerability"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, vulnerability_id):
        try:
            vulnerability = VulnerabilityTC3.objects.get(id=vulnerability_id)
            serializer = VulnerabilityTC3Serializer(vulnerability)
            return Response(serializer.data)
        except VulnerabilityTC3.DoesNotExist:
            return Response(
                {'error': 'Vulnerability not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class CouponTestCaseTC3View(APIView):
    """Manage coupon test cases"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """List all active test cases"""
        test_cases = CouponTestCaseTC3.objects.filter(is_active=True)
        serializer = CouponTestCaseTC3Serializer(test_cases, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """Create a new test case"""
        serializer = CouponTestCaseTC3Serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanReportTC3View(APIView):
    """Generate comprehensive scan report"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan = ScanTC3.objects.get(id=scan_id)
            
            # Get all vulnerabilities grouped by severity
            vulnerabilities = scan.vulnerabilities.all()
            vuln_by_severity = {}
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                vuln_by_severity[severity] = vulnerabilities.filter(severity=severity)
            
            # Get scan results summary
            results = scan.results.all()
            results_summary = {
                'total_tests': results.count(),
                'successful_tests': results.filter(status='success').count(),
                'failed_tests': results.filter(status='failed').count(),
                'error_tests': results.filter(status='error').count(),
            }
            
            # Calculate risk metrics
            risk_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
            total_risk_score = sum(
                vuln_by_severity[severity].count() * weight
                for severity, weight in risk_weights.items()
            )
            
            # OWASP API Top 10 mapping
            owasp_mapping = {}
            for vuln in vulnerabilities:
                category = vuln.owasp_category
                if category:
                    if category not in owasp_mapping:
                        owasp_mapping[category] = []
                    owasp_mapping[category].append({
                        'title': vuln.title,
                        'severity': vuln.severity,
                        'api_name': vuln.api_name
                    })
            
            # Executive summary
            exec_summary = {
                'scan_overview': {
                    'scan_id': str(scan.id),
                    'scan_date': scan.created_at,
                    'duration': (scan.end_time - scan.start_time).total_seconds() if scan.end_time and scan.start_time else None,
                    'status': scan.status,
                    'apis_tested': scan.total_apis,
                    'total_vulnerabilities': vulnerabilities.count()
                },
                'risk_assessment': {
                    'overall_risk_score': total_risk_score,
                    'risk_level': self._calculate_risk_level(total_risk_score),
                    'critical_issues': vuln_by_severity['critical'].count(),
                    'high_issues': vuln_by_severity['high'].count(),
                    'immediate_action_required': vuln_by_severity['critical'].count() > 0 or vuln_by_severity['high'].count() > 5
                },
                'key_findings': [
                    {
                        'title': vuln.title,
                        'severity': vuln.severity,
                        'api_name': vuln.api_name,
                        'impact': vuln.impact[:200] + '...' if len(vuln.impact) > 200 else vuln.impact
                    }
                    for vuln in vulnerabilities.filter(severity__in=['critical', 'high']).order_by('-confidence_score')[:10]
                ]
            }
            
            report_data = {
                'executive_summary': exec_summary,
                'vulnerability_breakdown': {
                    severity: [
                        VulnerabilityTC3Serializer(vuln).data
                        for vuln in vuln_list
                    ]
                    for severity, vuln_list in vuln_by_severity.items()
                },
                'owasp_api_top_10_mapping': owasp_mapping,
                'test_results_summary': results_summary,
                'remediation_roadmap': self._generate_remediation_roadmap(vulnerabilities),
                'compliance_notes': {
                    'pci_dss': 'Review payment-related vulnerabilities for PCI DSS compliance',
                    'gdpr': 'Ensure coupon data handling meets GDPR requirements',
                    'owasp_asvs': 'Address authentication and session management issues'
                },
                'generated_at': timezone.now()
            }
            
            return Response(report_data)
            
        except ScanTC3.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def _calculate_risk_level(self, risk_score):
        """Calculate overall risk level"""
        if risk_score >= 50:
            return 'Critical'
        elif risk_score >= 30:
            return 'High'
        elif risk_score >= 15:
            return 'Medium'
        elif risk_score >= 5:
            return 'Low'
        else:
            return 'Minimal'
    
    def _generate_remediation_roadmap(self, vulnerabilities):
        """Generate prioritized remediation roadmap"""
        priority_mapping = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5
        }
        
        roadmap = []
        for vuln in vulnerabilities.order_by('severity', '-confidence_score'):
            roadmap.append({
                'priority': priority_mapping[vuln.severity],
                'title': vuln.title,
                'severity': vuln.severity,
                'api_affected': vuln.api_name,
                'estimated_effort': self._estimate_effort(vuln.vulnerability_type),
                'remediation_steps': vuln.remediation,
                'business_impact': vuln.impact
            })
        
        return roadmap[:20]  # Top 20 priorities
    
    def _estimate_effort(self, vulnerability_type):
        """Estimate remediation effort"""
        effort_mapping = {
            'coupon_bruteforce': 'Medium (2-4 days)',
            'promo_code_abuse': 'Medium (2-4 days)',
            'rate_limit_bypass': 'Low (1-2 days)',
            'code_reuse': 'High (1-2 weeks)',
            'code_stacking': 'High (1-2 weeks)',
            'weak_validation': 'Medium (3-5 days)'
        }
        return effort_mapping.get(vulnerability_type, 'Medium (2-4 days)')


class HealthCheckTC3View(APIView):
    """Health check endpoint"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'status': 'healthy',
            'service': 'API Security Scanner TC3',
            'version': '1.0.0',
            'timestamp': timezone.now()
        })