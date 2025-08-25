# views.py
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.renderers import JSONRenderer
from rest_framework_csv.renderers import CSVRenderer
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator
from django.db.models import Q, Avg
from django.utils import timezone
from django.http import HttpResponse
import csv
import io
from .models import (
    VulnerabilityScanTC1, VulnerabilityTestTC1, 
    MassAccountTestResultTC1, ScanStatsTC1
)
from .serializers import (
    ScanStartRequestSerializerTC1, VulnerabilityScanSerializerTC1,
    VulnerabilityScanListSerializerTC1, VulnerabilityTestSerializerTC1,
    VulnerabilityTestFilterSerializerTC1, VulnerabilitySummarySerializerTC1,
    ScanHistorySerializerTC1, ScanStatsSerializerTC1
)
from .services import VulnerabilityTestServiceTC1, ScanManagementServiceTC1
from .tasks import run_vulnerability_scan_task


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
                status=status.HTTP_404_NOT_FOUND
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
                    status=status.HTTP_404_NOT_FOUND if stats_data['error'] == 'Scan not found' 
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