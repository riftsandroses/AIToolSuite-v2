from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.http import FileResponse
from django.conf import settings
import os

from .models import (
    SecurityAssessment,
    VulnerableComponent,
    RemediationControl,
    AssessmentHistory
)
from .serializers import (
    SecurityAssessmentListSerializer,
    SecurityAssessmentDetailSerializer,
    SecurityAssessmentCreateSerializer,
    VulnerableComponentSerializer,
    VulnerableComponentUpdateSerializer,
    RemediationControlSerializer,
    AssessmentHistorySerializer
)
from .services import SecurityAnalyzer
from .utils import ExcelReportGenerator


class AssessmentListCreateView(APIView):
    """
    List all assessments or create new assessment
    
    GET /api/assessments/
    POST /api/assessments/
    """
    
    parser_classes = (MultiPartParser, FormParser)
    
    def get(self, request):
        """List all security assessments"""
        assessments = SecurityAssessment.objects.all()
        
        # Filter by status if provided
        status_filter = request.query_params.get('status')
        if status_filter:
            assessments = assessments.filter(status=status_filter)
        
        # Filter by risk score range
        min_score = request.query_params.get('min_score')
        max_score = request.query_params.get('max_score')
        if min_score:
            assessments = assessments.filter(overall_risk_score__gte=int(min_score))
        if max_score:
            assessments = assessments.filter(overall_risk_score__lte=int(max_score))
        
        serializer = SecurityAssessmentListSerializer(assessments, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """Create new security assessment"""
        serializer = SecurityAssessmentCreateSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get architecture file
        architecture_file = request.FILES.get('architecture_diagram')
        if not architecture_file:
            return Response(
                {'error': 'Architecture diagram is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            with transaction.atomic():
                # Create assessment
                assessment = serializer.save(status='processing')
                
                # Prepare data for analysis
                assessment_data = {
                    'id': str(assessment.id),
                    **serializer.validated_data
                }
                
                # Remove file fields from dict for context building
                assessment_data.pop('architecture_diagram', None)
                assessment_data.pop('high_level_architecture', None)
                assessment_data.pop('logical_architecture', None)
                assessment_data.pop('physical_architecture', None)
                assessment_data.pop('data_flow_diagrams', None)
                
                print(f"Starting analysis for assessment {assessment.id}")
                print(f"Architecture file: {architecture_file.name}, size: {architecture_file.size} bytes")
                
                # Perform AI analysis
                analyzer = SecurityAnalyzer()
                risk_score, reasoning, vulnerabilities = analyzer.analyze_security(
                    assessment_data,
                    architecture_file
                )
                
                print(f"Analysis complete. Risk score: {risk_score}")
                
                # Update assessment with results
                assessment.overall_risk_score = risk_score
                assessment.risk_reasoning = reasoning
                assessment.status = 'completed'
                assessment.save()
                
                # Create vulnerability records
                for vuln_data in vulnerabilities:
                    VulnerableComponent.objects.create(
                        assessment=assessment,
                        **vuln_data
                    )
                
                print(f"Created {len(vulnerabilities)} vulnerability records")
                
                # Create initial history entry
                AssessmentHistory.objects.create(
                    assessment=assessment,
                    previous_score=None,
                    new_score=risk_score,
                    change_reason="Initial assessment completed"
                )
            
            # Return complete assessment
            result_serializer = SecurityAssessmentDetailSerializer(assessment)
            return Response(
                result_serializer.data,
                status=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            # Update status to failed
            if 'assessment' in locals():
                assessment.status = 'failed'
                assessment.save()
            
            import traceback
            error_details = f"{str(e)}\n\nTraceback:\n{traceback.format_exc()}"
            print(f"Assessment failed: {error_details}")
            
            return Response(
                {'error': 'Assessment failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AssessmentDetailView(APIView):
    """
    Retrieve, update or delete a security assessment
    
    GET /api/assessments/{id}/
    PATCH /api/assessments/{id}/
    DELETE /api/assessments/{id}/
    """
    
    def get(self, request, pk):
        """Get detailed assessment information"""
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        serializer = SecurityAssessmentDetailSerializer(assessment)
        return Response(serializer.data)
    
    def patch(self, request, pk):
        """Update assessment metadata (not risk score)"""
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        
        # Only allow updating certain fields
        allowed_fields = [
            'application_purpose', 'business_objectives', 'stakeholders',
            'system_owners', 'compliance_requirements'
        ]
        
        update_data = {k: v for k, v in request.data.items() if k in allowed_fields}
        
        for field, value in update_data.items():
            setattr(assessment, field, value)
        
        assessment.save()
        
        serializer = SecurityAssessmentDetailSerializer(assessment)
        return Response(serializer.data)
    
    def delete(self, request, pk):
        """Delete assessment"""
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        assessment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AssessmentReportView(APIView):
    """
    Generate and download Excel report
    
    GET /api/assessments/{id}/report/
    """
    
    def get(self, request, pk):
        """Generate and download Excel report"""
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        
        # Prepare data
        assessment_data = SecurityAssessmentDetailSerializer(assessment).data
        vulnerabilities_data = list(
            assessment.vulnerable_components.values(
                'control_title', 'control_description', 'control_impact',
                'control_recommendation', 'severity', 'status',
                'affected_devices', 'category_tag', 'framework_mapping',
                'cvss_score', 'cwe_id', 'owasp_category'
            )
        )
        
        # Add remediation controls to vulnerabilities
        for vuln_data in vulnerabilities_data:
            vuln = assessment.vulnerable_components.get(
                control_title=vuln_data['control_title']
            )
            vuln_data['remediation_controls'] = list(
                vuln.remediation_controls.values(
                    'control_name', 'implementation_details',
                    'risk_reduction_percentage', 'status',
                    'verified_by', 'verified_at'
                )
            )
        
        history_data = list(
            assessment.history.values(
                'timestamp', 'previous_score', 'new_score',
                'change_reason', 'changed_by'
            )
        )
        
        try:
            # Generate report
            generator = ExcelReportGenerator()
            filepath = generator.generate_report(
                assessment_data,
                vulnerabilities_data,
                history_data
            )
            
            # Return file
            response = FileResponse(
                open(filepath, 'rb'),
                content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(filepath)}"'
            return response
            
        except Exception as e:
            return Response(
                {'error': 'Report generation failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VulnerabilityListView(APIView):
    """
    List vulnerabilities for an assessment
    
    GET /api/assessments/{id}/vulnerabilities/
    """
    
    def get(self, request, pk):
        """Get all vulnerabilities for an assessment"""
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        vulnerabilities = assessment.vulnerable_components.all()
        
        # Filter by severity
        severity_filter = request.query_params.get('severity')
        if severity_filter:
            vulnerabilities = vulnerabilities.filter(severity=severity_filter)
        
        # Filter by status
        status_filter = request.query_params.get('status')
        if status_filter:
            vulnerabilities = vulnerabilities.filter(status=status_filter)
        
        # Filter by category
        category_filter = request.query_params.get('category')
        if category_filter:
            vulnerabilities = vulnerabilities.filter(category_tag=category_filter)
        
        serializer = VulnerableComponentSerializer(vulnerabilities, many=True)
        return Response(serializer.data)


class VulnerabilityDetailView(APIView):
    """
    Retrieve or update a specific vulnerability
    
    GET /api/vulnerabilities/{id}/
    PATCH /api/vulnerabilities/{id}/
    """
    
    def get(self, request, pk):
        """Get vulnerability details"""
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)
        serializer = VulnerableComponentSerializer(vulnerability)
        return Response(serializer.data)
    
    def patch(self, request, pk):
        """Update vulnerability status"""
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)
        serializer = VulnerableComponentUpdateSerializer(
            vulnerability,
            data=request.data,
            partial=True
        )
        
        if serializer.is_valid():
            serializer.save()
            
            # If marked as fixed, potentially recalculate risk score
            if serializer.validated_data.get('status') == 'fixed':
                self._recalculate_risk_score(vulnerability.assessment)
            
            result_serializer = VulnerableComponentSerializer(vulnerability)
            return Response(result_serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _recalculate_risk_score(self, assessment):
        """Helper to recalculate risk score when vulnerabilities are fixed"""
        try:
            # Get all implemented remediation controls
            all_controls = []
            for vuln in assessment.vulnerable_components.all():
                controls = vuln.remediation_controls.filter(status='implemented')
                all_controls.extend([{
                    'control_name': c.control_name,
                    'control_description': c.control_description,
                    'risk_reduction_percentage': c.risk_reduction_percentage,
                    'status': c.status
                } for c in controls])
            
            if all_controls:
                # Build context
                context = f"""
                Application: {assessment.application_purpose or 'N/A'}
                Original Risk Score: {assessment.overall_risk_score}
                Current Status: Assessment with {len(all_controls)} implemented controls
                """
                
                analyzer = SecurityAnalyzer()
                new_score, reasoning = analyzer.recalculate_risk_with_controls(
                    str(assessment.id),
                    context,
                    all_controls
                )
                
                # Create history entry
                AssessmentHistory.objects.create(
                    assessment=assessment,
                    previous_score=assessment.overall_risk_score,
                    new_score=new_score,
                    change_reason=f"Risk recalculated after implementing {len(all_controls)} controls"
                )
                
                # Update assessment
                assessment.overall_risk_score = new_score
                assessment.risk_reasoning = reasoning
                assessment.save()
                
        except Exception as e:
            print(f"Error recalculating risk score: {str(e)}")


class RemediationControlListCreateView(APIView):
    """
    List or create remediation controls for a vulnerability
    
    GET /api/vulnerabilities/{id}/controls/
    POST /api/vulnerabilities/{id}/controls/
    """
    
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    
    def get(self, request, pk):
        """Get all remediation controls for a vulnerability"""
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)
        controls = vulnerability.remediation_controls.all()
        serializer = RemediationControlSerializer(controls, many=True)
        return Response(serializer.data)
    
    def post(self, request, pk):
        """Add a remediation control"""
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)
        
        serializer = RemediationControlSerializer(data=request.data)
        if serializer.is_valid():
            control = serializer.save(vulnerable_component=vulnerability)
            
            # If control is implemented, recalculate risk
            if control.status == 'implemented':
                self._recalculate_assessment_risk(vulnerability.assessment)
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _recalculate_assessment_risk(self, assessment):
        """Recalculate risk score when new control is added"""
        try:
            all_controls = []
            for vuln in assessment.vulnerable_components.all():
                controls = vuln.remediation_controls.filter(status='implemented')
                all_controls.extend([{
                    'control_name': c.control_name,
                    'control_description': c.control_description,
                    'risk_reduction_percentage': c.risk_reduction_percentage,
                    'status': c.status
                } for c in controls])
            
            if all_controls:
                context = f"""
                Application: {assessment.application_purpose or 'N/A'}
                Original Risk Score: {assessment.overall_risk_score}
                """
                
                analyzer = SecurityAnalyzer()
                new_score, reasoning = analyzer.recalculate_risk_with_controls(
                    str(assessment.id),
                    context,
                    all_controls
                )
                
                AssessmentHistory.objects.create(
                    assessment=assessment,
                    previous_score=assessment.overall_risk_score,
                    new_score=new_score,
                    change_reason="New remediation control implemented"
                )
                
                assessment.overall_risk_score = new_score
                assessment.risk_reasoning = reasoning
                assessment.save()
                
        except Exception as e:
            print(f"Error recalculating risk: {str(e)}")


class RemediationControlDetailView(APIView):
    """
    Retrieve, update or delete a remediation control
    
    GET /api/controls/{id}/
    PATCH /api/controls/{id}/
    DELETE /api/controls/{id}/
    """
    
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    
    def get(self, request, pk):
        """Get control details"""
        control = get_object_or_404(RemediationControl, pk=pk)
        serializer = RemediationControlSerializer(control)
        return Response(serializer.data)
    
    def patch(self, request, pk):
        """Update control"""
        control = get_object_or_404(RemediationControl, pk=pk)
        
        old_status = control.status
        
        serializer = RemediationControlSerializer(
            control,
            data=request.data,
            partial=True
        )
        
        if serializer.is_valid():
            updated_control = serializer.save()
            
            # If status changed to implemented, recalculate risk
            if old_status != 'implemented' and updated_control.status == 'implemented':
                self._recalculate_assessment_risk(
                    updated_control.vulnerable_component.assessment
                )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Delete control"""
        control = get_object_or_404(RemediationControl, pk=pk)
        assessment = control.vulnerable_component.assessment
        
        control.delete()
        
        # Recalculate risk after removing control
        self._recalculate_assessment_risk(assessment)
        
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    def _recalculate_assessment_risk(self, assessment):
        """Recalculate risk score"""
        try:
            all_controls = []
            for vuln in assessment.vulnerable_components.all():
                controls = vuln.remediation_controls.filter(status='implemented')
                all_controls.extend([{
                    'control_name': c.control_name,
                    'control_description': c.control_description,
                    'risk_reduction_percentage': c.risk_reduction_percentage,
                    'status': c.status
                } for c in controls])
            
            context = f"Application: {assessment.application_purpose or 'N/A'}\nOriginal Risk Score: {assessment.overall_risk_score}"
            
            if all_controls:
                analyzer = SecurityAnalyzer()
                new_score, reasoning = analyzer.recalculate_risk_with_controls(
                    str(assessment.id),
                    context,
                    all_controls
                )
            else:
                # No controls left, return to original or near-original score
                new_score = assessment.overall_risk_score
                reasoning = "All remediation controls removed"
            
            AssessmentHistory.objects.create(
                assessment=assessment,
                previous_score=assessment.overall_risk_score,
                new_score=new_score,
                change_reason="Remediation control updated/removed"
            )
            
            assessment.overall_risk_score = new_score
            assessment.risk_reasoning = reasoning
            assessment.save()
            
        except Exception as e:
            print(f"Error recalculating risk: {str(e)}")


class AssessmentHistoryView(APIView):
    """
    Get assessment history
    
    GET /api/assessments/{id}/history/
    """
    
    def get(self, request, pk):
        """Get risk score change history"""
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        history = assessment.history.all()
        serializer = AssessmentHistorySerializer(history, many=True)
        return Response(serializer.data)


class AssessmentStatisticsView(APIView):
    """
    Get overall statistics
    
    GET /api/statistics/
    """
    
    def get(self, request):
        """Get comprehensive statistics"""
        
        # Overall counts
        total_assessments = SecurityAssessment.objects.count()
        completed_assessments = SecurityAssessment.objects.filter(
            status='completed'
        ).count()
        
        # Risk distribution
        high_risk = SecurityAssessment.objects.filter(
            overall_risk_score__gte=61
        ).count()
        medium_risk = SecurityAssessment.objects.filter(
            overall_risk_score__gte=41,
            overall_risk_score__lt=61
        ).count()
        low_risk = SecurityAssessment.objects.filter(
            overall_risk_score__lt=41
        ).count()
        
        # Vulnerability stats
        total_vulnerabilities = VulnerableComponent.objects.count()
        open_vulnerabilities = VulnerableComponent.objects.filter(
            status='open'
        ).count()
        fixed_vulnerabilities = VulnerableComponent.objects.filter(
            status='fixed'
        ).count()
        
        # Severity breakdown
        critical_vulns = VulnerableComponent.objects.filter(
            severity='critical',
            status='open'
        ).count()
        high_vulns = VulnerableComponent.objects.filter(
            severity='high',
            status='open'
        ).count()
        
        # Category breakdown
        from django.db.models import Count
        category_stats = VulnerableComponent.objects.values(
            'category_tag'
        ).annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        return Response({
            'assessments': {
                'total': total_assessments,
                'completed': completed_assessments,
                'high_risk': high_risk,
                'medium_risk': medium_risk,
                'low_risk': low_risk
            },
            'vulnerabilities': {
                'total': total_vulnerabilities,
                'open': open_vulnerabilities,
                'fixed': fixed_vulnerabilities,
                'critical': critical_vulns,
                'high': high_vulns
            },
            'top_categories': list(category_stats)
        })