from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.http import FileResponse
from django.utils import timezone
from django.conf import settings
import os

from .models import (
    SecurityAssessment,
    VulnerableComponent,
    RemediationControl,
    EvidenceFile,
    AssessmentHistory,
    VulnerabilityFeedback,
    TrainingJob,
)
from .serializers import (
    SecurityAssessmentListSerializer,
    SecurityAssessmentDetailSerializer,
    SecurityAssessmentCreateSerializer,
    VulnerableComponentSerializer,
    VulnerableComponentUpdateSerializer,
    RemediationControlSerializer,
    EvidenceFileSerializer,
    AssessmentHistorySerializer,
    VulnerabilityFeedbackSerializer,
    TrainingJobSerializer,
)
from .services import SecurityAnalyzer, FeedbackTrainer
from .utils import ExcelReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _recalculate_assessment_risk(assessment):
    """Shared helper — recalculate overall risk score when controls change."""
    try:
        all_controls = []
        for vuln in assessment.vulnerable_components.all():
            for c in vuln.remediation_controls.filter(status='implemented'):
                all_controls.append({
                    'control_name': c.control_name,
                    'control_description': c.control_description,
                    'risk_reduction_percentage': c.risk_reduction_percentage,
                    'status': c.status,
                })
        
        context = (
            f"Application: {assessment.application_purpose or 'N/A'}\n"
            f"Original Risk Score: {assessment.overall_risk_score}"
        )

        if all_controls:
            analyzer = SecurityAnalyzer()
            new_score, reasoning = analyzer.recalculate_risk_with_controls(
                str(assessment.id), context, all_controls
            )
        else:
            new_score = assessment.overall_risk_score
            reasoning = "No implemented controls — risk score unchanged."

        AssessmentHistory.objects.create(
            assessment=assessment,
            previous_score=assessment.overall_risk_score,
            new_score=new_score,
            change_reason="Risk recalculated after remediation control change"
        )
        assessment.overall_risk_score = new_score
        assessment.risk_reasoning = reasoning
        assessment.save()

    except Exception as e:
        print(f"Error recalculating risk: {str(e)}")


def _process_evidence_and_risk_reduction(control, vulnerability, files):
    """
    For each uploaded file:
      1. AI-verify the file against the control + vulnerability context.
      2. Persist an EvidenceFile record with the AI verdict.
    Then:
      3. AI-calculate the overall risk_reduction_percentage from all evidence results.
      4. Persist risk_reduction_percentage and risk_reduction_reasoning on the control.
      5. If all evidence passed, auto-advance a 'planned' control to 'implemented'.
    """
    analyzer = SecurityAnalyzer()
    control_data = {
        'control_name': control.control_name,
        'control_description': control.control_description,
        'implementation_details': control.implementation_details,
        'status': control.status,
    }
    vuln_data = {
        'control_title': vulnerability.control_title,
        'control_description': vulnerability.control_description,
        'control_impact': vulnerability.control_impact,
        'category_tag': vulnerability.category_tag,
        'severity': vulnerability.severity,
        'cvss_score': str(vulnerability.cvss_score) if vulnerability.cvss_score else None,
    }

    analyses = []
    all_passed = True

    for f in files:
        try:
            passed, analysis = analyzer.verify_evidence_file(control_data, vuln_data, f)
            f.seek(0)
            ext = f.name.split('.')[-1].lower()
            EvidenceFile.objects.create(
                remediation_control=control,
                file=f,
                original_filename=f.name,
                file_type=ext,
                ai_analysis=analysis,
                verification_passed=passed,
            )
            analyses.append(analysis)
            if not passed:
                all_passed = False
        except Exception as e:
            analyses.append(f"[Error processing {f.name}: {e}]")
            all_passed = False

    # Concatenate all evidence analyses into a single summary for the control
    combined_analysis = "\n---\n".join(analyses)

    # Calculate risk reduction based on evidence quality
    try:
        pct, reasoning = analyzer.calculate_risk_reduction(
            control_data, vuln_data, analyses, all_passed
        )
    except Exception as e:
        pct, reasoning = 0, f"Risk reduction calculation failed: {e}"

    # Auto-advance status if all evidence verified
    new_status = control.status
    if all_passed and control.status == 'planned':
        new_status = 'implemented'

    update_fields = [
        'evidence_verification_result', 'evidence_verification_passed',
        'evidence_verified_at', 'risk_reduction_percentage',
        'risk_reduction_reasoning', 'status', 'updated_at',
    ]
    control.evidence_verification_result = combined_analysis
    control.evidence_verification_passed = all_passed
    control.evidence_verified_at = timezone.now()
    control.risk_reduction_percentage = pct
    control.risk_reduction_reasoning = reasoning
    control.status = new_status
    control.save(update_fields=update_fields)


def _recalculate_vulnerability_severity(vulnerability):
    """
    Auto-recalculate the severity of a vulnerability based on all its controls.
    Updates the vulnerability in-place (saves to DB).
    """
    try:
        controls = list(vulnerability.remediation_controls.values(
            'control_name', 'control_description', 'implementation_details',
            'status', 'risk_reduction_percentage'
        ))
        vuln_data = {
            'control_title': vulnerability.control_title,
            'control_description': vulnerability.control_description,
            'control_impact': vulnerability.control_impact,
            'category_tag': vulnerability.category_tag,
            'cvss_score': str(vulnerability.cvss_score) if vulnerability.cvss_score else None,
            'cwe_id': vulnerability.cwe_id,
            'severity': vulnerability.severity,
        }
        analyzer = SecurityAnalyzer()
        new_severity, reasoning = analyzer.recalculate_vulnerability_severity(
            vuln_data, controls
        )
        vulnerability.severity = new_severity
        vulnerability.severity_reasoning = reasoning
        vulnerability.severity_last_calculated_at = timezone.now()
        vulnerability.save(update_fields=[
            'severity', 'severity_reasoning', 'severity_last_calculated_at', 'updated_at'
        ])
    except Exception as e:
        print(f"Error recalculating severity for {vulnerability.id}: {str(e)}")


# ---------------------------------------------------------------------------
# Assessment endpoints
# ---------------------------------------------------------------------------

class AssessmentListCreateView(APIView):
    """
    GET  /api/assessments/   — list all assessments
    POST /api/assessments/   — create new assessment + run AI analysis
    """
    parser_classes = (MultiPartParser, FormParser)
    
    def get(self, request):
        assessments = SecurityAssessment.objects.all()
        
        status_filter = request.query_params.get('status')
        if status_filter:
            assessments = assessments.filter(status=status_filter)
        
        min_score = request.query_params.get('min_score')
        max_score = request.query_params.get('max_score')
        if min_score:
            assessments = assessments.filter(overall_risk_score__gte=int(min_score))
        if max_score:
            assessments = assessments.filter(overall_risk_score__lte=int(max_score))
        
        serializer = SecurityAssessmentListSerializer(assessments, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = SecurityAssessmentCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        architecture_file = request.FILES.get('architecture_diagram')
        if not architecture_file:
            return Response(
                {'error': 'Architecture diagram is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            with transaction.atomic():
                assessment = serializer.save(status='processing')
                
                assessment_data = {'id': str(assessment.id), **serializer.validated_data}
                for key in ['architecture_diagram', 'high_level_architecture',
                            'logical_architecture', 'physical_architecture', 'data_flow_diagrams']:
                    assessment_data.pop(key, None)
                
                analyzer = SecurityAnalyzer()
                risk_score, reasoning, vulnerabilities = analyzer.analyze_security(
                    assessment_data, architecture_file
                )
                
                assessment.overall_risk_score = risk_score
                assessment.risk_reasoning = reasoning
                assessment.status = 'completed'
                assessment.save()
                
                for vuln_data in vulnerabilities:
                    VulnerableComponent.objects.create(assessment=assessment, **vuln_data)
                
                print(f"Created {len(vulnerabilities)} vulnerability records")
                
                AssessmentHistory.objects.create(
                    assessment=assessment,
                    previous_score=None,
                    new_score=risk_score,
                    change_reason="Initial assessment completed"
                )
            
            result_serializer = SecurityAssessmentDetailSerializer(assessment)
            return Response(result_serializer.data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            if 'assessment' in locals():
                assessment.status = 'failed'
                assessment.save()
            import traceback
            print(f"Assessment failed: {e}\n{traceback.format_exc()}")
            return Response(
                {'error': 'Assessment failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AssessmentDetailView(APIView):
    """
    GET    /api/assessments/{id}/
    PATCH  /api/assessments/{id}/
    DELETE /api/assessments/{id}/
    """
    
    def get(self, request, pk):
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        serializer = SecurityAssessmentDetailSerializer(assessment)
        return Response(serializer.data)
    
    def patch(self, request, pk):
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        allowed_fields = [
            'application_purpose', 'business_objectives', 'stakeholders',
            'system_owners', 'compliance_requirements'
        ]
        update_data = {k: v for k, v in request.data.items() if k in allowed_fields}
        for field, value in update_data.items():
            setattr(assessment, field, value)
        assessment.save()
        return Response(SecurityAssessmentDetailSerializer(assessment).data)
    
    def delete(self, request, pk):
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        assessment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AssessmentReportView(APIView):
    """GET /api/assessments/{id}/report/"""
    
    def get(self, request, pk):
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        assessment_data = SecurityAssessmentDetailSerializer(assessment).data
        vulnerabilities_data = list(
            assessment.vulnerable_components.values(
                'control_title', 'control_description', 'control_impact',
                'control_recommendation', 'severity', 'status',
                'affected_devices', 'category_tag', 'framework_mapping',
                'cvss_score', 'cwe_id', 'owasp_category'
            )
        )
        for vuln_data in vulnerabilities_data:
            vuln = assessment.vulnerable_components.get(control_title=vuln_data['control_title'])
            vuln_data['remediation_controls'] = list(
                vuln.remediation_controls.values(
                    'control_name', 'implementation_details',
                    'risk_reduction_percentage', 'status',
                    'verified_by', 'verified_at'
                )
            )
        
        history_data = list(assessment.history.values(
            'timestamp', 'previous_score', 'new_score', 'change_reason', 'changed_by'
        ))
        
        try:
            generator = ExcelReportGenerator()
            filepath = generator.generate_report(assessment_data, vulnerabilities_data, history_data)
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


class AssessmentHistoryView(APIView):
    """GET /api/assessments/{id}/history/"""
    
    def get(self, request, pk):
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        history = assessment.history.all()
        serializer = AssessmentHistorySerializer(history, many=True)
        return Response(serializer.data)


class AssessmentStatisticsView(APIView):
    """GET /api/statistics/"""
    
    def get(self, request):
        from django.db.models import Count

        total_assessments = SecurityAssessment.objects.count()
        completed_assessments = SecurityAssessment.objects.filter(status='completed').count()
        high_risk = SecurityAssessment.objects.filter(overall_risk_score__gte=61).count()
        medium_risk = SecurityAssessment.objects.filter(
            overall_risk_score__gte=41, overall_risk_score__lt=61
        ).count()
        low_risk = SecurityAssessment.objects.filter(overall_risk_score__lt=41).count()
        
        total_vulnerabilities = VulnerableComponent.objects.count()
        open_vulnerabilities = VulnerableComponent.objects.filter(status='open').count()
        fixed_vulnerabilities = VulnerableComponent.objects.filter(status='fixed').count()
        critical_vulns = VulnerableComponent.objects.filter(severity='critical', status='open').count()
        high_vulns = VulnerableComponent.objects.filter(severity='high', status='open').count()
        
        category_stats = (
            VulnerableComponent.objects
            .values('category_tag')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        return Response({
            'assessments': {
                'total': total_assessments, 'completed': completed_assessments,
                'high_risk': high_risk, 'medium_risk': medium_risk, 'low_risk': low_risk
            },
            'vulnerabilities': {
                'total': total_vulnerabilities, 'open': open_vulnerabilities,
                'fixed': fixed_vulnerabilities, 'critical': critical_vulns, 'high': high_vulns
            },
            'top_categories': list(category_stats)
        })


# ---------------------------------------------------------------------------
# Vulnerability endpoints
# ---------------------------------------------------------------------------

class VulnerabilityListView(APIView):
    """GET /api/assessments/{id}/vulnerabilities/"""
    
    def get(self, request, pk):
        assessment = get_object_or_404(SecurityAssessment, pk=pk)
        vulnerabilities = assessment.vulnerable_components.all()
        
        severity_filter = request.query_params.get('severity')
        if severity_filter:
            vulnerabilities = vulnerabilities.filter(severity=severity_filter)
        
        status_filter = request.query_params.get('status')
        if status_filter:
            vulnerabilities = vulnerabilities.filter(status=status_filter)
        
        category_filter = request.query_params.get('category')
        if category_filter:
            vulnerabilities = vulnerabilities.filter(category_tag=category_filter)
        
        serializer = VulnerableComponentSerializer(vulnerabilities, many=True)
        return Response(serializer.data)


class VulnerabilityDetailView(APIView):
    """
    GET   /api/vulnerabilities/{id}/
    PATCH /api/vulnerabilities/{id}/
    """
    
    def get(self, request, pk):
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)
        return Response(VulnerableComponentSerializer(vulnerability).data)
    
    def patch(self, request, pk):
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)
        serializer = VulnerableComponentUpdateSerializer(vulnerability, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            if serializer.validated_data.get('status') == 'fixed':
                _recalculate_assessment_risk(vulnerability.assessment)
            return Response(VulnerableComponentSerializer(vulnerability).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ---------------------------------------------------------------------------
# Remediation control endpoints
# ---------------------------------------------------------------------------

class RemediationControlListCreateView(APIView):
    """
    GET  /api/vulnerabilities/{id}/controls/
    POST /api/vulnerabilities/{id}/controls/

    Creating a control requires at least one evidence file uploaded under the
    multipart field name 'files'. The API will:
      1. Reject the request if no evidence file is provided.
      2. AI-verify each evidence file.
      3. AI-calculate risk_reduction_percentage from evidence quality + context.
      4. Auto-recalculate the vulnerability severity.
      5. Recalculate the overall assessment risk score.
    """
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get(self, request, pk):
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)
        controls = vulnerability.remediation_controls.all()
        return Response(RemediationControlSerializer(controls, many=True).data)

    def post(self, request, pk):
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)

        # --- Evidence is mandatory on creation -------------------------------
        files = request.FILES.getlist('files')
        if not files:
            return Response(
                {
                    'error': 'At least one evidence file is required.',
                    'detail': (
                        'Upload evidence files using the multipart field "files". '
                        'The AI will verify each file and automatically calculate '
                        'the risk_reduction_percentage.'
                    )
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = RemediationControlSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Save with risk_reduction_percentage=None; AI will fill it in below
        control = serializer.save(vulnerable_component=vulnerability, risk_reduction_percentage=None)

        # --- Evidence verification + risk reduction calculation --------------
        _process_evidence_and_risk_reduction(control, vulnerability, files)

        # --- Severity auto-calculation ---------------------------------------
        _recalculate_vulnerability_severity(vulnerability)

        # --- Overall risk recalculation --------------------------------------
        if control.status in ('implemented', 'verified'):
            _recalculate_assessment_risk(vulnerability.assessment)

        return Response(
            RemediationControlSerializer(control).data,
            status=status.HTTP_201_CREATED
        )


class RemediationControlDetailView(APIView):
    """
    GET    /api/controls/{id}/
    PATCH  /api/controls/{id}/
    DELETE /api/controls/{id}/
    """
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    
    def get(self, request, pk):
        control = get_object_or_404(RemediationControl, pk=pk)
        return Response(RemediationControlSerializer(control).data)
    
    def patch(self, request, pk):
        control = get_object_or_404(RemediationControl, pk=pk)
        old_status = control.status
        serializer = RemediationControlSerializer(control, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        updated_control = serializer.save()
        vulnerability = updated_control.vulnerable_component

        # --- Process any newly uploaded evidence files -----------------------
        files = request.FILES.getlist('files')
        if files:
            _process_evidence_and_risk_reduction(updated_control, vulnerability, files)

        # --- Severity auto-recalculation -------------------------------------
        _recalculate_vulnerability_severity(vulnerability)

        # --- Overall risk recalculation when status becomes implemented ------
        if old_status not in ('implemented', 'verified') and updated_control.status in ('implemented', 'verified'):
            _recalculate_assessment_risk(vulnerability.assessment)

        return Response(RemediationControlSerializer(updated_control).data)
    
    def delete(self, request, pk):
        control = get_object_or_404(RemediationControl, pk=pk)
        vulnerability = control.vulnerable_component
        assessment = vulnerability.assessment
        control.delete()
        _recalculate_vulnerability_severity(vulnerability)
        _recalculate_assessment_risk(assessment)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Evidence file upload (additional files for an existing control)
# ---------------------------------------------------------------------------

class EvidenceFileUploadView(APIView):
    """
    POST /api/controls/{id}/evidence/

    Upload one or more additional evidence files to an existing control.
    Each file is individually AI-verified.
    """
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, pk):
        control = get_object_or_404(RemediationControl, pk=pk)
        vulnerability = control.vulnerable_component

        files = request.FILES.getlist('files')
        if not files:
            return Response(
                {'error': 'No files provided. Use the "files" multipart field.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Process all files: verify + calculate risk reduction
        _process_evidence_and_risk_reduction(control, vulnerability, files)

        # Re-run severity & risk calculations
        _recalculate_vulnerability_severity(vulnerability)
        if control.status in ('implemented', 'verified'):
            _recalculate_assessment_risk(vulnerability.assessment)

        # Return updated evidence attachments
        updated_attachments = EvidenceFileSerializer(
            control.evidence_attachments.all(), many=True
        ).data
        return Response(
            {
                'uploaded': updated_attachments,
                'risk_reduction_percentage': control.risk_reduction_percentage,
                'risk_reduction_reasoning': control.risk_reduction_reasoning,
                'evidence_verification_passed': control.evidence_verification_passed,
            },
            status=status.HTTP_201_CREATED
        )


# ---------------------------------------------------------------------------
# Feedback endpoints
# ---------------------------------------------------------------------------

class VulnerabilityFeedbackListCreateView(APIView):
    """
    GET  /api/feedback/                — list all feedback (filterable)
    POST /api/feedback/                — submit new feedback
    """
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get(self, request):
        qs = VulnerabilityFeedback.objects.all()

        fb_type = request.query_params.get('feedback_type')
        if fb_type:
            qs = qs.filter(feedback_type=fb_type)

        assessment_id = request.query_params.get('assessment')
        if assessment_id:
            qs = qs.filter(assessment_id=assessment_id)

        incorporated = request.query_params.get('incorporated')
        if incorporated is not None:
            qs = qs.filter(incorporated_in_training=(incorporated.lower() == 'true'))

        return Response(VulnerabilityFeedbackSerializer(qs, many=True).data)

    def post(self, request):
        serializer = VulnerabilityFeedbackSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid feedback data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        feedback = serializer.save()

        # Auto-update the vulnerability status when marked as false positive
        if feedback.feedback_type == 'false_positive' and feedback.vulnerable_component:
            vc = feedback.vulnerable_component
            vc.status = 'false_positive'
            vc.save(update_fields=['status', 'updated_at'])

        return Response(
            VulnerabilityFeedbackSerializer(feedback).data,
            status=status.HTTP_201_CREATED
        )


class VulnerabilityFeedbackDetailView(APIView):
    """
    GET    /api/feedback/{id}/
    PATCH  /api/feedback/{id}/
    DELETE /api/feedback/{id}/
    """
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get(self, request, pk):
        feedback = get_object_or_404(VulnerabilityFeedback, pk=pk)
        return Response(VulnerabilityFeedbackSerializer(feedback).data)

    def patch(self, request, pk):
        feedback = get_object_or_404(VulnerabilityFeedback, pk=pk)
        if feedback.incorporated_in_training:
            return Response(
                {'error': 'Cannot edit feedback that has already been incorporated into training.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = VulnerabilityFeedbackSerializer(feedback, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        feedback = get_object_or_404(VulnerabilityFeedback, pk=pk)
        if feedback.incorporated_in_training:
            return Response(
                {'error': 'Cannot delete feedback that has already been incorporated into training.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        feedback.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Training job endpoints
# ---------------------------------------------------------------------------

class TrainingJobListView(APIView):
    """
    GET  /api/training/   — list all training jobs
    POST /api/training/   — trigger a new training run immediately
    """

    def get(self, request):
        jobs = TrainingJob.objects.all()
        return Response(TrainingJobSerializer(jobs, many=True).data)

    def post(self, request):
        """
        Manually trigger a training run.
        Returns the TrainingJob record.  The actual work is done synchronously
        here; for production you'd dispatch this to a Celery task.
        """
        pending_count = VulnerabilityFeedback.objects.filter(
            incorporated_in_training=False
        ).count()
        if pending_count == 0:
            return Response(
                {'message': 'No unincorporated feedback found. Nothing to train on.'},
                status=status.HTTP_200_OK
            )

        try:
            trainer = FeedbackTrainer()
            job = trainer.run_weekly_training()
            return Response(TrainingJobSerializer(job).data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {'error': 'Training run failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TrainingJobDetailView(APIView):
    """GET /api/training/{id}/"""

    def get(self, request, pk):
        job = get_object_or_404(TrainingJob, pk=pk)
        return Response(TrainingJobSerializer(job).data)