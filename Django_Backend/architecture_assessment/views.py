from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.shortcuts import get_object_or_404
from django.db import models as db_models
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
    TokenUsage,
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
    TokenUsageStatsSerializer,
)
from .services import SecurityAnalyzer, FeedbackTrainer, FeedbackVectorIndexer
from .utils import ExcelReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_user(request):
    """Return request.user if authenticated, else None."""
    user = getattr(request, 'user', None)
    if user and user.is_authenticated:
        return user
    return None


def _recalculate_assessment_risk(assessment, user=None):
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
                str(assessment.id), context, all_controls,
                user=user, assessment=assessment,
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


def _process_evidence_and_risk_reduction(control, vulnerability, files, user=None):
    """
    For each uploaded file:
      1. AI-verify the file against the control + vulnerability context.
      2. Persist an EvidenceFile record.
    Then:
      3. AI-calculate the overall risk_reduction_percentage.
      4. Persist risk_reduction on the control.
      5. Auto-advance a 'planned' control to 'implemented' if all evidence passed.
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
    assessment = vulnerability.assessment

    analyses = []
    all_passed = True

    for f in files:
        try:
            passed, analysis = analyzer.verify_evidence_file(
                control_data, vuln_data, f,
                user=user, assessment=assessment,
            )
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

    combined_analysis = "\n---\n".join(analyses)

    try:
        pct, reasoning = analyzer.calculate_risk_reduction(
            control_data, vuln_data, analyses, all_passed,
            user=user, assessment=assessment,
        )
    except Exception as e:
        pct, reasoning = 0, f"Risk reduction calculation failed: {e}"

    new_status = control.status
    if all_passed and control.status == 'planned':
        new_status = 'implemented'

    control.evidence_verification_result = combined_analysis
    control.evidence_verification_passed = all_passed
    control.evidence_verified_at = timezone.now()
    control.risk_reduction_percentage = pct
    control.risk_reduction_reasoning = reasoning
    control.status = new_status
    control.save(update_fields=[
        'evidence_verification_result', 'evidence_verification_passed',
        'evidence_verified_at', 'risk_reduction_percentage',
        'risk_reduction_reasoning', 'status', 'updated_at',
    ])


def _recalculate_vulnerability_severity(vulnerability, user=None):
    """Auto-recalculate the severity of a vulnerability based on all its controls."""
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
            vuln_data, controls,
            user=user, assessment=vulnerability.assessment,
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
        user = _get_user(request)
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
                # Attach owner at creation time
                assessment = serializer.save(status='processing', owner=user)

                assessment_data = {'id': str(assessment.id), **serializer.validated_data}
                for key in ['architecture_diagram', 'high_level_architecture',
                            'logical_architecture', 'physical_architecture', 'data_flow_diagrams']:
                    assessment_data.pop(key, None)

                analyzer = SecurityAnalyzer()
                risk_score, reasoning, vulnerabilities = analyzer.analyze_security(
                    assessment_data, architecture_file,
                    user=user, assessment_obj=assessment,
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
                    change_reason="Initial assessment completed",
                    changed_by=user.username if user else None,
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
        return Response(SecurityAssessmentDetailSerializer(assessment).data)

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
        return Response(AssessmentHistorySerializer(history, many=True).data)


class AssessmentStatisticsView(APIView):
    """
    GET /api/statistics/

    Returns global assessment/vulnerability stats PLUS per-user token usage
    for the currently authenticated user.
    """

    def get(self, request):
        from django.db.models import Count, Sum

        user = _get_user(request)

        # ---- Global assessment stats ----
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

        # ---- Feedback / RAG stats ----
        from .services import VectorStore
        try:
            vs = VectorStore()
            chroma_stats = vs.get_feedback_collection_stats()
        except Exception:
            chroma_stats = {"total_indexed": 0}

        total_feedback = VulnerabilityFeedback.objects.count()
        pending_feedback = VulnerabilityFeedback.objects.filter(
            incorporated_in_training=False
        ).count()
        last_training = (
            TrainingJob.objects.filter(status='completed')
            .order_by('-completed_at')
            .values('id', 'completed_at', 'feedback_count', 'chroma_indexed_count')
            .first()
        )

        # ---- Per-user token usage ----
        token_usage_data = None
        if user:
            user_qs = TokenUsage.objects.filter(user=user)

            # Totals
            totals = user_qs.aggregate(
                total_prompt=Sum('prompt_tokens'),
                total_completion=Sum('completion_tokens'),
                total_all=Sum('total_tokens'),
                total_cost=Sum('estimated_cost_usd'),
                total_calls=Count('id'),
            )

            # Per-operation breakdown
            by_operation = list(
                user_qs.values('operation')
                .annotate(
                    calls=Count('id'),
                    prompt_tokens=Sum('prompt_tokens'),
                    completion_tokens=Sum('completion_tokens'),
                    total_tokens=Sum('total_tokens'),
                    estimated_cost_usd=Sum('estimated_cost_usd'),
                )
                .order_by('-total_tokens')
            )

            # Per-model breakdown
            by_model = list(
                user_qs.values('model_name')
                .annotate(
                    calls=Count('id'),
                    total_tokens=Sum('total_tokens'),
                    estimated_cost_usd=Sum('estimated_cost_usd'),
                )
                .order_by('-total_tokens')
            )

            # Last 30 days usage (daily)
            from django.db.models.functions import TruncDate
            daily_usage = list(
                user_qs.annotate(date=TruncDate('created_at'))
                .values('date')
                .annotate(
                    calls=Count('id'),
                    total_tokens=Sum('total_tokens'),
                    estimated_cost_usd=Sum('estimated_cost_usd'),
                )
                .order_by('-date')[:30]
            )

            token_usage_data = {
                "user": user.username,
                "summary": {
                    "total_api_calls": totals['total_calls'] or 0,
                    "prompt_tokens": totals['total_prompt'] or 0,
                    "completion_tokens": totals['total_completion'] or 0,
                    "total_tokens": totals['total_all'] or 0,
                    "estimated_cost_usd": str(totals['total_cost'] or 0),
                },
                "by_operation": by_operation,
                "by_model": by_model,
                "daily_usage_last_30_days": daily_usage,
            }

        return Response({
            'assessments': {
                'total': total_assessments,
                'completed': completed_assessments,
                'high_risk': high_risk,
                'medium_risk': medium_risk,
                'low_risk': low_risk,
            },
            'vulnerabilities': {
                'total': total_vulnerabilities,
                'open': open_vulnerabilities,
                'fixed': fixed_vulnerabilities,
                'critical': critical_vulns,
                'high': high_vulns,
            },
            'top_categories': list(category_stats),
            'rag_knowledge_base': {
                'total_feedback_documents_indexed': chroma_stats.get('total_indexed', 0),
                'total_feedback_records': total_feedback,
                'pending_incorporation': pending_feedback,
                'last_training_job': last_training,
            },
            'token_usage': token_usage_data,
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

        return Response(VulnerableComponentSerializer(vulnerabilities, many=True).data)


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
                _recalculate_assessment_risk(
                    vulnerability.assessment, user=_get_user(request)
                )
            return Response(VulnerableComponentSerializer(vulnerability).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ---------------------------------------------------------------------------
# Remediation control endpoints
# ---------------------------------------------------------------------------

class RemediationControlListCreateView(APIView):
    """
    GET  /api/vulnerabilities/{id}/controls/
    POST /api/vulnerabilities/{id}/controls/
    """
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get(self, request, pk):
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)
        return Response(RemediationControlSerializer(
            vulnerability.remediation_controls.all(), many=True
        ).data)

    def post(self, request, pk):
        user = _get_user(request)
        vulnerability = get_object_or_404(VulnerableComponent, pk=pk)

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

        control = serializer.save(vulnerable_component=vulnerability, risk_reduction_percentage=None)

        _process_evidence_and_risk_reduction(control, vulnerability, files, user=user)
        _recalculate_vulnerability_severity(vulnerability, user=user)

        if control.status in ('implemented', 'verified'):
            _recalculate_assessment_risk(vulnerability.assessment, user=user)

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
        user = _get_user(request)
        control = get_object_or_404(RemediationControl, pk=pk)
        old_status = control.status
        serializer = RemediationControlSerializer(control, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        updated_control = serializer.save()
        vulnerability = updated_control.vulnerable_component

        files = request.FILES.getlist('files')
        if files:
            _process_evidence_and_risk_reduction(updated_control, vulnerability, files, user=user)

        _recalculate_vulnerability_severity(vulnerability, user=user)

        if old_status not in ('implemented', 'verified') and updated_control.status in ('implemented', 'verified'):
            _recalculate_assessment_risk(vulnerability.assessment, user=user)

        return Response(RemediationControlSerializer(updated_control).data)

    def delete(self, request, pk):
        user = _get_user(request)
        control = get_object_or_404(RemediationControl, pk=pk)
        vulnerability = control.vulnerable_component
        assessment = vulnerability.assessment
        control.delete()
        _recalculate_vulnerability_severity(vulnerability, user=user)
        _recalculate_assessment_risk(assessment, user=user)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Evidence file upload
# ---------------------------------------------------------------------------

class EvidenceFileUploadView(APIView):
    """POST /api/controls/{id}/evidence/"""
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, pk):
        user = _get_user(request)
        control = get_object_or_404(RemediationControl, pk=pk)
        vulnerability = control.vulnerable_component

        files = request.FILES.getlist('files')
        if not files:
            return Response(
                {'error': 'No files provided. Use the "files" multipart field.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        _process_evidence_and_risk_reduction(control, vulnerability, files, user=user)
        _recalculate_vulnerability_severity(vulnerability, user=user)
        if control.status in ('implemented', 'verified'):
            _recalculate_assessment_risk(vulnerability.assessment, user=user)

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
# Feedback endpoints — now also immediately indexes into ChromaDB
# ---------------------------------------------------------------------------

class VulnerabilityFeedbackListCreateView(APIView):
    """
    GET  /api/feedback/   — list all feedback (filterable)
    POST /api/feedback/   — submit new feedback (immediately indexed into ChromaDB)
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
        user = _get_user(request)
        serializer = VulnerabilityFeedbackSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid feedback data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        feedback = serializer.save()

        # Auto-update vulnerability status for false positives
        if feedback.feedback_type == 'false_positive' and feedback.vulnerable_component:
            vc = feedback.vulnerable_component
            vc.status = 'false_positive'
            vc.save(update_fields=['status', 'updated_at'])

        # Immediately index into ChromaDB — learning starts now, not next training run
        try:
            indexer = FeedbackVectorIndexer()
            doc_id = indexer.index(feedback, user=user)
            print(f"[RAG] Indexed feedback {feedback.id} into ChromaDB as {doc_id}")
        except Exception as exc:
            # Non-fatal — the feedback is saved, just not yet in the vector store
            print(f"[RAG] Warning: Failed to immediately index feedback {feedback.id}: {exc}")

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
        user = _get_user(request)
        feedback = get_object_or_404(VulnerabilityFeedback, pk=pk)
        if feedback.incorporated_in_training:
            return Response(
                {'error': 'Cannot edit feedback that has already been incorporated into training.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = VulnerabilityFeedbackSerializer(feedback, data=request.data, partial=True)
        if serializer.is_valid():
            updated = serializer.save()
            # Re-index updated feedback in ChromaDB
            try:
                indexer = FeedbackVectorIndexer()
                indexer.index(updated, user=user)
            except Exception as exc:
                print(f"[RAG] Warning: Failed to re-index feedback {feedback.id}: {exc}")
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        from .services import VectorStore
        feedback = get_object_or_404(VulnerabilityFeedback, pk=pk)
        if feedback.incorporated_in_training:
            return Response(
                {'error': 'Cannot delete feedback that has already been incorporated into training.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        # Remove from ChromaDB before deleting the DB record
        try:
            vs = VectorStore()
            vs.delete_feedback(str(feedback.id))
        except Exception as exc:
            print(f"[RAG] Warning: Failed to remove feedback {feedback.id} from ChromaDB: {exc}")
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
        user = _get_user(request)
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
            job = trainer.run_weekly_training(user=user)
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