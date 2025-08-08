from django.contrib import admin
from .models import SSRFCandidate, LLMAnalysisResult, SSRFProof


@admin.register(SSRFCandidate)
class SSRFCandidateAdmin(admin.ModelAdmin):
    list_display = ['id', 'api', 'risk_score', 'identified_at']
    list_filter = ['risk_score', 'identified_at', 'api__scan__scan_name']
    search_fields = ['api__name', 'api__url', 'risk_factors']
    readonly_fields = ['id', 'api', 'risk_factors', 'vulnerable_components', 'identified_at']

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(api__scan__created_by=request.user)


@admin.register(LLMAnalysisResult)
class LLMAnalysisResultAdmin(admin.ModelAdmin):
    list_display = ['id', 'ssrf_candidate', 'provider', 'model_used', 'overall_risk', 'critical_findings_count', 'analysis_timestamp']
    list_filter = ['provider', 'model_used', 'overall_risk', 'analysis_timestamp', 'ssrf_candidate__api__scan__scan_name']
    search_fields = ['ssrf_candidate__api__name', 'raw_llm_response', 'parsed_analysis']
    readonly_fields = [
        'id', 'ssrf_candidate', 'provider', 'model_used', 'prompt_sent',
        'raw_llm_response', 'parsed_analysis', 'analysis_timestamp',
        'overall_risk', 'critical_findings_count'
    ]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(ssrf_candidate__api__scan__created_by=request.user)


@admin.register(SSRFProof)
class SSRFProofAdmin(admin.ModelAdmin):
    list_display = ['id', 'ssrf_candidate', 'payload_used', 'injection_point', 'target_internal_ip_or_domain', 'status', 'exploitation_timestamp']
    list_filter = ['status', 'exploitation_timestamp', 'injection_point', 'ssrf_candidate__api__scan__scan_name']
    search_fields = ['ssrf_candidate__api__name', 'payload_used', 'target_internal_ip_or_domain', 'proof_details']
    readonly_fields = [
        'id', 'ssrf_candidate', 'payload_used', 'injection_point',
        'target_internal_ip_or_domain', 'proof_details', 'exploitation_timestamp', 'status'
    ]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(ssrf_candidate__api__scan__created_by=request.user)
