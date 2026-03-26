from django.contrib import admin
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


@admin.register(SecurityAssessment)
class SecurityAssessmentAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'created_at', 'status', 'overall_risk_score',
        'application_purpose', 'business_criticality', 'owner'
    ]
    list_filter = ['status', 'created_at', 'business_criticality']
    search_fields = [
        'application_purpose', 'business_objectives',
        'stakeholders', 'programming_languages', 'owner__username'
    ]
    readonly_fields = ['id', 'created_at', 'updated_at']

    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'created_at', 'updated_at', 'status', 'owner',
                'architecture_diagram', 'overall_risk_score', 'risk_reasoning'
            )
        }),
        ('Application Context', {
            'fields': (
                'application_purpose', 'business_objectives', 'business_criticality',
                'impact_of_failure', 'supported_business_processes',
                'data_sensitivity', 'data_classification_levels',
                'regulatory_requirements', 'compliance_requirements',
                'stakeholders', 'system_owners', 'risk_tolerance',
                'risk_acceptance_criteria'
            ),
            'classes': ('collapse',)
        }),
        ('Application Overview', {
            'fields': (
                'application_type', 'usage_model', 'functional_overview',
                'major_modules', 'user_roles', 'access_types',
                'expected_traffic', 'load_patterns', 'deployment_model'
            ),
            'classes': ('collapse',)
        }),
        ('Technology Stack', {
            'fields': (
                'programming_languages', 'frameworks_versions',
                'libraries_packages', 'runtime_environments',
                'databases', 'storage_systems', 'middleware_components',
                'message_queues', 'api_gateways', 'web_servers',
                'application_servers'
            ),
            'classes': ('collapse',)
        }),
        ('Infrastructure', {
            'fields': (
                'containerization_platforms', 'orchestration_platforms',
                'hosting_environment', 'cloud_services',
                'network_architecture', 'network_topology',
                'network_segmentation', 'subnets', 'load_balancers',
                'traffic_routing', 'firewall_config', 'waf_config',
                'cdn_usage', 'regions', 'availability_zones'
            ),
            'classes': ('collapse',)
        }),
        ('Security Controls', {
            'fields': (
                'authentication_mechanisms', 'authorization_model',
                'sso_federation', 'mfa_enforcement', 'service_authentication',
                'secrets_management', 'key_management',
                'privileged_access_controls', 'account_provisioning',
                'account_deprovisioning', 'encryption_at_rest',
                'encryption_in_transit', 'input_validation_controls',
                'secure_coding_standards', 'api_authentication'
            ),
            'classes': ('collapse',)
        }),
    )


@admin.register(VulnerableComponent)
class VulnerableComponentAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'assessment', 'control_title', 'severity',
        'status', 'category_tag', 'created_at',
        'severity_last_calculated_at'
    ]
    list_filter = ['severity', 'status', 'category_tag', 'created_at']
    search_fields = [
        'control_title', 'control_description',
        'affected_devices', 'framework_mapping'
    ]
    readonly_fields = ['id', 'created_at', 'updated_at', 'severity_reasoning', 'severity_last_calculated_at']

    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'assessment', 'created_at', 'updated_at')
        }),
        ('Finding Details', {
            'fields': (
                'control_title', 'control_description', 'control_impact',
                'control_recommendation', 'severity', 'status'
            )
        }),
        ('Classification', {
            'fields': (
                'category_tag', 'framework_mapping', 'affected_devices',
                'cvss_score', 'cwe_id', 'owasp_category'
            )
        }),
        ('AI Severity Calculation', {
            'fields': ('severity_reasoning', 'severity_last_calculated_at'),
            'classes': ('collapse',)
        }),
    )


class EvidenceFileInline(admin.TabularInline):
    model = EvidenceFile
    extra = 0
    readonly_fields = ['uploaded_at', 'ai_analysis', 'verification_passed']
    fields = ['file', 'original_filename', 'file_type', 'uploaded_at', 'verification_passed', 'ai_analysis']


@admin.register(RemediationControl)
class RemediationControlAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'vulnerable_component', 'control_name',
        'status', 'risk_reduction_percentage',
        'evidence_verification_passed', 'created_at'
    ]
    list_filter = ['status', 'evidence_verification_passed', 'created_at']
    search_fields = ['control_name', 'control_description', 'verified_by']
    readonly_fields = [
        'id', 'created_at', 'updated_at',
        'evidence_verification_result', 'evidence_verified_at', 'evidence_verification_passed'
    ]
    inlines = [EvidenceFileInline]

    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'vulnerable_component', 'created_at', 'updated_at')
        }),
        ('Control Details', {
            'fields': (
                'control_name', 'control_description',
                'implementation_details', 'status',
                'risk_reduction_percentage'
            )
        }),
        ('Verification', {
            'fields': (
                'verification_notes', 'verified_by',
                'verified_at', 'evidence_files'
            )
        }),
        ('AI Evidence Verification', {
            'fields': (
                'evidence_verification_result',
                'evidence_verified_at',
                'evidence_verification_passed'
            ),
            'classes': ('collapse',)
        }),
    )


@admin.register(EvidenceFile)
class EvidenceFileAdmin(admin.ModelAdmin):
    list_display = ['id', 'remediation_control', 'original_filename', 'file_type', 'verification_passed', 'uploaded_at']
    list_filter = ['verification_passed', 'file_type', 'uploaded_at']
    search_fields = ['original_filename', 'ai_analysis']
    readonly_fields = ['id', 'uploaded_at', 'ai_analysis', 'verification_passed']


@admin.register(AssessmentHistory)
class AssessmentHistoryAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'assessment', 'timestamp',
        'previous_score', 'new_score', 'changed_by'
    ]
    list_filter = ['timestamp']
    search_fields = ['change_reason', 'changed_by']
    readonly_fields = ['id', 'timestamp']


@admin.register(VulnerabilityFeedback)
class VulnerabilityFeedbackAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'feedback_type', 'vulnerable_component', 'assessment',
        'submitted_by', 'incorporated_in_training', 'chroma_vector_id', 'created_at'
    ]
    list_filter = ['feedback_type', 'incorporated_in_training', 'created_at']
    search_fields = [
        'explanation', 'false_positive_reason',
        'prior_control_name', 'missed_finding_title', 'submitted_by',
        'chroma_vector_id',
    ]
    readonly_fields = [
        'id', 'created_at', 'updated_at',
        'incorporated_in_training', 'training_job', 'chroma_vector_id',
    ]

    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'created_at', 'updated_at', 'feedback_type', 'submitted_by')
        }),
        ('Linked Records', {
            'fields': ('vulnerable_component', 'assessment')
        }),
        ('Feedback Content', {
            'fields': ('explanation',)
        }),
        ('False Positive Details', {
            'fields': ('false_positive_reason',),
            'classes': ('collapse',)
        }),
        ('Prior Control Details', {
            'fields': ('prior_control_name', 'prior_control_description', 'prior_control_evidence'),
            'classes': ('collapse',)
        }),
        ('Missed Finding Details', {
            'fields': (
                'missed_finding_title', 'missed_finding_description',
                'missed_finding_severity', 'missed_finding_category',
                'missed_finding_recommendation'
            ),
            'classes': ('collapse',)
        }),
        ('RAG / Training Status', {
            'fields': ('chroma_vector_id', 'incorporated_in_training', 'training_job'),
            'classes': ('collapse',)
        }),
    )


@admin.register(TrainingJob)
class TrainingJobAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'status', 'feedback_count',
        'false_positive_count', 'prior_control_count', 'missed_finding_count',
        'chroma_indexed_count', 'created_at', 'completed_at'
    ]
    list_filter = ['status', 'created_at']
    readonly_fields = [
        'id', 'created_at', 'started_at', 'completed_at',
        'feedback_count', 'false_positive_count', 'prior_control_count',
        'missed_finding_count', 'chroma_indexed_count',
        'training_summary', 'error_message',
        'refined_system_prompt',
    ]

    fieldsets = (
        ('Job Info', {
            'fields': ('id', 'status', 'created_at', 'started_at', 'completed_at')
        }),
        ('Feedback Stats', {
            'fields': (
                'feedback_count', 'false_positive_count',
                'prior_control_count', 'missed_finding_count',
                'chroma_indexed_count',
            )
        }),
        ('Results', {
            'fields': ('training_summary', 'error_message')
        }),
        ('Generated Prompt Addendum (internal)', {
            'fields': ('refined_system_prompt',),
            'classes': ('collapse',)
        }),
    )


@admin.register(TokenUsage)
class TokenUsageAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'user', 'operation', 'model_name',
        'prompt_tokens', 'completion_tokens', 'total_tokens',
        'estimated_cost_usd', 'created_at',
    ]
    list_filter = ['operation', 'model_name', 'created_at', 'user']
    search_fields = ['user__username', 'operation', 'model_name']
    readonly_fields = [
        'id', 'created_at', 'user', 'operation', 'model_name',
        'prompt_tokens', 'completion_tokens', 'total_tokens',
        'estimated_cost_usd', 'assessment', 'training_job',
    ]

    fieldsets = (
        ('Basic Info', {
            'fields': ('id', 'created_at', 'user', 'operation', 'model_name')
        }),
        ('Token Counts', {
            'fields': ('prompt_tokens', 'completion_tokens', 'total_tokens', 'estimated_cost_usd')
        }),
        ('Context', {
            'fields': ('assessment', 'training_job'),
            'classes': ('collapse',)
        }),
    )

    def has_add_permission(self, request):
        return False  # Token records are created programmatically only

    def has_change_permission(self, request, obj=None):
        return False  # Immutable audit log