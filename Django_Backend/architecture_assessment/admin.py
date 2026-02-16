from django.contrib import admin
from .models import (
    SecurityAssessment,
    VulnerableComponent,
    RemediationControl,
    AssessmentHistory
)


@admin.register(SecurityAssessment)
class SecurityAssessmentAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'created_at', 'status', 'overall_risk_score',
        'application_purpose', 'business_criticality'
    ]
    list_filter = ['status', 'created_at', 'business_criticality']
    search_fields = [
        'application_purpose', 'business_objectives',
        'stakeholders', 'programming_languages'
    ]
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'created_at', 'updated_at', 'status',
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
        'status', 'category_tag', 'created_at'
    ]
    list_filter = ['severity', 'status', 'category_tag', 'created_at']
    search_fields = [
        'control_title', 'control_description',
        'affected_devices', 'framework_mapping'
    ]
    readonly_fields = ['id', 'created_at', 'updated_at']
    
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
    )


@admin.register(RemediationControl)
class RemediationControlAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'vulnerable_component', 'control_name',
        'status', 'risk_reduction_percentage', 'created_at'
    ]
    list_filter = ['status', 'created_at']
    search_fields = ['control_name', 'control_description', 'verified_by']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
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
    )


@admin.register(AssessmentHistory)
class AssessmentHistoryAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'assessment', 'timestamp',
        'previous_score', 'new_score', 'changed_by'
    ]
    list_filter = ['timestamp']
    search_fields = ['change_reason', 'changed_by']
    readonly_fields = ['id', 'timestamp']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'assessment', 'timestamp')
        }),
        ('Score Change', {
            'fields': (
                'previous_score', 'new_score',
                'change_reason', 'changed_by'
            )
        }),
    )