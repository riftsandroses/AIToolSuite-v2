from rest_framework import serializers
from .models import (
    SecurityAssessment,
    VulnerableComponent,
    RemediationControl,
    AssessmentHistory
)


class RemediationControlSerializer(serializers.ModelSerializer):
    """Serializer for remediation controls"""
    
    class Meta:
        model = RemediationControl
        fields = [
            'id', 'control_name', 'control_description',
            'implementation_details', 'status', 'risk_reduction_percentage',
            'verification_notes', 'verified_by', 'verified_at',
            'evidence_files', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class VulnerableComponentSerializer(serializers.ModelSerializer):
    """Serializer for vulnerable components/findings"""
    
    remediation_controls = RemediationControlSerializer(many=True, read_only=True)
    remediation_count = serializers.SerializerMethodField()
    is_remediated = serializers.SerializerMethodField()
    
    class Meta:
        model = VulnerableComponent
        fields = [
            'id', 'control_title', 'control_description', 'control_impact',
            'control_recommendation', 'severity', 'status', 'affected_devices',
            'category_tag', 'framework_mapping', 'cvss_score', 'cwe_id',
            'owasp_category', 'remediation_controls', 'remediation_count',
            'is_remediated', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_remediation_count(self, obj):
        return obj.remediation_controls.filter(status='implemented').count()
    
    def get_is_remediated(self, obj):
        return obj.status == 'fixed'
    
    def validate_control_description(self, value):
        """Ensure control description starts with 'It was observed'"""
        if not value.strip().lower().startswith('it was observed'):
            raise serializers.ValidationError(
                "Control description must start with 'It was observed...'"
            )
        return value
    
    def validate_control_recommendation(self, value):
        """Ensure control recommendation starts with 'It is recommended'"""
        if not value.strip().lower().startswith('it is recommended'):
            raise serializers.ValidationError(
                "Control recommendation must start with 'It is recommended...'"
            )
        return value


class AssessmentHistorySerializer(serializers.ModelSerializer):
    """Serializer for assessment history"""
    
    score_change = serializers.SerializerMethodField()
    
    class Meta:
        model = AssessmentHistory
        fields = [
            'id', 'previous_score', 'new_score', 'score_change',
            'change_reason', 'changed_by', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']
    
    def get_score_change(self, obj):
        if obj.previous_score is not None:
            return obj.new_score - obj.previous_score
        return 0


class SecurityAssessmentListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing assessments"""
    
    vulnerability_count = serializers.SerializerMethodField()
    critical_count = serializers.SerializerMethodField()
    high_count = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityAssessment
        fields = [
            'id', 'created_at', 'updated_at', 'status',
            'overall_risk_score', 'vulnerability_count',
            'critical_count', 'high_count', 'application_purpose'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_vulnerability_count(self, obj):
        return obj.vulnerable_components.filter(status='open').count()
    
    def get_critical_count(self, obj):
        return obj.vulnerable_components.filter(
            severity='critical',
            status='open'
        ).count()
    
    def get_high_count(self, obj):
        return obj.vulnerable_components.filter(
            severity='high',
            status='open'
        ).count()


class SecurityAssessmentDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for assessment with all fields and relationships"""
    
    vulnerable_components = VulnerableComponentSerializer(many=True, read_only=True)
    history = AssessmentHistorySerializer(many=True, read_only=True)
    vulnerability_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityAssessment
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'overall_risk_score', 'risk_reasoning']
    
    def get_vulnerability_summary(self, obj):
        """Get summary of vulnerabilities by severity"""
        components = obj.vulnerable_components.filter(status='open')
        return {
            'total': components.count(),
            'critical': components.filter(severity='critical').count(),
            'high': components.filter(severity='high').count(),
            'medium': components.filter(severity='medium').count(),
            'low': components.filter(severity='low').count(),
            'informational': components.filter(severity='informational').count(),
        }


class SecurityAssessmentCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new assessments"""
    
    class Meta:
        model = SecurityAssessment
        fields = [
            'architecture_diagram',
            'application_purpose', 'business_objectives', 'business_criticality',
            'impact_of_failure', 'supported_business_processes', 'data_sensitivity',
            'data_classification_levels', 'regulatory_requirements', 
            'compliance_requirements', 'stakeholders', 'system_owners',
            'risk_tolerance', 'risk_acceptance_criteria', 'application_type',
            'usage_model', 'functional_overview', 'major_modules', 'user_roles',
            'access_types', 'expected_traffic', 'load_patterns', 'deployment_model',
            'high_level_architecture', 'logical_architecture', 'physical_architecture',
            'data_flow_diagrams', 'trust_boundaries', 'component_interaction',
            'design_patterns', 'programming_languages', 'frameworks_versions',
            'libraries_packages', 'runtime_environments', 'databases',
            'storage_systems', 'middleware_components', 'message_queues',
            'api_gateways', 'web_servers', 'application_servers',
            'containerization_platforms', 'orchestration_platforms',
            'hosting_environment', 'cloud_services', 'network_architecture',
            'network_topology', 'network_segmentation', 'subnets',
            'load_balancers', 'traffic_routing', 'firewall_config', 'waf_config',
            'cdn_usage', 'regions', 'availability_zones',
            'high_availability_design', 'backup_architecture',
            'disaster_recovery_setup', 'authentication_mechanisms',
            'authorization_model', 'sso_federation', 'mfa_enforcement',
            'service_authentication', 'secrets_management', 'key_management',
            'privileged_access_controls', 'account_provisioning',
            'account_deprovisioning', 'data_types_processed', 'data_types_stored',
            'sensitive_data_locations', 'data_flow_paths', 'encryption_at_rest',
            'encryption_in_transit', 'key_rotation_practices',
            'data_retention_policies', 'data_masking', 'data_tokenization',
            'sensitive_data_in_logs', 'data_import_paths', 'data_export_paths',
            'third_party_integrations', 'external_dependencies', 'internal_apis',
            'external_apis', 'partner_integrations', 'vendor_integrations',
            'webhooks', 'callbacks', 'file_transfer_interfaces',
            'api_authentication', 'rate_limiting', 'input_validation_controls',
            'secure_coding_standards', 'threat_modeling_status',
            'security_design_reviews', 'output_encoding_controls',
            'error_handling_approach', 'session_management', 'injection_protections',
            'xss_protections', 'dependency_scanning', 'container_scanning',
            'image_scanning', 'runtime_security_controls', 'network_protocols',
            'open_ports', 'exposed_services', 'tls_configuration',
            'certificate_management', 'internal_external_exposure',
            'zero_trust_controls', 'service_mesh_controls', 'sdlc_methodology',
            'code_review_requirements', 'static_analysis_tooling',
            'dynamic_testing_tooling', 'sca_tooling', 'cicd_pipeline_design',
            'build_artifact_controls', 'environment_separation',
            'secrets_handling_pipelines', 'logging_architecture',
            'security_event_logging', 'centralized_log_collection',
            'siem_integration', 'alerting_rules', 'detection_rules',
            'monitoring_coverage', 'audit_trail', 'log_retention_periods',
            'patch_management', 'configuration_management', 'change_management',
            'incident_response_procedures', 'operational_runbooks',
            'support_maintenance_model', 'fault_tolerance_mechanisms',
            'redundancy_design', 'auto_scaling_config', 'retry_logic',
            'circuit_breaker_logic', 'backup_restore_testing', 'rto_targets',
            'rpo_targets', 'third_party_services', 'vendor_risk_assessments',
            'open_source_components', 'license_risks',
            'dependency_update_cadence', 'component_support_status',
            'compliance_standards', 'control_framework_mappings',
            'prior_audit_findings', 'policy_exceptions',
            'existing_risk_register', 'known_vulnerabilities', 'accepted_risks',
            'architecture_assumptions', 'design_constraints', 'technical_debt_areas'
        ]
    
    def validate_architecture_diagram(self, value):
        """Validate that architecture diagram is provided and is an image"""
        if not value:
            raise serializers.ValidationError("Architecture diagram is required")
        
        # Check file extension
        allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg', 'pdf']
        ext = value.name.split('.')[-1].lower()
        if ext not in allowed_extensions:
            raise serializers.ValidationError(
                f"Invalid file type. Allowed types: {', '.join(allowed_extensions)}"
            )
        
        # Check file size (max 10MB)
        if value.size > 10 * 1024 * 1024:
            raise serializers.ValidationError("File size must be under 10MB")
        
        return value


class VulnerableComponentUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating vulnerable component status"""
    
    class Meta:
        model = VulnerableComponent
        fields = ['status', 'affected_devices', 'framework_mapping']
    
    def validate_status(self, value):
        """Validate status transitions"""
        if self.instance and self.instance.status == 'fixed' and value != 'fixed':
            raise serializers.ValidationError(
                "Cannot reopen a fixed vulnerability. Create a new finding instead."
            )
        return value