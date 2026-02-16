from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid


class SecurityAssessment(models.Model):
    """Main assessment model containing all security analysis data"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Core Information (Architecture diagram is mandatory)
    architecture_diagram = models.FileField(upload_to='architecture_diagrams/', null=False)
    
    # Application Context (all optional except architecture)
    application_purpose = models.TextField(blank=True, null=True)
    business_objectives = models.TextField(blank=True, null=True)
    business_criticality = models.CharField(max_length=50, blank=True, null=True)
    impact_of_failure = models.TextField(blank=True, null=True)
    supported_business_processes = models.TextField(blank=True, null=True)
    data_sensitivity = models.TextField(blank=True, null=True)
    data_classification_levels = models.TextField(blank=True, null=True)
    regulatory_requirements = models.TextField(blank=True, null=True)
    compliance_requirements = models.TextField(blank=True, null=True)
    stakeholders = models.TextField(blank=True, null=True)
    system_owners = models.TextField(blank=True, null=True)
    risk_tolerance = models.TextField(blank=True, null=True)
    risk_acceptance_criteria = models.TextField(blank=True, null=True)
    
    # Application Overview
    application_type = models.CharField(max_length=100, blank=True, null=True)
    usage_model = models.TextField(blank=True, null=True)
    functional_overview = models.TextField(blank=True, null=True)
    major_modules = models.TextField(blank=True, null=True)
    user_roles = models.TextField(blank=True, null=True)
    access_types = models.TextField(blank=True, null=True)
    expected_traffic = models.TextField(blank=True, null=True)
    load_patterns = models.TextField(blank=True, null=True)
    deployment_model = models.CharField(max_length=100, blank=True, null=True)
    
    # Architecture Details
    high_level_architecture = models.FileField(upload_to='architecture_files/', blank=True, null=True)
    logical_architecture = models.FileField(upload_to='architecture_files/', blank=True, null=True)
    physical_architecture = models.FileField(upload_to='architecture_files/', blank=True, null=True)
    data_flow_diagrams = models.FileField(upload_to='architecture_files/', blank=True, null=True)
    trust_boundaries = models.TextField(blank=True, null=True)
    component_interaction = models.TextField(blank=True, null=True)
    design_patterns = models.TextField(blank=True, null=True)
    
    # Technology Stack
    programming_languages = models.TextField(blank=True, null=True)
    frameworks_versions = models.TextField(blank=True, null=True)
    libraries_packages = models.TextField(blank=True, null=True)
    runtime_environments = models.TextField(blank=True, null=True)
    databases = models.TextField(blank=True, null=True)
    storage_systems = models.TextField(blank=True, null=True)
    middleware_components = models.TextField(blank=True, null=True)
    message_queues = models.TextField(blank=True, null=True)
    api_gateways = models.TextField(blank=True, null=True)
    web_servers = models.TextField(blank=True, null=True)
    application_servers = models.TextField(blank=True, null=True)
    
    # Infrastructure
    containerization_platforms = models.TextField(blank=True, null=True)
    orchestration_platforms = models.TextField(blank=True, null=True)
    hosting_environment = models.CharField(max_length=100, blank=True, null=True)
    cloud_services = models.TextField(blank=True, null=True)
    network_architecture = models.TextField(blank=True, null=True)
    network_topology = models.TextField(blank=True, null=True)
    network_segmentation = models.TextField(blank=True, null=True)
    subnets = models.TextField(blank=True, null=True)
    load_balancers = models.TextField(blank=True, null=True)
    traffic_routing = models.TextField(blank=True, null=True)
    firewall_config = models.TextField(blank=True, null=True)
    waf_config = models.TextField(blank=True, null=True)
    cdn_usage = models.TextField(blank=True, null=True)
    regions = models.TextField(blank=True, null=True)
    availability_zones = models.TextField(blank=True, null=True)
    
    # High Availability & DR
    high_availability_design = models.TextField(blank=True, null=True)
    backup_architecture = models.TextField(blank=True, null=True)
    disaster_recovery_setup = models.TextField(blank=True, null=True)
    
    # Authentication & Authorization
    authentication_mechanisms = models.TextField(blank=True, null=True)
    authorization_model = models.TextField(blank=True, null=True)
    sso_federation = models.TextField(blank=True, null=True)
    mfa_enforcement = models.TextField(blank=True, null=True)
    service_authentication = models.TextField(blank=True, null=True)
    secrets_management = models.TextField(blank=True, null=True)
    key_management = models.TextField(blank=True, null=True)
    privileged_access_controls = models.TextField(blank=True, null=True)
    account_provisioning = models.TextField(blank=True, null=True)
    account_deprovisioning = models.TextField(blank=True, null=True)
    
    # Data Security
    data_types_processed = models.TextField(blank=True, null=True)
    data_types_stored = models.TextField(blank=True, null=True)
    sensitive_data_locations = models.TextField(blank=True, null=True)
    data_flow_paths = models.TextField(blank=True, null=True)
    encryption_at_rest = models.TextField(blank=True, null=True)
    encryption_in_transit = models.TextField(blank=True, null=True)
    key_rotation_practices = models.TextField(blank=True, null=True)
    data_retention_policies = models.TextField(blank=True, null=True)
    data_masking = models.TextField(blank=True, null=True)
    data_tokenization = models.TextField(blank=True, null=True)
    sensitive_data_in_logs = models.TextField(blank=True, null=True)
    data_import_paths = models.TextField(blank=True, null=True)
    data_export_paths = models.TextField(blank=True, null=True)
    
    # Integrations & APIs
    third_party_integrations = models.TextField(blank=True, null=True)
    external_dependencies = models.TextField(blank=True, null=True)
    internal_apis = models.TextField(blank=True, null=True)
    external_apis = models.TextField(blank=True, null=True)
    partner_integrations = models.TextField(blank=True, null=True)
    vendor_integrations = models.TextField(blank=True, null=True)
    webhooks = models.TextField(blank=True, null=True)
    callbacks = models.TextField(blank=True, null=True)
    file_transfer_interfaces = models.TextField(blank=True, null=True)
    api_authentication = models.TextField(blank=True, null=True)
    rate_limiting = models.TextField(blank=True, null=True)
    
    # Security Controls
    input_validation_controls = models.TextField(blank=True, null=True)
    secure_coding_standards = models.TextField(blank=True, null=True)
    threat_modeling_status = models.TextField(blank=True, null=True)
    security_design_reviews = models.TextField(blank=True, null=True)
    output_encoding_controls = models.TextField(blank=True, null=True)
    error_handling_approach = models.TextField(blank=True, null=True)
    session_management = models.TextField(blank=True, null=True)
    injection_protections = models.TextField(blank=True, null=True)
    xss_protections = models.TextField(blank=True, null=True)
    dependency_scanning = models.TextField(blank=True, null=True)
    container_scanning = models.TextField(blank=True, null=True)
    image_scanning = models.TextField(blank=True, null=True)
    runtime_security_controls = models.TextField(blank=True, null=True)
    
    # Network Security
    network_protocols = models.TextField(blank=True, null=True)
    open_ports = models.TextField(blank=True, null=True)
    exposed_services = models.TextField(blank=True, null=True)
    tls_configuration = models.TextField(blank=True, null=True)
    certificate_management = models.TextField(blank=True, null=True)
    internal_external_exposure = models.TextField(blank=True, null=True)
    zero_trust_controls = models.TextField(blank=True, null=True)
    service_mesh_controls = models.TextField(blank=True, null=True)
    
    # SDLC & DevSecOps
    sdlc_methodology = models.TextField(blank=True, null=True)
    code_review_requirements = models.TextField(blank=True, null=True)
    static_analysis_tooling = models.TextField(blank=True, null=True)
    dynamic_testing_tooling = models.TextField(blank=True, null=True)
    sca_tooling = models.TextField(blank=True, null=True)
    cicd_pipeline_design = models.TextField(blank=True, null=True)
    build_artifact_controls = models.TextField(blank=True, null=True)
    environment_separation = models.TextField(blank=True, null=True)
    secrets_handling_pipelines = models.TextField(blank=True, null=True)
    
    # Monitoring & Logging
    logging_architecture = models.TextField(blank=True, null=True)
    security_event_logging = models.TextField(blank=True, null=True)
    centralized_log_collection = models.TextField(blank=True, null=True)
    siem_integration = models.TextField(blank=True, null=True)
    alerting_rules = models.TextField(blank=True, null=True)
    detection_rules = models.TextField(blank=True, null=True)
    monitoring_coverage = models.TextField(blank=True, null=True)
    audit_trail = models.TextField(blank=True, null=True)
    log_retention_periods = models.TextField(blank=True, null=True)
    
    # Operations
    patch_management = models.TextField(blank=True, null=True)
    configuration_management = models.TextField(blank=True, null=True)
    change_management = models.TextField(blank=True, null=True)
    incident_response_procedures = models.TextField(blank=True, null=True)
    operational_runbooks = models.TextField(blank=True, null=True)
    support_maintenance_model = models.TextField(blank=True, null=True)
    
    # Resilience
    fault_tolerance_mechanisms = models.TextField(blank=True, null=True)
    redundancy_design = models.TextField(blank=True, null=True)
    auto_scaling_config = models.TextField(blank=True, null=True)
    retry_logic = models.TextField(blank=True, null=True)
    circuit_breaker_logic = models.TextField(blank=True, null=True)
    backup_restore_testing = models.TextField(blank=True, null=True)
    rto_targets = models.TextField(blank=True, null=True)
    rpo_targets = models.TextField(blank=True, null=True)
    
    # Third-Party Risk
    third_party_services = models.TextField(blank=True, null=True)
    vendor_risk_assessments = models.TextField(blank=True, null=True)
    open_source_components = models.TextField(blank=True, null=True)
    license_risks = models.TextField(blank=True, null=True)
    dependency_update_cadence = models.TextField(blank=True, null=True)
    component_support_status = models.TextField(blank=True, null=True)
    
    # Compliance & Risk
    compliance_standards = models.TextField(blank=True, null=True)
    control_framework_mappings = models.TextField(blank=True, null=True)
    prior_audit_findings = models.TextField(blank=True, null=True)
    policy_exceptions = models.TextField(blank=True, null=True)
    existing_risk_register = models.TextField(blank=True, null=True)
    known_vulnerabilities = models.TextField(blank=True, null=True)
    accepted_risks = models.TextField(blank=True, null=True)
    
    # Technical Debt & Constraints
    architecture_assumptions = models.TextField(blank=True, null=True)
    design_constraints = models.TextField(blank=True, null=True)
    technical_debt_areas = models.TextField(blank=True, null=True)
    
    # Assessment Results
    overall_risk_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        null=True,
        blank=True
    )
    risk_reasoning = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'security_assessments'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['overall_risk_score']),
        ]
    
    def __str__(self):
        return f"Assessment {self.id} - Score: {self.overall_risk_score}"


class VulnerableComponent(models.Model):
    """Findings/vulnerable components identified in the assessment"""
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('informational', 'Informational'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('fixed', 'Fixed'),
        ('accepted', 'Accepted'),
        ('false_positive', 'False Positive'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(
        SecurityAssessment,
        on_delete=models.CASCADE,
        related_name='vulnerable_components'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Finding Details
    control_title = models.CharField(max_length=255)
    control_description = models.TextField(help_text="Should start with 'It was observed...'")
    control_impact = models.TextField(help_text="Describe what happens if exploited")
    control_recommendation = models.TextField(help_text="Should start with 'It is recommended...'")
    
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    affected_devices = models.TextField(blank=True, null=True)
    category_tag = models.CharField(max_length=100)
    framework_mapping = models.TextField(
        help_text="e.g., NIST CSF, CIS Controls, OWASP, ISO 27001",
        blank=True,
        null=True
    )
    
    # Additional context
    cvss_score = models.DecimalField(
        max_digits=3,
        decimal_places=1,
        null=True,
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(10.0)]
    )
    cwe_id = models.CharField(max_length=50, blank=True, null=True)
    owasp_category = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        db_table = 'vulnerable_components'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['assessment', 'severity']),
            models.Index(fields=['status']),
            models.Index(fields=['category_tag']),
        ]
    
    def __str__(self):
        return f"{self.control_title} - {self.severity}"


class RemediationControl(models.Model):
    """Controls/patches implemented to fix vulnerabilities"""
    
    STATUS_CHOICES = [
        ('planned', 'Planned'),
        ('in_progress', 'In Progress'),
        ('implemented', 'Implemented'),
        ('verified', 'Verified'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerable_component = models.ForeignKey(
        VulnerableComponent,
        on_delete=models.CASCADE,
        related_name='remediation_controls'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    control_name = models.CharField(max_length=255)
    control_description = models.TextField()
    implementation_details = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='planned')
    
    # Impact on risk
    risk_reduction_percentage = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Expected percentage reduction in risk"
    )
    
    # Verification
    verification_notes = models.TextField(blank=True, null=True)
    verified_by = models.CharField(max_length=255, blank=True, null=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    
    # Supporting documents
    evidence_files = models.FileField(
        upload_to='remediation_evidence/',
        blank=True,
        null=True
    )
    
    class Meta:
        db_table = 'remediation_controls'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['vulnerable_component', 'status']),
        ]
    
    def __str__(self):
        return f"{self.control_name} - {self.status}"


class AssessmentHistory(models.Model):
    """Track changes to assessment risk scores over time"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(
        SecurityAssessment,
        on_delete=models.CASCADE,
        related_name='history'
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    
    previous_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        null=True
    )
    new_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    change_reason = models.TextField()
    changed_by = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        db_table = 'assessment_history'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['assessment', '-timestamp']),
        ]
    
    def __str__(self):
        return f"Score change: {self.previous_score} -> {self.new_score}"