

import os
import pickle
from django.db import models
from django.conf import settings
from django.contrib.auth.models import User

def get_upload_path(instance, filename):
    # This will create a path like: media/YourAppName/pdf/yourfile.pdf
    return os.path.join(
        instance.threat_model.app_name,
        instance.file_type,
        filename
    )

class ThreatModel(models.Model):
    """
    Stores information and results for a threat modeling session.
    """
    class StatusChoices(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    # --- Core Assessment Info ---
    assessment_name = models.CharField(max_length=255)
    app_name = models.CharField(max_length=255, unique=True, help_text="Unique name for the application, used for directory paths.")
    client_name = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='threat_models')

    # --- Detailed System Context ---
    description = models.TextField(blank=True, help_text="High-level description of the application's purpose and functionality.")
    authentication_methods = models.CharField(max_length=255, blank=True, help_text="e.g., 'SSO, MFA, API Keys'")
    is_internet_facing = models.BooleanField(default=True, help_text="Is the application exposed to the internet?")
    handles_sensitive_data = models.BooleanField(default=False, help_text="Does it handle PII, PHI, or financial data?")
    data_classification = models.CharField(max_length=100, blank=True, help_text="e.g., Public, Internal, Confidential, Restricted")
    deployment_environment = models.CharField(max_length=100, blank=True, help_text="e.g., AWS, Azure, On-premise")
    compliance_requirements = models.TextField(blank=True, help_text="e.g., GDPR, HIPAA, PCI-DSS")
    user_types = models.TextField(blank=True, help_text="e.g., 'Authenticated Users, Anonymous Users, Administrators'")
    third_party_integrations = models.TextField(blank=True, help_text="List of third-party APIs or services used.")
    critical_assets = models.TextField(blank=True, help_text="e.g., 'Customer PII, Payment Transactions, JWT Tokens'")
    technology_stack = models.JSONField(default=dict, blank=True, help_text="e.g., {'frontend': 'React', 'backend': 'Django', 'database': 'PostgreSQL'}")

    # --- Analysis Results & Status ---
    threat_model_data = models.JSONField(default=dict, blank=True, help_text="Stores the generated STRIDE threat model from the LLM.")
    context_completeness = models.FloatField(default=0.0, help_text="Score (0.0-1.0) indicating how complete the provided context is.")
    confidence_score = models.FloatField(default=0.0, help_text="Overall confidence score (0.0-1.0) of the generated threat model.")
    status = models.CharField(max_length=20, choices=StatusChoices.choices, default=StatusChoices.PENDING)
    last_analysis_at = models.DateTimeField(null=True, blank=True, help_text="Timestamp of the last analysis run.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    dread_assessment_data = models.JSONField(default=dict, blank=True, help_text="Stores the generated DREAD risk assessment.")
    pasta_assessment_data = models.JSONField(default=dict, blank=True, help_text="Stores the multi-stage PASTA assessment results.")
    attack_tree_data = models.JSONField(default=dict, blank=True, help_text="Stores the generated Attack Tree data.")
    
    def __str__(self):
        return f"Threat Model for {self.app_name} ({self.id})"

    def get_context_summary(self):
        """
        Provides a dictionary summary of the application context.
        Used for populating the LLM prompt.
        """
        return {
            "authentication": self.authentication_methods or "Not specified",
            "internet_facing": "Yes" if self.is_internet_facing else "No",
            "sensitive_data": "Yes" if self.handles_sensitive_data else "No",
            "data_classification": self.data_classification or "Not specified",
            "deployment": self.deployment_environment or "Not specified",
            "compliance": self.compliance_requirements or "Not specified",
            "user_types": self.user_types or "Not specified",
            "integrations": self.third_party_integrations or "None",
            "critical_assets": self.critical_assets or "Not specified",
            "technology_stack": self.technology_stack or {}
        }

    def get_context_completeness(self):
        """
        Calculates a simple completeness score based on filled-out fields.
        """
        fields_to_check = [
            self.description, self.authentication_methods, self.data_classification,
            self.deployment_environment, self.compliance_requirements,
            self.user_types, self.third_party_integrations, self.technology_stack
        ]
        filled_fields = sum(1 for field in fields_to_check if field)
        return filled_fields / len(fields_to_check)

    def get_total_docs_from_faiss_metadata(self):
        """
        Gets the total number of unique documents from the latest FAISS metadata file.
        Provides an accurate count for the document coverage calculation.
        """
        metadata_path = os.path.join(settings.BASE_DIR, "faiss_indexes", self.app_name, "latest", "metadata.pkl")
        if not os.path.exists(metadata_path):
            raise FileNotFoundError("FAISS metadata.pkl not found.")

        with open(metadata_path, "rb") as f:
            metadata = pickle.load(f)

        # Count the number of unique filenames in the metadata
        unique_filenames = set(item['filename'] for item in metadata)
        return len(unique_filenames)


# --- Document Class ---

class Document(models.Model):
    """
    Stores individual documents related to a ThreatModel session.
    """
    threat_model = models.ForeignKey(ThreatModel, on_delete=models.CASCADE, related_name='documents')
    file = models.FileField(upload_to=get_upload_path)
    file_type = models.CharField(max_length=10) # Removed choices to allow for any extension
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file.name} for {self.threat_model.app_name}"
    
class History(models.Model):
    """
    Stores an audit trail of user actions within the system.
    """
    class ActionChoices(models.TextChoices):
        CREATE_ASSESSMENT = 'CREATE_ASSESSMENT', 'Created Assessment'
        REASSESS_MODEL = 'REASSESS_MODEL', 'Re-assessed Model'
        RUN_STRIDE_ANALYSIS = 'RUN_STRIDE_ANALYSIS', 'Ran STRIDE Analysis'
        RUN_DREAD_ASSESSMENT = 'RUN_DREAD_ASSESSMENT', 'Ran DREAD Assessment'
        RUN_PASTA_ASSESSMENT = 'RUN_PASTA_ASSESSMENT', 'Ran PASTA Assessment'
        GENERATE_ATTACK_TREE = 'GENERATE_ATTACK_TREE', 'Generated Attack Tree'
        DOWNLOAD_REPORT = 'DOWNLOAD_REPORT', 'Downloaded Report'

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='history_events')
    threat_model = models.ForeignKey(ThreatModel, on_delete=models.SET_NULL, null=True, blank=True, related_name='history_events')
    action = models.CharField(max_length=50, choices=ActionChoices.choices)
    details = models.JSONField(default=dict, blank=True, help_text="Extra details, e.g., uploaded filenames or report format.")
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = "History"

    def __str__(self):
        return f"{self.user.username} - {self.get_action_display()} on {self.timestamp.strftime('%Y-%m-%d %H:%M')}"