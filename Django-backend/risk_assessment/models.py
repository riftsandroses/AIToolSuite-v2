from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class ApplicationType(models.Model):
    name = models.CharField(max_length=100, unique=True)
    
    def __str__(self):
        return self.name

class RiskAssessment(models.Model):
    # Basic information
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Form responses
    application_name = models.CharField(max_length=255)
    business_logic = models.TextField()
    
    # Question 3
    SENSITIVITY_CHOICES = [
        ('none', 'No sensitive data'),
        ('pii', 'Personal Identifiable Information (PII)'),
        ('financial', 'Financial Data'),
        ('health', 'Health Data'),
        ('multiple', 'Multiple types of sensitive data')
    ]
    sensitive_data = models.CharField(max_length=20, choices=SENSITIVITY_CHOICES)
    
    # Question 4
    application_type = models.ForeignKey(ApplicationType, on_delete=models.PROTECT)
    
    # Question 5
    THIRD_PARTY_CHOICES = [
        ('none', 'No third-party integrations'),
        ('few', 'Few (1-3) third-party integrations'),
        ('many', 'Many (4+) third-party integrations'),
        ('critical', 'Critical dependencies on third-party services')
    ]
    third_party_integrations = models.CharField(max_length=20, choices=THIRD_PARTY_CHOICES)
    
    # Question 6
    ERROR_HANDLING_CHOICES = [
        ('basic', 'Basic error handling'),
        ('advanced', 'Advanced error handling with logging'),
        ('comprehensive', 'Comprehensive error handling, logging, and recovery'),
        ('minimal', 'Minimal or no error handling')
    ]
    error_handling = models.CharField(max_length=20, choices=ERROR_HANDLING_CHOICES)
    
    # Question 7
    USER_INPUT_CHOICES = [
        ('none', 'No file uploads or large data inputs'),
        ('text_only', 'Text inputs only, no file uploads'),
        ('limited_files', 'Limited file uploads with restrictions'),
        ('extensive_files', 'Extensive file upload capabilities')
    ]
    user_input_handling = models.CharField(max_length=20, choices=USER_INPUT_CHOICES)
    
    # Question 8
    ARCHITECTURE_CHOICES = [
        ('monolith', 'Monolithic Architecture'),
        ('client_server', 'Client-Server Architecture'),
        ('microservices', 'Microservices Architecture'),
        ('serverless', 'Serverless Architecture'),
        ('hybrid', 'Hybrid Architecture')
    ]
    architecture = models.CharField(max_length=20, choices=ARCHITECTURE_CHOICES)
    
    # Question 9
    HOSTING_CHOICES = [
        ('on_premise', 'On-Premise'),
        ('aws', 'Amazon Web Services (AWS)'),
        ('azure', 'Microsoft Azure'),
        ('gcp', 'Google Cloud Platform (GCP)'),
        ('other_cloud', 'Other Cloud Provider'),
        ('hybrid', 'Hybrid (Cloud + On-Premise)')
    ]
    hosting = models.CharField(max_length=20, choices=HOSTING_CHOICES)
    
    # Question 10
    tech_stack = models.TextField()
    
    # Question 11
    PLATFORM_CHOICES = [
        ('web_only', 'Web Application Only'),
        ('web_mobile', 'Web and Mobile Applications'),
        ('web_desktop', 'Web and Desktop Applications'),
        ('all', 'Web, Mobile, and Desktop Applications')
    ]
    platforms = models.CharField(max_length=20, choices=PLATFORM_CHOICES)
    
    # Question 12
    DATA_SECURITY_CHOICES = [
        ('basic', 'Basic Security (HTTPS, Simple Encryption)'),
        ('standard', 'Standard Security Practices'),
        ('advanced', 'Advanced Security (End-to-end Encryption, etc.)'),
        ('minimal', 'Minimal Security Measures')
    ]
    data_security = models.CharField(max_length=20, choices=DATA_SECURITY_CHOICES)
    
    # Question 13
    LEGACY_DEPENDENCIES_CHOICES = [
        ('none', 'No Legacy Dependencies'),
        ('minor', 'Minor Legacy Dependencies'),
        ('major', 'Major Legacy Dependencies'),
        ('critical', 'Critical Legacy Dependencies')
    ]
    legacy_dependencies = models.CharField(max_length=20, choices=LEGACY_DEPENDENCIES_CHOICES)
    
    # Question 14
    MONITORING_CHOICES = [
        ('comprehensive', 'Comprehensive Monitoring and Alerts'),
        ('standard', 'Standard Logging and Monitoring'),
        ('basic', 'Basic Logging Only'),
        ('minimal', 'Minimal or No Monitoring')
    ]
    monitoring = models.CharField(max_length=20, choices=MONITORING_CHOICES)
    
    # Results
    application_description = models.TextField(blank=True, null=True)
    risk_score = models.FloatField(default=0.0)
    
    def __str__(self):
        return f"Risk Assessment for {self.application_name}"
    
    def calculate_risk_score(self):
        """Calculate risk score based on the answers provided"""
        score = 0
        
        # Sensitive data handling (0-25 points)
        if self.sensitive_data == 'none':
            score += 0
        elif self.sensitive_data == 'pii':
            score += 15
        elif self.sensitive_data == 'financial':
            score += 20
        elif self.sensitive_data == 'health':
            score += 25
        elif self.sensitive_data == 'multiple':
            score += 25
            
        # Third-party integrations (0-15 points)
        if self.third_party_integrations == 'none':
            score += 0
        elif self.third_party_integrations == 'few':
            score += 5
        elif self.third_party_integrations == 'many':
            score += 10
        elif self.third_party_integrations == 'critical':
            score += 15
            
        # Error handling (0-10 points)
        if self.error_handling == 'comprehensive':
            score += 0
        elif self.error_handling == 'advanced':
            score += 3
        elif self.error_handling == 'basic':
            score += 7
        elif self.error_handling == 'minimal':
            score += 10
            
        # User input handling (0-15 points)
        if self.user_input_handling == 'none':
            score += 0
        elif self.user_input_handling == 'text_only':
            score += 5
        elif self.user_input_handling == 'limited_files':
            score += 10
        elif self.user_input_handling == 'extensive_files':
            score += 15
            
        # Cloud hosting (0-10 points)
        if self.hosting == 'on_premise':
            score += 3
        elif self.hosting in ['aws', 'azure', 'gcp']:
            score += 7
        elif self.hosting == 'other_cloud':
            score += 10
        elif self.hosting == 'hybrid':
            score += 5
            
        # Platform diversity (0-10 points)
        if self.platforms == 'web_only':
            score += 3
        elif self.platforms in ['web_mobile', 'web_desktop']:
            score += 7
        elif self.platforms == 'all':
            score += 10
            
        # Data security (0-20 points)
        if self.data_security == 'advanced':
            score += 0
        elif self.data_security == 'standard':
            score += 8
        elif self.data_security == 'basic':
            score += 15
        elif self.data_security == 'minimal':
            score += 20
            
        # Legacy dependencies (0-15 points)
        if self.legacy_dependencies == 'none':
            score += 0
        elif self.legacy_dependencies == 'minor':
            score += 5
        elif self.legacy_dependencies == 'major':
            score += 10
        elif self.legacy_dependencies == 'critical':
            score += 15
            
        # Monitoring (0-10 points)
        if self.monitoring == 'comprehensive':
            score += 0
        elif self.monitoring == 'standard':
            score += 3
        elif self.monitoring == 'basic':
            score += 7
        elif self.monitoring == 'minimal':
            score += 10
        
        return score