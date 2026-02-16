from django.apps import AppConfig


class ArchitectureAssessmentConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "architecture_assessment"
    verbose_name = 'Architecture Assessment'
    
    def ready(self):
        """Initialize app components"""
        pass