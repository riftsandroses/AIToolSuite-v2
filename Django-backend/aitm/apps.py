# apps.py
from django.apps import AppConfig

class AitmConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'aitm'
    
    def ready(self):
        import aitm.signals  # Import signals