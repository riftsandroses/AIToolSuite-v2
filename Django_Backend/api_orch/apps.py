# api_orch/apps.py
from django.apps import AppConfig


class ApiOrchConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api_orch'
    verbose_name = 'API Orchestrator'