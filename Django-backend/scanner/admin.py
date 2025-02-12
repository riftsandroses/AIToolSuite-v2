from django.contrib import admin
from .models import OpenAIIntegration, AzureDeployment, ValueMapping

@admin.register(OpenAIIntegration)
class OpenAIIntegrationAdmin(admin.ModelAdmin):
    list_display = ['scan_name', 'user', 'created_at']
    search_fields = ['scan_name', 'user__username']

@admin.register(AzureDeployment)
class AzureDeploymentAdmin(admin.ModelAdmin):
    list_display = ['scan_name', 'user', 'created_at']
    search_fields = ['scan_name', 'user__username']

@admin.register(ValueMapping)
class ValueMappingAdmin(admin.ModelAdmin):
    list_display = ('id', 'attack_name', 'probes_name')  # Columns displayed in the admin list view
    search_fields = ('attack_name', 'probes_name')       # Add search functionality for these fields