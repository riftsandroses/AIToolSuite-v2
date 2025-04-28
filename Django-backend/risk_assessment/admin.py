from django.contrib import admin
from .models import ApplicationType, RiskAssessment

@admin.register(ApplicationType)
class ApplicationTypeAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)

@admin.register(RiskAssessment)
class RiskAssessmentAdmin(admin.ModelAdmin):
    list_display = ('application_name', 'user', 'application_type', 'sensitive_data', 'risk_score', 'created_at')
    list_filter = ('application_type', 'sensitive_data', 'hosting', 'platforms')
    search_fields = ('application_name', 'business_logic', 'tech_stack')
    readonly_fields = ('risk_score', 'application_description')
    fieldsets = (
        ('Basic Information', {
            'fields': ('user', 'application_name', 'business_logic', 'application_type')
        }),
        ('Security & Risk Factors', {
            'fields': ('sensitive_data', 'third_party_integrations', 'error_handling', 
                      'user_input_handling', 'data_security', 'legacy_dependencies')
        }),
        ('Technical Details', {
            'fields': ('architecture', 'hosting', 'tech_stack', 'platforms', 'monitoring')
        }),
        ('Results', {
            'fields': ('risk_score', 'application_description')
        }),
    )