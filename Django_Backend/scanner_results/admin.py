from django.contrib import admin
from .models import ProbeControlMapping

@admin.register(ProbeControlMapping)
class ProbeControlMappingAdmin(admin.ModelAdmin):
    list_display = ('probe_name', 'control_title')
    search_fields = ('probe_name', 'control_title', 'control_description')