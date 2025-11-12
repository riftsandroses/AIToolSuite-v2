from django.contrib import admin
from .models import APIVersionCheck

@admin.register(APIVersionCheck)
class APIVersionCheckAdmin(admin.ModelAdmin):
    list_display = ['scan_id', 'original_api_url', 'version', 'is_accessible', 'response_status_code', 'checked_at']
    list_filter = ['is_accessible', 'checked_at', 'response_status_code']
    search_fields = ['scan_id', 'original_api_url', 'version']
    readonly_fields = ['checked_at']