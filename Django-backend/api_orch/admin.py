# api_orch/admin.py
from django.contrib import admin
from .models import Scan, PostmanAPI


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan_name', 'client_name', 'client_app_name', 'created_by', 'created_at']
    list_filter = ['created_at', 'client_name', 'created_by']
    search_fields = ['scan_name', 'client_name', 'client_app_name', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(created_by=request.user)


@admin.register(PostmanAPI)
class PostmanAPIAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'method', 'url', 'scan', 'folder_path', 'created_at']
    list_filter = ['method', 'created_at', 'scan__scan_name']
    search_fields = ['name', 'url', 'scan__scan_name', 'folder_path']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(scan__created_by=request.user)