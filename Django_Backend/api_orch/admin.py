# api_orch/admin.py
from django.contrib import admin
from .models import Scan, PostmanAPI, TestCaseSelection


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan_name', 'client_name', 'client_app_name', 'created_by', 'has_test_cases', 'created_at']
    list_filter = ['created_at', 'client_name', 'created_by']
    search_fields = ['scan_name', 'client_name', 'client_app_name', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        (None, {
            'fields': ('scan_name', 'description', 'client_name', 'client_app_name')
        }),
        ('Credentials', {
            'fields': ('username', 'password')
        }),
        ('Collection', {
            'fields': ('postman_collection_file',)
        }),
        ('Test Cases', {
            'fields': ('test_case_selections',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def has_test_cases(self, obj):
        return bool(obj.test_case_selections)
    has_test_cases.boolean = True
    has_test_cases.short_description = 'Has Test Cases'
    
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


@admin.register(TestCaseSelection)
class TestCaseSelectionAdmin(admin.ModelAdmin):
    list_display = ['id', 'api_category', 'test_case', 'name', 'is_active', 'created_at']
    list_filter = ['api_category', 'test_case', 'is_active', 'created_at']
    search_fields = ['name', 'description', 'api_category', 'test_case']
    readonly_fields = ['created_at']
    
    fieldsets = (
        (None, {
            'fields': ('api_category', 'test_case', 'name', 'description', 'is_active')
        }),
        ('Metadata', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )