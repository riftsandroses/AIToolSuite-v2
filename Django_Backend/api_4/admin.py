from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import FileUploadScanResult, FileUploadTest, ScanSession, ConcurrentSessionScanTC6, TokenTestResultTC6, ScanLogTC6, VulnerabilityReportTC6




@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    list_display = ['scan_id', 'user', 'status', 'total_apis', 'completed_apis', 'vulnerable_apis', 'started_at', 'progress_display']
    list_filter = ['status', 'started_at', 'completed_at']
    search_fields = ['scan_id', 'user__username']
    readonly_fields = ['started_at', 'completed_at', 'progress_display']
    ordering = ['-started_at']
    
    def progress_display(self, obj):
        if obj.total_apis == 0:
            return "0%"
        
        progress = (obj.completed_apis / obj.total_apis) * 100
        color = 'green' if progress == 100 else 'orange' if progress > 50 else 'red'
        
        return format_html(
            '<div style="width: 100px; background-color: #f0f0f0; border-radius: 3px;">'
            '<div style="width: {}%; background-color: {}; height: 20px; border-radius: 3px; text-align: center; color: white; line-height: 20px;">'
            '{:.1f}%'
            '</div></div>',
            progress, color, progress
        )
    progress_display.short_description = 'Progress'


@admin.register(FileUploadScanResult)
class FileUploadScanResultAdmin(admin.ModelAdmin):
    list_display = [
        'scan_id', 'api_name', 'api_method', 'status', 'vulnerability_type',
        'risk_score_display', 'accepts_file_upload', 'webshell_upload_success',
        'large_file_upload_success', 'unrestricted_file_types', 'created_at'
    ]
    list_filter = [
        'status', 'vulnerability_type', 'api_method', 'accepts_file_upload',
        'webshell_upload_success', 'large_file_upload_success', 'unrestricted_file_types',
        'created_at'
    ]
    search_fields = ['scan_id', 'api_name', 'api_url']
    readonly_fields = [
        'scan_id', 'api_id', 'response_headers_display', 'response_body_display',
        'uploaded_files_display', 'rejected_files_display', 'scan_duration', 'created_at', 'updated_at'
    ]
    ordering = ['-created_at']
    
    fieldsets = (
        ('API Information', {
            'fields': ('scan_id', 'api_id', 'api_name', 'api_url', 'api_method')
        }),
        ('Vulnerability Results', {
            'fields': ('status', 'vulnerability_type', 'accepts_file_upload',
                      'webshell_upload_success', 'large_file_upload_success', 'unrestricted_file_types')
        }),
        ('Response Details', {
            'fields': ('response_status_code', 'response_headers_display', 'response_body_display'),
            'classes': ('collapse',)
        }),
        ('File Upload Details', {
            'fields': ('uploaded_files_display', 'rejected_files_display'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('error_message', 'scan_duration', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def risk_score_display(self, obj):
        score = self._calculate_risk_score(obj)
        if score >= 70:
            color = '#d32f2f'  # Red
            level = 'Critical'
        elif score >= 40:
            color = '#f57c00'  # Orange
            level = 'High'
        elif score >= 20:
            color = '#fbc02d'  # Yellow
            level = 'Medium'
        elif score > 0:
            color = '#388e3c'  # Green
            level = 'Low'
        else:
            color = '#757575'  # Gray
            level = 'None'
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{} ({})</span>',
            color, level, score
        )
    risk_score_display.short_description = 'Risk Score'
    
    def _calculate_risk_score(self, obj):
        score = 0
        if obj.webshell_upload_success:
            score += 70
        if obj.large_file_upload_success:
            score += 20
        if obj.unrestricted_file_types:
            score += 10
        return min(score, 100)
    
    def response_headers_display(self, obj):
        if not obj.response_headers:
            return "No headers"
        
        headers_html = '<table style="width: 100%; border-collapse: collapse;">'
        for key, value in obj.response_headers.items():
            headers_html += f'<tr><td style="border: 1px solid #ddd; padding: 4px; font-weight: bold;">{key}</td><td style="border: 1px solid #ddd; padding: 4px;">{value}</td></tr>'
        headers_html += '</table>'
        
        return mark_safe(headers_html)
    response_headers_display.short_description = 'Response Headers'
    
    def response_body_display(self, obj):
        if not obj.response_body_snippet:
            return "No response body"
        
        # Truncate long responses
        body = obj.response_body_snippet
        if len(body) > 500:
            body = body[:500] + "... (truncated)"
        
        return format_html('<pre style="white-space: pre-wrap; max-height: 200px; overflow-y: auto;">{}</pre>', body)
    response_body_display.short_description = 'Response Body'
    
    def uploaded_files_display(self, obj):
        if not obj.uploaded_files:
            return "No uploaded files"
        
        files_html = '<ul>'
        for file_info in obj.uploaded_files:
            files_html += f'<li>{file_info}</li>'
        files_html += '</ul>'
        
        return mark_safe(files_html)
    uploaded_files_display.short_description = 'Uploaded Files'
    
    def rejected_files_display(self, obj):
        if not obj.rejected_files:
            return "No rejected files"
        
        files_html = '<ul>'
        for file_info in obj.rejected_files:
            files_html += f'<li>{file_info}</li>'
        files_html += '</ul>'
        
        return mark_safe(files_html)
    rejected_files_display.short_description = 'Rejected Files'


@admin.register(FileUploadTest)
class FileUploadTestAdmin(admin.ModelAdmin):
    list_display = [
        'scan_result', 'file_name', 'file_type', 'file_size_display',
        'test_type', 'upload_success', 'response_status', 'created_at'
    ]
    list_filter = ['test_type', 'upload_success', 'response_status', 'file_type', 'created_at']
    search_fields = ['file_name', 'scan_result__api_name', 'scan_result__scan_id']
    readonly_fields = ['created_at', 'file_size_display']
    ordering = ['-created_at']
    
    def file_size_display(self, obj):
        size = obj.file_size
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    file_size_display.short_description = 'File Size'


# Custom admin actions
def mark_as_false_positive(modeladmin, request, queryset):
    """Mark selected results as false positives"""
    queryset.update(status='safe')
    modeladmin.message_user(request, f'{queryset.count()} results marked as false positives.')
mark_as_false_positive.short_description = "Mark selected results as false positives"

def export_vulnerable_apis(modeladmin, request, queryset):
    """Export vulnerable APIs to CSV"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="vulnerable_apis.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Scan ID', 'API Name', 'URL', 'Method', 'Vulnerability Type', 'Risk Score'])
    
    for result in queryset.filter(status='vulnerable'):
        risk_score = 0
        if result.webshell_upload_success:
            risk_score += 70
        if result.large_file_upload_success:
            risk_score += 20
        if result.unrestricted_file_types:
            risk_score += 10
        
        writer.writerow([
            result.scan_id,
            result.api_name,
            result.api_url,
            result.api_method,
            result.vulnerability_type or 'Unknown',
            risk_score
        ])
    
    return response
export_vulnerable_apis.short_description = "Export vulnerable APIs to CSV"

# Add actions to admin
FileUploadScanResultAdmin.actions = [mark_as_false_positive, export_vulnerable_apis]

class ScanLogInlineTC6(admin.TabularInline):
    """Inline admin for scan logs"""
    model = ScanLogTC6
    extra = 0
    readonly_fields = ['level', 'message', 'step', 'metadata', 'created_at']
    fields = ['level', 'step', 'message', 'created_at']
    
    def has_add_permission(self, request, obj=None):
        return False


class TokenTestResultInlineTC6(admin.TabularInline):
    """Inline admin for token test results"""
    model = TokenTestResultTC6
    extra = 0
    readonly_fields = [
        'token_1_active_after_5min', 'token_2_active_after_5min',
        'test_api_url', 'vulnerability_confirmed', 'created_at', 'tested_at'
    ]
    fields = [
        'test_api_url', 'token_1_active_after_5min', 'token_2_active_after_5min',
        'vulnerability_confirmed', 'tested_at'
    ]
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(ConcurrentSessionScanTC6)
class ConcurrentSessionScanAdminTC6(admin.ModelAdmin):
    """Admin interface for concurrent session scans"""
    list_display = [
        'scan_id', 'status', 'login_api_identified', 'vulnerability_found',
        'created_at', 'completed_at', 'view_logs_link'
    ]
    list_filter = [
        'status', 'login_api_identified', 'vulnerability_found',
        'created_at', 'completed_at'
    ]
    search_fields = ['scan_id', 'login_api_url', 'error_message']
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'completed_at',
        'login_api_identified', 'vulnerability_found'
    ]
    fieldsets = [
        ('Basic Information', {
            'fields': ['id', 'scan_id', 'status']
        }),
        ('Login API Information', {
            'fields': ['login_api_identified', 'login_api_url', 'login_api_method'],
            'classes': ['collapse'] if not None else []
        }),
        ('Results', {
            'fields': ['vulnerability_found', 'error_message']
        }),
        ('Timestamps', {
            'fields': ['created_at', 'updated_at', 'completed_at'],
            'classes': ['collapse']
        })
    ]
    inlines = [TokenTestResultInlineTC6, ScanLogInlineTC6]
    
    def view_logs_link(self, obj):
        """Link to view scan logs"""
        if obj.logs.exists():
            url = reverse('admin:api_4_scanlogtc6_changelist') + f'?scan__id__exact={obj.id}'
            return format_html('<a href="{}">View Logs ({})</a>', url, obj.logs.count())
        return 'No logs'
    view_logs_link.short_description = 'Logs'
    
    def get_queryset(self, request):
        """Optimize queryset with prefetch_related"""
        return super().get_queryset(request).prefetch_related('logs', 'token_results')


@admin.register(TokenTestResultTC6)
class TokenTestResultAdminTC6(admin.ModelAdmin):
    """Admin interface for token test results"""
    list_display = [
        'scan_link', 'test_api_method', 'test_api_url',
        'token_1_active_after_5min', 'token_2_active_after_5min',
        'vulnerability_confirmed', 'tested_at'
    ]
    list_filter = [
        'vulnerability_confirmed', 'token_1_active_after_5min',
        'token_2_active_after_5min', 'test_api_method', 'tested_at'
    ]
    search_fields = ['scan__scan_id', 'test_api_url']
    readonly_fields = [
        'id', 'scan', 'token_1', 'token_2', 'token_1_active_after_5min',
        'token_2_active_after_5min', 'test_api_url', 'test_api_method',
        'vulnerability_confirmed', 'token_1_response_code', 'token_2_response_code',
        'created_at', 'tested_at'
    ]
    fieldsets = [
        ('Scan Information', {
            'fields': ['id', 'scan']
        }),
        ('Test Configuration', {
            'fields': ['test_api_url', 'test_api_method']
        }),
        ('Token Test Results', {
            'fields': [
                'token_1_active_after_5min', 'token_2_active_after_5min',
                'token_1_response_code', 'token_2_response_code',
                'vulnerability_confirmed'
            ]
        }),
        ('Tokens (Partial)', {
            'fields': ['token_1', 'token_2'],
            'classes': ['collapse'],
            'description': 'Only partial tokens are stored for security'
        }),
        ('Timestamps', {
            'fields': ['created_at', 'tested_at'],
            'classes': ['collapse']
        })
    ]
    
    def scan_link(self, obj):
        """Link to the related scan"""
        url = reverse('admin:api_4_concurrentsessionscantc6_change', args=[obj.scan.id])
        return format_html('<a href="{}">Scan {}</a>', url, obj.scan.scan_id)
    scan_link.short_description = 'Scan'
    
    def has_add_permission(self, request):
        return False


@admin.register(ScanLogTC6)
class ScanLogAdminTC6(admin.ModelAdmin):
    """Admin interface for scan logs"""
    list_display = [
        'scan_link', 'level', 'step', 'short_message', 'created_at'
    ]
    list_filter = ['level', 'step', 'created_at']
    search_fields = ['scan__scan_id', 'message', 'step']
    readonly_fields = [
        'id', 'scan', 'level', 'message', 'step', 'metadata', 'created_at'
    ]
    fieldsets = [
        ('Log Information', {
            'fields': ['id', 'scan', 'level', 'step', 'created_at']
        }),
        ('Message', {
            'fields': ['message']
        }),
        ('Metadata', {
            'fields': ['metadata'],
            'classes': ['collapse']
        })
    ]
    
    def scan_link(self, obj):
        """Link to the related scan"""
        url = reverse('admin:api_4_concurrentsessionscantc6_change', args=[obj.scan.id])
        return format_html('<a href="{}">Scan {}</a>', url, obj.scan.scan_id)
    scan_link.short_description = 'Scan'
    
    def short_message(self, obj):
        """Truncated message for list display"""
        return obj.message[:100] + '...' if len(obj.message) > 100 else obj.message
    short_message.short_description = 'Message'
    
    def has_add_permission(self, request):
        return False


@admin.register(VulnerabilityReportTC6)
class VulnerabilityReportAdminTC6(admin.ModelAdmin):
    """Admin interface for vulnerability reports"""
    list_display = [
        'scan_link', 'title', 'severity', 'created_at'
    ]
    list_filter = ['severity', 'created_at']
    search_fields = ['scan__scan_id', 'title', 'description']
    readonly_fields = [
        'id', 'scan', 'title', 'description', 'severity',
        'impact', 'recommendation', 'evidence', 'created_at'
    ]
    fieldsets = [
        ('Report Information', {
            'fields': ['id', 'scan', 'title', 'severity', 'created_at']
        }),
        ('Vulnerability Details', {
            'fields': ['description', 'impact', 'recommendation']
        }),
        ('Evidence', {
            'fields': ['evidence'],
            'classes': ['collapse']
        })
    ]
    
    def scan_link(self, obj):
        """Link to the related scan"""
        url = reverse('admin:api_4_concurrentsessionscantc6_change', args=[obj.scan.id])
        return format_html('<a href="{}">Scan {}</a>', url, obj.scan.scan_id)
    scan_link.short_description = 'Scan'
    
    def has_add_permission(self, request):
        return False


# Custom admin site configuration
admin.site.site_header = 'Concurrent Session Vulnerability Scanner Admin'
admin.site.site_title = 'CSVS Admin'
admin.site.index_title = 'Welcome to Concurrent Session Vulnerability Scanner Administration'