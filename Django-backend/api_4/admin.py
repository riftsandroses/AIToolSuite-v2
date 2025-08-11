from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import FileUploadScanResult, FileUploadTest, ScanSession

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