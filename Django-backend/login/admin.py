from django.contrib import admin
from .models import UserTOTP

@admin.register(UserTOTP)
class UserTOTPAdmin(admin.ModelAdmin):
    list_display = ['user', 'is_enabled', 'created_at', 'updated_at']
    list_filter = ['is_enabled', 'created_at']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['secret_key', 'created_at', 'updated_at']
    
    def get_readonly_fields(self, request, obj=None):
        if obj:  # Editing an existing object
            return self.readonly_fields + ['user']
        return self.readonly_fields