from django.db import models

class ConnectionLog(models.Model):
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=255)  # Added password field
    ip_address = models.GenericIPAddressField()
    connection_name = models.CharField(max_length=100, unique=True)  # Made unique for foreign key reference
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.connection_name} - {self.username}@{self.ip_address}"

class ProcessCapture(models.Model):
    connection = models.ForeignKey(ConnectionLog, on_delete=models.CASCADE, related_name='process_captures')
    # Input fields
    exe_name = models.CharField(max_length=255)
    exe_directory = models.TextField()
    exe_fullname = models.TextField()
    # Output fields
    filename = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500, blank=True)
    success = models.BooleanField(default=False)
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.connection.connection_name} - {self.exe_name}"
    
class ProcessFilteredResult(models.Model):
    connection = models.ForeignKey(ConnectionLog, on_delete=models.CASCADE, related_name='filtered_results')
    process_capture = models.ForeignKey(ProcessCapture, on_delete=models.CASCADE, related_name='filtered_results')
    csv_filename = models.CharField(max_length=255)
    application_name = models.CharField(max_length=255)
    process_name = models.CharField(max_length=255)
    path = models.TextField()
    result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['connection', 'csv_filename']),
            models.Index(fields=['application_name']),
        ]
    
    def __str__(self):
        return f"{self.connection.connection_name} - {self.application_name} - {self.process_name}"