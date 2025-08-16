from django.apps import AppConfig
from django.db import connection
from django.core.management import call_command


class Api2Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api_2'

    def ready(self):
        """Auto-populate templates when the app starts"""
        try:
            # Check if database is migrated and table exists
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM information_schema.tables 
                    WHERE table_name = 'api2_vulnerability_templates'
                """)
                table_exists = cursor.fetchone()[0] > 0
            
            if table_exists:
                # Check if templates are already populated
                from .models import VulnerabilityTemplateTC3
                
                if VulnerabilityTemplateTC3.objects.count() == 0:
                    print("Auto-populating vulnerability templates...")
                    call_command('populate_templates_tc3')
                    print("Vulnerability templates populated successfully!")
                    
        except Exception as e:
            # Silently fail during migrations or if database isn't ready
            pass
