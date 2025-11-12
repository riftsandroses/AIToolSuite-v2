from django.apps import AppConfig
from django.db import connection
from django.core.management import call_command
from django.db.models.signals import post_migrate
from django.db.utils import OperationalError
import logging

logger = logging.getLogger(__name__)

# Keep a global reference so we don't start multiple times
_auto_scanner_instance = None


class Api2Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api_2'

    def ready(self):
        """Auto-populate templates, setup vulnerability types, and hook JWT scanner startup after migrations"""
        
        # --- Vulnerability Type TC5 setup ---
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM information_schema.tables 
                    WHERE table_name = 'api_2_vulnerability_type'
                """)
                
                if cursor.fetchone()[0] > 0:
                    # Check if vulnerability types already exist
                    from .models import VulnerabilityTypeTC5
                    if VulnerabilityTypeTC5.objects.count() == 0:
                        try:
                            call_command('setup_vulnerability_types_tc5')
                            logger.info("Vulnerability types TC5 setup completed successfully!")
                        except Exception as e:
                            logger.error(f"Failed to setup vulnerability types TC5: {e}")
                            
        except (OperationalError, Exception):
            # Database not ready or other issues, skip setup
            logger.debug("Skipping vulnerability types TC5 setup (database not ready)")

        # --- TC3 vulnerability template auto-population ---
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM information_schema.tables 
                    WHERE table_name = 'api2_vulnerability_templates'
                """)
                table_exists = cursor.fetchone()[0] > 0

            if table_exists:
                from .models import VulnerabilityTemplateTC3
                if VulnerabilityTemplateTC3.objects.count() == 0:
                    logger.info("Auto-populating vulnerability templates...")
                    call_command('populate_templates_tc3')
                    logger.info("Vulnerability templates populated successfully!")

        except Exception:
            # Silently fail during migrations or if database isn't ready
            logger.debug("Skipping vulnerability templates population (database not ready)")

        # --- Hook JWT auto-scanner startup after migrations ---
        post_migrate.connect(start_jwt_scanner_after_migrate, sender=self)


def start_jwt_scanner_after_migrate(sender, **kwargs):
    """Start JWT Scanner Auto-Service only after migrations are applied"""
    global _auto_scanner_instance
    if _auto_scanner_instance is None:
        try:
            from .startup_service import JWTScannerAutoServiceTC4
            service = JWTScannerAutoServiceTC4()
            service.start()
            _auto_scanner_instance = service
            logger.info("JWT Scanner Auto-Service started successfully (post_migrate)")
        except Exception as e:
            logger.error(f"Failed to start JWT Scanner Auto-Service after migrate: {str(e)}")