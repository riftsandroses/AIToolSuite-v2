"""
JWT Scanner Startup Service - Automatic Integration with Django
This service automatically starts when Django initializes.
"""

import threading
import time
import logging
from typing import Optional
import os

logger = logging.getLogger(__name__)

# Global daemon instance
_auto_scanner_instance: Optional['JWTScannerAutoServiceTC4'] = None


class JWTScannerAutoServiceTC4:
    """Auto-starting JWT vulnerability scanner service"""
    
    def __init__(self, check_interval: int = 30, max_concurrent: int = 2):
        self.check_interval = check_interval
        self.max_concurrent = max_concurrent
        self.is_running = False
        self.monitor_thread = None
        
        # Import Django models here to avoid AppRegistryNotReady
        from .services import JWTScanServiceTC4
        from .models import JWTScanTC4
        from django.contrib.auth import get_user_model
        
        self.scan_service = JWTScanServiceTC4()
        self.JWTScan = JWTScanTC4
        self.User = get_user_model()
        self.system_user = None
    
    def start(self) -> bool:
        """Start the auto scanner service"""
        if self.is_running:
            logger.info("JWT Scanner already running")
            return True
        
        try:
            # Ensure system user exists
            self._create_system_user()
            
            # Start monitoring thread
            self.is_running = True
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop, 
                daemon=True,
                name="JWTScannerMonitor"
            )
            self.monitor_thread.start()
            
            logger.info(f"JWT Scanner auto-service started (interval: {self.check_interval}s)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start JWT Scanner auto-service: {str(e)}")
            self.is_running = False
            return False
    
    def stop(self):
        """Stop the auto scanner service"""
        self.is_running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        logger.info("JWT Scanner auto-service stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop - runs continuously"""
        logger.info("JWT Scanner monitoring started")
        
        while self.is_running:
            try:
                self._check_and_process_scans()
                time.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(self.check_interval)  # Continue despite errors
        
        logger.info("JWT Scanner monitoring stopped")
    
    def _check_and_process_scans(self):
        """Check for new scans and process them"""
        try:
            # Get scan IDs that need processing
            new_scan_ids = self._get_unprocessed_scan_ids()
            
            if not new_scan_ids:
                return  # Nothing to do
            
            logger.info(f"Found {len(new_scan_ids)} new scan(s): {new_scan_ids}")
            
            # Check current load
            current_running = self.JWTScan.objects.filter(status='in_progress').count()
            available_slots = max(0, self.max_concurrent - current_running)
            
            if available_slots == 0:
                logger.info(f"Max concurrent scans ({self.max_concurrent}) reached, waiting...")
                return
            
            # Process available scans
            scans_to_process = new_scan_ids[:available_slots]
            
            for scan_id in scans_to_process:
                self._start_scan_async(scan_id)
                
        except Exception as e:
            logger.error(f"Error checking for new scans: {str(e)}")
    
    def _start_scan_async(self, scan_id: int):
        """Start a single scan asynchronously"""
        def scan_worker():
            try:
                # Validate prerequisites
                if not self._validate_scan_data(scan_id):
                    logger.warning(f"Scan {scan_id}: Missing prerequisites (APIs or JWT token)")
                    return
                
                # Start the scan
                scan = self.scan_service.start_scan(scan_id, self.system_user)
                logger.info(f"Started JWT vulnerability scan for scan_id {scan_id}")
                
            except Exception as e:
                logger.error(f"Failed to start scan {scan_id}: {str(e)}")
        
        # Start scan in background thread
        thread = threading.Thread(
            target=scan_worker, 
            daemon=True,
            name=f"JWTScan-{scan_id}"
        )
        thread.start()
    
    def _get_unprocessed_scan_ids(self) -> list[int]:
        """Get scan_ids that exist in api_orch but not yet processed"""
        try:
            from django.db import connection
            
            with connection.cursor() as cursor:
                # Find scan_ids with APIs and JWT tokens but no JWT scan yet
                cursor.execute("""
                    SELECT DISTINCT "aop"."scan_id"
                    FROM "api_orch_postmanapi" AS "aop"
                    INNER JOIN "api_orch_scantokens" AS "ast" ON "aop"."scan_id" = "ast"."scan_id"
                    LEFT JOIN "jwt_scan_tc4" AS "jst" ON "aop"."scan_id" = "jst"."scan_id"
                    WHERE "jst"."scan_id" IS NULL
                    AND "ast"."access_token" IS NOT NULL
                    AND "ast"."access_token" != ''
                    ORDER BY "aop"."scan_id"
                    LIMIT 10;
                """)
                
                return [row[0] for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error querying unprocessed scans: {str(e)}")
            return []
    
    def _validate_scan_data(self, scan_id: int) -> bool:
        """Validate that scan has required data"""
        try:
            from django.db import connection
            
            with connection.cursor() as cursor:
                # Check for APIs
                cursor.execute("""
                    SELECT COUNT(*) FROM api_orch_postmanapi 
                    WHERE "scan_id" = %s
                """, [scan_id])
                
                api_count = cursor.fetchone()[0]
                if api_count == 0:
                    return False
                
                # Check for JWT token
                cursor.execute("""
                    SELECT COUNT(*) FROM api_orch_scantokens 
                    WHERE "scan_id" = %s 
                    AND "access_token" IS NOT NULL 
                    AND "access_token" != ''
                """, [scan_id])
                
                token_count = cursor.fetchone()[0]
                return token_count > 0
                
        except Exception as e:
            logger.error(f"Error validating scan {scan_id}: {str(e)}")
            return False
    
    def _create_system_user(self):
        """Create system user for automated scans"""
        try:
            self.system_user, created = self.User.objects.get_or_create(
                username='jwt_scanner_auto',
                defaults={
                    'email': 'jwt.scanner.auto@system.local',
                    'first_name': 'JWT',
                    'last_name': 'Scanner Auto',
                    'is_active': True,
                    'is_staff': False,  # Not admin, just for scanning
                }
            )
            
            if created:
                logger.info("Created system user: jwt_scanner_auto")
                
        except Exception as e:
            logger.error(f"Error creating system user: {str(e)}")
            # Fallback to any existing user
            self.system_user = self.User.objects.first()
            
            if not self.system_user:
                raise Exception("No users exist in system - cannot start JWT scanner")


def start_jwt_scanner_auto() -> bool:
    """
    Start JWT scanner auto-service (called by Django app.ready())
    Returns True if started successfully, False otherwise
    """
    global _auto_scanner_instance
    
    try:
        # Only start once
        if _auto_scanner_instance and _auto_scanner_instance.is_running:
            logger.info("JWT Scanner auto-service already running")
            return True
        
        # Get configuration from Django settings
        from django.conf import settings
        
        config = getattr(settings, 'JWT_SCANNER_CONFIG', {})
        check_interval = config.get('AUTO_CHECK_INTERVAL', 30)
        max_concurrent = config.get('MAX_CONCURRENT_SCANS', 2)
        
        # Create and start service
        _auto_scanner_instance = JWTScannerAutoServiceTC4(
            check_interval=check_interval,
            max_concurrent=max_concurrent
        )
        
        return _auto_scanner_instance.start()
        
    except Exception as e:
        logger.error(f"Failed to start JWT scanner auto-service: {str(e)}")
        return False


def stop_jwt_scanner_auto():
    """Stop JWT scanner auto-service"""
    global _auto_scanner_instance
    
    if _auto_scanner_instance:
        _auto_scanner_instance.stop()
        _auto_scanner_instance = None


def get_auto_service_status() -> dict:
    """Get status of auto-service"""
    global _auto_scanner_instance
    
    if _auto_scanner_instance and _auto_scanner_instance.is_running:
        try:
            from .models import JWTScanTC4
            running_scans = JWTScanTC4.objects.filter(status='in_progress').count()
            
            return {
                'running': True,
                'check_interval': _auto_scanner_instance.check_interval,
                'max_concurrent': _auto_scanner_instance.max_concurrent,
                'current_running_scans': running_scans,
                'thread_alive': _auto_scanner_instance.monitor_thread.is_alive() if _auto_scanner_instance.monitor_thread else False
            }
        except Exception as e:
            return {
                'running': True,
                'error': str(e)
            }
    else:
        return {
            'running': False,
            'check_interval': None,
            'max_concurrent': None,
            'current_running_scans': 0
        }


# Signal handlers for graceful shutdown
def shutdown_handler():
    """Handle application shutdown"""
    logger.info("Shutting down JWT Scanner auto-service...")
    stop_jwt_scanner_auto()


# Register shutdown handler
import atexit
atexit.register(shutdown_handler)