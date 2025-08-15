from celery import shared_task
from django.contrib.auth.models import User
from .services import APISecurityScannerTC1
from .models import ScanSessionTC1
from django.utils import timezone
import openai
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def run_security_scan_async(self, scan_id, user_id, scan_config=None):
    """Async task for running security scans"""
    try:
        user = User.objects.get(id=user_id)
        scanner = APISecurityScannerTC1(user=user)
        
        # Update scan status to scanning
        session = ScanSessionTC1.objects.get(scan_id=scan_id)
        session.status = 'scanning'
        session.save()
        
        result = scanner.initiate_scan(scan_id, scan_config or {})
        
        return {
            'success': True,
            'scan_id': scan_id,
            'result': result
        }
        
    except Exception as exc:
        logger.error(f"Scan failed for scan_id {scan_id}: {str(exc)}")
        
        # Update scan status to failed
        try:
            session = ScanSessionTC1.objects.get(scan_id=scan_id)
            session.status = 'failed'
            session.completed_at = timezone.now()
            session.save()
        except:
            pass
            
        # Retry task
        raise self.retry(exc=exc, countdown=60)