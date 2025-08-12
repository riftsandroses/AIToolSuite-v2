# api_4/tasks.py
from celery import shared_task
import logging
from .services import VulnerabilityScanServiceTC6

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def perform_vulnerability_scan_task(self, scan_id):
    """
    Celery task to perform vulnerability scan asynchronously
    """
    try:
        logger.info(f"Starting vulnerability scan task for scan_id: {scan_id}")
        
        service = VulnerabilityScanServiceTC6()
        scan = service.perform_vulnerability_scan(scan_id)
        
        logger.info(f"Vulnerability scan completed for scan_id: {scan_id}, "
                   f"vulnerability_found: {scan.vulnerability_found}")
        
        return {
            'scan_uuid': str(scan.id),
            'scan_id': scan_id,
            'status': scan.status,
            'vulnerability_found': scan.vulnerability_found
        }
        
    except Exception as exc:
        logger.error(f"Vulnerability scan failed for scan_id {scan_id}: {str(exc)}")
        
        # Retry the task up to max_retries times
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying vulnerability scan for scan_id {scan_id}, "
                       f"attempt {self.request.retries + 1}")
            raise self.retry(countdown=60, exc=exc)
        else:
            logger.error(f"Max retries exceeded for scan_id {scan_id}")
            raise exc


@shared_task
def cleanup_old_scans_task():
    """
    Celery task to cleanup old scan records (optional maintenance task)
    """
    from django.utils import timezone
    from datetime import timedelta
    from .models import ConcurrentSessionScanTC6
    
    try:
        # Delete scans older than 90 days
        cutoff_date = timezone.now() - timedelta(days=90)
        
        deleted_count = ConcurrentSessionScanTC6.objects.filter(
            created_at__lt=cutoff_date
        ).delete()[0]
        
        logger.info(f"Cleaned up {deleted_count} old scan records")
        return {'deleted_count': deleted_count}
        
    except Exception as exc:
        logger.error(f"Error during cleanup task: {str(exc)}")
        raise exc