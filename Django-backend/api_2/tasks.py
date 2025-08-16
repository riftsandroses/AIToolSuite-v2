from celery import shared_task
from django.contrib.auth.models import User
from .services import APISecurityScannerTC1, VulnerabilityScannerServiceTC3, ScanStatsServiceTC3
from .models import ScanSessionTC1, ScanSessionTC3, ScanResultTC3
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

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def execute_vulnerability_scan_tc3(self, scan_id, vulnerability_types=None, config=None):
    """
    Execute vulnerability scan as a background task
    """
    if vulnerability_types is None:
        vulnerability_types = ['weak_password_policy']
    
    if config is None:
        config = {}
    
    try:
        scanner = VulnerabilityScannerServiceTC3()
        scan_session = scanner.initiate_scan(scan_id, vulnerability_types, config)
        
        logger.info(f"Vulnerability scan completed for scan_id: {scan_id}")
        
        return {
            'status': 'completed',
            'scan_id': scan_id,
            'vulnerabilities_found': scan_session.vulnerabilities_found,
            'apis_scanned': scan_session.apis_scanned
        }
        
    except Exception as exc:
        logger.error(f"Vulnerability scan failed for scan_id {scan_id}: {str(exc)}")
        
        # Update scan session status to failed
        try:
            scan_session = ScanSessionTC3.objects.get(scan_id=scan_id)
            scan_session.status = 'failed'
            scan_session.completed_at = timezone.now()
            scan_session.errors.append({
                'error': str(exc),
                'timestamp': timezone.now().isoformat(),
                'task_id': self.request.id
            })
            scan_session.save()
        except ScanSessionTC3.DoesNotExist:
            pass
        
        # Retry the task
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying scan for scan_id {scan_id} (attempt {self.request.retries + 1})")
            raise self.retry(exc=exc)
        
        return {
            'status': 'failed',
            'scan_id': scan_id,
            'error': str(exc)
        }


@shared_task
def cleanup_old_scan_results_tc3(retention_days=90):
    """
    Cleanup old scan results based on retention policy
    """
    cutoff_date = timezone.now() - timezone.timedelta(days=retention_days)
    
    # Delete old scan results
    deleted_results_count, _ = ScanResultTC3.objects.filter(
        created_at__lt=cutoff_date
    ).delete()
    
    # Delete old scan sessions
    deleted_sessions_count, _ = ScanSessionTC3.objects.filter(
        started_at__lt=cutoff_date,
        status__in=['completed', 'failed', 'cancelled']
    ).delete()
    
    logger.info(
        f"Cleanup completed: {deleted_results_count} scan results and "
        f"{deleted_sessions_count} scan sessions deleted"
    )
    
    return {
        'deleted_results': deleted_results_count,
        'deleted_sessions': deleted_sessions_count,
        'cutoff_date': cutoff_date.isoformat()
    }


@shared_task
def generate_daily_security_report_tc3():
    """
    Generate daily security report with scan statistics
    """
    try:
        stats_service = ScanStatsServiceTC3()
        stats = stats_service.get_scan_statistics()
        
        # You can extend this to send email reports, save to file, etc.
        logger.info(f"Daily security report generated: {stats}")
        
        return {
            'status': 'completed',
            'report_date': timezone.now().date().isoformat(),
            'stats': stats
        }
        
    except Exception as exc:
        logger.error(f"Failed to generate daily security report: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc)
        }


@shared_task
def batch_vulnerability_scan_tc3(scan_ids, vulnerability_types=None):
    """
    Execute vulnerability scans for multiple scan IDs
    """
    if vulnerability_types is None:
        vulnerability_types = ['weak_password_policy']
    
    results = []
    
    for scan_id in scan_ids:
        try:
            # Queue individual scan tasks
            task = execute_vulnerability_scan_tc3.delay(
                scan_id, vulnerability_types
            )
            
            results.append({
                'scan_id': scan_id,
                'task_id': task.id,
                'status': 'queued'
            })
            
        except Exception as exc:
            results.append({
                'scan_id': scan_id,
                'status': 'failed',
                'error': str(exc)
            })
    
    logger.info(f"Batch scan initiated for {len(scan_ids)} scan IDs")
    
    return {
        'total_scans': len(scan_ids),
        'results': results
    }


@shared_task
def update_vulnerability_templates_tc3():
    """
    Update vulnerability templates from external sources
    """
    try:
        from .models import VulnerabilityTemplateTC3
        
        # This is a placeholder for updating templates from external sources
        # like OWASP, CWE database, etc.
        
        updated_count = 0
        logger.info(f"Vulnerability templates update completed: {updated_count} templates updated")
        
        return {
            'status': 'completed',
            'updated_templates': updated_count
        }
        
    except Exception as exc:
        logger.error(f"Failed to update vulnerability templates: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc)
        }


@shared_task
def monitor_scan_health_tc3():
    """
    Monitor the health of running scans and handle stuck scans
    """
    try:
        # Find scans that have been running for too long
        stale_cutoff = timezone.now() - timezone.timedelta(hours=2)
        
        stale_scans = ScanSessionTC3.objects.filter(
            status='running',
            started_at__lt=stale_cutoff
        )
        
        updated_count = 0
        for scan in stale_scans:
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.errors.append({
                'error': 'Scan timeout - marked as failed by health monitor',
                'timestamp': timezone.now().isoformat()
            })
            scan.save()
            updated_count += 1
        
        logger.info(f"Scan health monitor completed: {updated_count} stale scans marked as failed")
        
        return {
            'status': 'completed',
            'stale_scans_found': updated_count
        }
        
    except Exception as exc:
        logger.error(f"Scan health monitoring failed: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc)
        }