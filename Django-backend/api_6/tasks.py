# tasks.py - Celery tasks for async vulnerability testing
from celery import shared_task
from django.utils import timezone
from .models import VulnerabilityScanTC1
from .services import VulnerabilityTestServiceTC1
import asyncio


@shared_task(bind=True, max_retries=3)
def run_vulnerability_scan_task(self, scan_id: int, test_types: list = None, **options):
    """
    Celery task to run vulnerability scan asynchronously
    """
    try:
        # Get scan record
        scan = VulnerabilityScanTC1.objects.get(scan_id=scan_id)
        scan.status = 'running'
        scan.save()
        
        # Run the scan
        service = VulnerabilityTestServiceTC1()
        
        # Since Celery doesn't handle async well, we need to run in event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Get APIs and JWT token
            apis = loop.run_until_complete(service._get_apis_for_scan(scan_id))
            if not apis:
                raise ValueError(f"No APIs found for scan_id {scan_id}")
            
            # Run the scan
            loop.run_until_complete(
                service._run_scan_tests(scan, apis, test_types or ['mass_account_creation'], options)
            )
            
        finally:
            loop.close()
        
        return {'status': 'completed', 'scan_id': scan_id}
        
    except Exception as exc:
        # Update scan status on failure
        try:
            scan = VulnerabilityScanTC1.objects.get(scan_id=scan_id)
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.save()
        except:
            pass
        
        # Retry logic
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (self.request.retries + 1), exc=exc)
        
        raise exc


@shared_task
def cleanup_old_scans():
    """
    Cleanup old completed scans and their associated data
    """
    from datetime import timedelta
    
    cutoff_date = timezone.now() - timedelta(days=30)  # Keep data for 30 days
    
    old_scans = VulnerabilityScanTC1.objects.filter(
        completed_at__lt=cutoff_date,
        status__in=['completed', 'failed', 'cancelled']
    )
    
    count = old_scans.count()
    old_scans.delete()
    
    return f"Cleaned up {count} old scans"


@shared_task
def generate_daily_security_report():
    """
    Generate daily security report with vulnerability statistics
    """
    from .services import ScanManagementServiceTC1
    from datetime import timedelta
    
    service = ScanManagementServiceTC1()
    
    # Get yesterday's data
    yesterday = timezone.now().date() - timedelta(days=1)
    
    scans_yesterday = VulnerabilityScanTC1.objects.filter(
        created_at__date=yesterday
    )
    
    report = {
        'date': yesterday.isoformat(),
        'total_scans': scans_yesterday.count(),
        'completed_scans': scans_yesterday.filter(status='completed').count(),
        'failed_scans': scans_yesterday.filter(status='failed').count(),
        'total_vulnerabilities': sum(scan.vulnerabilities_found for scan in scans_yesterday),
    }
    
    # You can extend this to send email reports, save to file, etc.
    print(f"Daily Security Report: {report}")
    
    return report


@shared_task
def update_scan_statistics():
    """
    Update scan statistics for all active scans
    """
    from .models import ScanStatsTC1
    
    active_scans = VulnerabilityScanTC1.objects.filter(
        status__in=['completed']
    ).exclude(
        stats__isnull=False  # Already has stats
    )
    
    updated_count = 0
    
    for scan in active_scans:
        try:
            service = VulnerabilityTestServiceTC1()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(service._update_scan_stats(scan))
                updated_count += 1
            finally:
                loop.close()
                
        except Exception as e:
            print(f"Failed to update stats for scan {scan.id}: {e}")
    
    return f"Updated statistics for {updated_count} scans"