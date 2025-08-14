# Celery tasks for background processing
# Add this to your Django project if using Celery for async task processing

from celery import shared_task
from django.utils import timezone
from .services import TLSScanServiceTC2
from .models import ScanTC2
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def execute_tls_scan_tc2(self, scan_id, apis_data):
    """
    Execute TLS security scan asynchronously using Celery
    
    Args:
        scan_id (str): UUID of the scan
        apis_data (list): List of API data tuples
    """
    try:
        scan = ScanTC2.objects.get(id=scan_id)
        scan_service = TLSScanServiceTC2()
        
        # Update scan status
        scan.status = 'running'
        scan.save()
        
        # Process each API
        for api_data in apis_data:
            try:
                vulnerabilities = scan_service.perform_tls_analysis(api_data, scan)
                logger.info(f"Scanned API {api_data[0]}, found {len(vulnerabilities)} vulnerabilities")
            except Exception as e:
                logger.error(f"Failed to scan API {api_data[0]}: {str(e)}")
                # Continue with next API instead of failing entire scan
                continue
        
        # Finalize scan
        scan_service.finalize_scan(scan)
        logger.info(f"TLS scan {scan.id} completed successfully")
        
        return {
            'status': 'completed',
            'scan_id': str(scan.id),
            'vulnerabilities_found': scan.vulnerabilities_found
        }
        
    except ScanTC2.DoesNotExist:
        logger.error(f"Scan {scan_id} not found")
        return {'status': 'error', 'message': 'Scan not found'}
        
    except Exception as exc:
        logger.error(f"TLS scan task failed: {str(exc)}")
        
        # Update scan status to failed
        try:
            scan = ScanTC2.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.save()
        except:
            pass
        
        # Retry the task if retries available
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying TLS scan task (attempt {self.request.retries + 1})")
            raise self.retry(countdown=60 * (self.request.retries + 1))
        
        return {'status': 'failed', 'error': str(exc)}

@shared_task
def cleanup_old_scans_tc2():
    """
    Cleanup old completed scans and their associated data
    Run this periodically to maintain database size
    """
    from datetime import datetime, timedelta
    
    try:
        # Delete scans older than 6 months
        cutoff_date = timezone.now() - timedelta(days=180)
        old_scans = ScanTC2.objects.filter(
            completed_at__lt=cutoff_date,
            status__in=['completed', 'failed', 'cancelled']
        )
        
        count = old_scans.count()
        old_scans.delete()
        
        logger.info(f"Cleaned up {count} old scans")
        return {'cleaned_scans': count}
        
    except Exception as e:
        logger.error(f"Cleanup task failed: {str(e)}")
        return {'error': str(e)}

@shared_task
def generate_scan_report_tc2(scan_id):
    """
    Generate a comprehensive security report for a scan
    """
    try:
        from .utils.report_generator_tc2 import ReportGeneratorTC2
        
        scan = ScanTC2.objects.get(id=scan_id)
        report_generator = ReportGeneratorTC2()
        
        report_data = report_generator.generate_comprehensive_report(scan)
        
        # You could save this to a file, send via email, etc.
        logger.info(f"Generated report for scan {scan_id}")
        return report_data
        
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return {'error': str(e)}

@shared_task
def update_vulnerability_intelligence_tc2():
    """
    Update vulnerability intelligence data from external sources
    """
    try:
        from .utils.threat_intelligence_tc2 import ThreatIntelligenceTC2
        
        intel_service = ThreatIntelligenceTC2()
        updates = intel_service.update_tls_vulnerability_data()
        
        logger.info(f"Updated vulnerability intelligence: {updates}")
        return updates
        
    except Exception as e:
        logger.error(f"Intelligence update failed: {str(e)}")
        return {'error': str(e)}