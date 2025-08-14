from celery import shared_task
from django.utils import timezone
from .services import TLSScanServiceTC2, VulnerabilityScannerServiceTC3
from .models import ScanTC2, ScanTC3
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

@shared_task(bind=True, max_retries=3)
def run_vulnerability_scan_TC3(self, scan_id):
    """
    Celery task to run vulnerability scan asynchronously
    """
    try:
        logger.info(f"Starting async vulnerability scan for scan_id: {scan_id}")
        
        scanner = VulnerabilityScannerServiceTC3()
        result = scanner.scan_apis_for_vulnerabilities(scan_id)
        
        if 'error' in result:
            logger.error(f"Scan failed: {result['error']}")
            # Update scan status to failed
            try:
                scan = ScanTC3.objects.get(scan_id=scan_id)
                scan.status = 'FAILED'
                scan.completed_at = timezone.now()
                scan.save()
            except ScanTC3.DoesNotExist:
                pass
            
            return {'status': 'failed', 'error': result['error']}
        
        logger.info(f"Scan completed successfully: {result}")
        return {'status': 'completed', 'result': result}
        
    except Exception as exc:
        logger.error(f"Scan task failed with exception: {str(exc)}")
        
        # Retry logic
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying scan task. Attempt {self.request.retries + 1}")
            raise self.retry(countdown=60 * (self.request.retries + 1))
        
        # Final failure - update scan status
        try:
            scan = ScanTC3.objects.get(scan_id=scan_id)
            scan.status = 'FAILED'
            scan.completed_at = timezone.now()
            scan.save()
        except ScanTC3.DoesNotExist:
            pass
        
        return {'status': 'failed', 'error': str(exc)}

@shared_task
def cleanup_old_scans_TC3(days_old=30):
    """
    Celery task to cleanup old scan records
    """
    try:
        cutoff_date = timezone.now() - timezone.timedelta(days=days_old)
        
        old_scans = ScanTC3.objects.filter(
            completed_at__lt=cutoff_date,
            status__in=['COMPLETED', 'FAILED', 'CANCELLED']
        )
        
        deleted_count = old_scans.count()
        old_scans.delete()
        
        logger.info(f"Cleaned up {deleted_count} old scan records")
        return {'deleted_count': deleted_count}
        
    except Exception as e:
        logger.error(f"Cleanup task failed: {str(e)}")
        return {'error': str(e)}

@shared_task
def generate_vulnerability_report_TC3(scan_id, report_format='json'):
    """
    Generate comprehensive vulnerability report
    """
    try:
        from .models import ScanTC3, VulnerabilityTC3
        import json
        from datetime import datetime
        
        scan = ScanTC3.objects.get(scan_id=scan_id)
        vulnerabilities = scan.vulnerabilities.all()
        
        # Generate report data
        report_data = {
            'scan_info': {
                'scan_id': scan.scan_id,
                'status': scan.status,
                'started_at': scan.started_at.isoformat(),
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'total_apis': scan.total_apis,
                'scanned_apis': scan.scanned_apis,
                'vulnerabilities_found': scan.vulnerabilities_found
            },
            'vulnerability_summary': {
                'total': vulnerabilities.count(),
                'critical': vulnerabilities.filter(severity='CRITICAL').count(),
                'high': vulnerabilities.filter(severity='HIGH').count(),
                'medium': vulnerabilities.filter(severity='MEDIUM').count(),
                'low': vulnerabilities.filter(severity='LOW').count()
            },
            'vulnerabilities': []
        }
        
        for vuln in vulnerabilities:
            report_data['vulnerabilities'].append({
                'id': vuln.id,
                'api_name': vuln.api_name,
                'api_url': vuln.api_url,
                'api_method': vuln.api_method,
                'vulnerability_type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'title': vuln.title,
                'description': vuln.description,
                'evidence': vuln.evidence,
                'recommendation': vuln.recommendation,
                'discovered_at': vuln.discovered_at.isoformat()
            })
        
        # Save report (you might want to save to file system or S3)
        report_filename = f"vulnerability_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # For this example, we'll just return the data
        # In production, you might save to file system or cloud storage
        
        logger.info(f"Generated vulnerability report for scan {scan_id}")
        return {
            'report_filename': report_filename,
            'report_data': report_data
        }
        
    except ScanTC3.DoesNotExist:
        error_msg = f"Scan {scan_id} not found"
        logger.error(error_msg)
        return {'error': error_msg}
    except Exception as e:
        error_msg = f"Report generation failed: {str(e)}"
        logger.error(error_msg)
        return {'error': error_msg}