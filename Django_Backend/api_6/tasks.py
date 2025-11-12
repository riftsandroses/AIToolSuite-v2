# tasks.py - Celery tasks for async vulnerability testing
from celery import shared_task
from django.utils import timezone
from .models import VulnerabilityScanTC1, ScanTC3, VulnerabilityTC3
from .services import VulnerabilityTestServiceTC1, CouponBruteForceServiceTC3, APIOrchServiceTC3
from .utils.utils_tc3 import LoggerTC3, CacheManagerTC3
import asyncio
import logging

logger = logging.getLogger(__name__)


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


@shared_task(bind=True, max_retries=3)
def execute_security_scan_tc3(self, scan_id: str):
    """Execute security scan as a Celery task"""
    try:
        scan = ScanTC3.objects.get(id=scan_id)
        
        # Get APIs and token from api_orch
        apis = APIOrchServiceTC3.get_apis_by_scan_id(scan.scan_id)
        access_token = APIOrchServiceTC3.get_access_token_by_scan_id(scan.scan_id)
        
        if not apis:
            scan.status = 'failed'
            scan.save()
            logger.error(f"No APIs found for scan {scan_id}")
            return
        
        # Get scan configuration
        config = scan.config
        
        # Log scan start
        LoggerTC3.log_scan_start(scan_id, len(apis), scan.user_id)
        
        # Execute the scan
        service = CouponBruteForceServiceTC3()
        asyncio.run(service.execute_scan(scan_id, apis, access_token, config))
        
        # Log completion
        duration = (scan.end_time - scan.start_time).total_seconds() if scan.end_time and scan.start_time else 0
        LoggerTC3.log_scan_complete(scan_id, duration, scan.vulnerabilities_found)
        
        # Invalidate cache
        CacheManagerTC3.invalidate_scan_cache(scan_id)
        
    except ScanTC3.DoesNotExist:
        logger.error(f"Scan {scan_id} not found")
        return
        
    except Exception as exc:
        logger.error(f"Scan {scan_id} failed: {str(exc)}")
        
        # Update scan status on failure
        try:
            scan = ScanTC3.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
        except:
            pass
        
        # Retry if possible
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying scan {scan_id} (attempt {self.request.retries + 1})")
            raise self.retry(countdown=60, exc=exc)
        
        raise exc


@shared_task
def cleanup_old_scans_tc3():
    """Clean up old scan data"""
    from django.conf import settings
    from datetime import timedelta
    
    retention_days = getattr(settings, 'API6_SCAN_RETENTION_DAYS', 90)
    cutoff_date = timezone.now() - timedelta(days=retention_days)
    
    # Delete old scans and related data
    old_scans = ScanTC3.objects.filter(created_at__lt=cutoff_date)
    deleted_count = old_scans.count()
    old_scans.delete()
    
    logger.info(f"Cleaned up {deleted_count} old scans")
    return deleted_count


@shared_task
def generate_daily_security_report_tc3():
    """Generate daily security report"""
    from django.db.models import Count
    from datetime import timedelta
    
    yesterday = timezone.now() - timedelta(days=1)
    today = timezone.now()
    
    # Get yesterday's statistics
    scans_yesterday = ScanTC3.objects.filter(
        created_at__gte=yesterday,
        created_at__lt=today
    )
    
    vulnerabilities_yesterday = VulnerabilityTC3.objects.filter(
        created_at__gte=yesterday,
        created_at__lt=today
    )
    
    # Count by severity
    vuln_counts = vulnerabilities_yesterday.values('severity').annotate(count=Count('id'))
    severity_summary = {item['severity']: item['count'] for item in vuln_counts}
    
    report_data = {
        'date': yesterday.date(),
        'scans_completed': scans_yesterday.filter(status='completed').count(),
        'scans_failed': scans_yesterday.filter(status='failed').count(),
        'total_vulnerabilities': vulnerabilities_yesterday.count(),
        'critical_vulnerabilities': severity_summary.get('critical', 0),
        'high_vulnerabilities': severity_summary.get('high', 0),
        'medium_vulnerabilities': severity_summary.get('medium', 0),
        'low_vulnerabilities': severity_summary.get('low', 0),
        'info_vulnerabilities': severity_summary.get('info', 0)
    }
    
    logger.info(f"Daily report generated: {report_data}")
    return report_data


@shared_task
def update_vulnerability_intelligence_tc3():
    """Update vulnerability intelligence data"""
    from .utils import CouponPatternGeneratorTC3
    
    try:
        # Generate new patterns based on recent findings
        recent_vulns = VulnerabilityTC3.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=7),
            vulnerability_type='coupon_bruteforce'
        )
        
        # Extract successful patterns from evidence
        new_patterns = []
        for vuln in recent_vulns:
            evidence = vuln.evidence
            if 'valid_codes' in evidence:
                valid_codes = evidence['valid_codes']
                for code in valid_codes:
                    # Generate variations
                    patterns = CouponPatternGeneratorTC3.generate_sequential_patterns(code)
                    new_patterns.extend(patterns[:5])  # Limit per code
        
        # Store new patterns (you might want to save these to a model)
        if new_patterns:
            logger.info(f"Generated {len(new_patterns)} new coupon patterns from recent findings")
        
        return len(new_patterns)
        
    except Exception as e:
        logger.error(f"Failed to update vulnerability intelligence: {str(e)}")
        return 0


@shared_task
def monitor_scan_health_tc3():
    """Monitor scan system health"""
    from django.db.models import Avg, Count
    
    # Check for stuck scans
    stuck_threshold = timezone.now() - timedelta(hours=2)
    stuck_scans = ScanTC3.objects.filter(
        status='in_progress',
        start_time__lt=stuck_threshold
    )
    
    if stuck_scans.exists():
        logger.warning(f"Found {stuck_scans.count()} stuck scans")
        # Mark as failed
        stuck_scans.update(status='failed', end_time=timezone.now())
    
    # Check system performance
    recent_scans = ScanTC3.objects.filter(
        created_at__gte=timezone.now() - timedelta(hours=24),
        status='completed'
    )
    
    if recent_scans.exists():
        # Calculate average scan time
        avg_duration = 0
        durations = []
        for scan in recent_scans:
            if scan.start_time and scan.end_time:
                duration = (scan.end_time - scan.start_time).total_seconds()
                durations.append(duration)
        
        if durations:
            avg_duration = sum(durations) / len(durations)
        
        # Check if performance is degrading
        if avg_duration > 3600:  # More than 1 hour average
            logger.warning(f"Scan performance degraded: avg duration {avg_duration}s")
    
    health_report = {
        'stuck_scans_found': stuck_scans.count(),
        'recent_scans_completed': recent_scans.count(),
        'avg_scan_duration': avg_duration if 'avg_duration' in locals() else 0,
        'timestamp': timezone.now()
    }
    
    return health_report


@shared_task
def export_scan_results_tc3(scan_id: str, format_type: str = 'json'):
    """Export scan results in various formats"""
    try:
        scan = ScanTC3.objects.get(id=scan_id)
        vulnerabilities = scan.vulnerabilities.all()
        results = scan.results.all()
        
        export_data = {
            'scan_info': {
                'id': str(scan.id),
                'scan_id': scan.scan_id,
                'status': scan.status,
                'created_at': scan.created_at.isoformat(),
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'total_apis': scan.total_apis,
                'vulnerabilities_found': scan.vulnerabilities_found
            },
            'vulnerabilities': [
                {
                    'id': str(vuln.id),
                    'type': vuln.vulnerability_type,
                    'severity': vuln.severity,
                    'title': vuln.title,
                    'description': vuln.description,
                    'impact': vuln.impact,
                    'remediation': vuln.remediation,
                    'api_name': vuln.api_name,
                    'api_url': vuln.api_url,
                    'evidence': vuln.evidence,
                    'confidence_score': vuln.confidence_score,
                    'cwe_id': vuln.cwe_id,
                    'owasp_category': vuln.owasp_category,
                    'created_at': vuln.created_at.isoformat()
                }
                for vuln in vulnerabilities
            ],
            'test_results': [
                {
                    'id': str(result.id),
                    'api_name': result.api_name,
                    'api_url': result.api_url,
                    'test_type': result.test_type,
                    'status': result.status,
                    'response_time': result.response_time,
                    'status_code': result.status_code,
                    'findings': result.findings,
                    'tested_at': result.tested_at.isoformat()
                }
                for result in results
            ]
        }
        
        if format_type == 'json':
            import json
            return json.dumps(export_data, indent=2, default=str)
        elif format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write vulnerabilities CSV
            writer.writerow(['ID', 'Type', 'Severity', 'Title', 'API', 'Confidence'])
            for vuln in export_data['vulnerabilities']:
                writer.writerow([
                    vuln['id'], vuln['type'], vuln['severity'],
                    vuln['title'], vuln['api_name'], vuln['confidence_score']
                ])
            
            return output.getvalue()
        
        return export_data
        
    except ScanTC3.DoesNotExist:
        logger.error(f"Scan {scan_id} not found for export")
        return None
    except Exception as e:
        logger.error(f"Failed to export scan {scan_id}: {str(e)}")
        return None