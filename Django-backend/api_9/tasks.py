from celery import shared_task, current_task
from .services import SubdomainDiscoveryService
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def async_subdomain_discovery(self, scan_id):
    """Async task for subdomain discovery with progress tracking"""
    try:
        # Update task state to PROGRESS
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': 5, 'message': 'Starting subdomain discovery...'}
        )
        
        service = SubdomainDiscoveryService()
        
        # Step 1: Get APIs for scan_id
        self.update_state(
            state='PROGRESS',
            meta={'current': 1, 'total': 5, 'message': 'Fetching APIs for scan_id...'}
        )
        
        # Step 2: Extract base URLs
        self.update_state(
            state='PROGRESS',
            meta={'current': 2, 'total': 5, 'message': 'Extracting base URLs...'}
        )
        
        # Step 3: Discover subdomains
        self.update_state(
            state='PROGRESS',
            meta={'current': 3, 'total': 5, 'message': 'Running subdomain discovery...'}
        )
        
        # Step 4: Check live subdomains
        self.update_state(
            state='PROGRESS',
            meta={'current': 4, 'total': 5, 'message': 'Checking live subdomains...'}
        )
        
        # Step 5: Analyze environments and save
        self.update_state(
            state='PROGRESS',
            meta={'current': 5, 'total': 5, 'message': 'Analyzing environments and saving results...'}
        )
        
        # Process the scan
        results = service.process_scan(scan_id)
        
        if 'error' in results:
            self.update_state(
                state='FAILURE',
                meta={'error': results['error']}
            )
            return {'error': results['error']}
        
        logger.info(f"Subdomain discovery completed for scan_id: {scan_id}")
        
        return {
            'status': 'completed',
            'scan_id': scan_id,
            'results': results
        }
        
    except Exception as e:
        logger.error(f"Error in async_subdomain_discovery for scan_id {scan_id}: {str(e)}")
        self.update_state(
            state='FAILURE',
            meta={'error': str(e)}
        )
        return {'error': str(e)}