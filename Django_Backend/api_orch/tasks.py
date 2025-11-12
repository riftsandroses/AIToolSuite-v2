from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import ScanTokens, Scan
import requests
import json
import logging

logger = logging.getLogger(__name__)

@shared_task
def refresh_scan_tokens():
    """
    Celery task to refresh tokens for all scans that need it
    This task should be run every 10 minutes to ensure tokens are refreshed before expiry
    """
    logger.info("Starting token refresh task")
    
    # Find all scans with tokens that are expired or about to expire (within 5 minutes)
    threshold_time = timezone.now() + timedelta(minutes=5)
    
    expired_tokens = ScanTokens.objects.filter(
        token_expires_at__lte=threshold_time,
        login_successful=True
    ).select_related('scan')
    
    refreshed_count = 0
    failed_count = 0
    
    for scan_token in expired_tokens:
        try:
            logger.info(f"Refreshing tokens for scan: {scan_token.scan.scan_name}")
            
            # Try refresh token first, then fall back to full login
            if scan_token.refresh_token:
                try:
                    refresh_with_refresh_token.delay(scan_token.scan.id)
                    refreshed_count += 1
                except Exception as e:
                    logger.warning(f"Refresh token failed for scan {scan_token.scan.id}, trying full login: {str(e)}")
                    perform_full_login.delay(scan_token.scan.id)
                    refreshed_count += 1
            else:
                perform_full_login.delay(scan_token.scan.id)
                refreshed_count += 1
                
        except Exception as e:
            logger.error(f"Failed to refresh tokens for scan {scan_token.scan.id}: {str(e)}")
            failed_count += 1
    
    logger.info(f"Token refresh task completed. Refreshed: {refreshed_count}, Failed: {failed_count}")
    
    return {
        'refreshed': refreshed_count,
        'failed': failed_count,
        'total_processed': refreshed_count + failed_count
    }

@shared_task
def perform_full_login(scan_id):
    """
    Celery task to perform full login for a specific scan
    """
    try:
        scan = Scan.objects.get(id=scan_id)
        logger.info(f"Performing full login for scan: {scan.scan_name}")
        
        # Import here to avoid circular imports
        from .views import ScanTokenManagementView
        
        # Create a mock request-like object for the view
        class MockRequest:
            def __init__(self, user):
                self.user = user
        
        mock_request = MockRequest(scan.created_by)
        
        # Create view instance and perform login
        view = ScanTokenManagementView()
        view.request = mock_request
        
        # Find login API
        login_api = view._find_login_api(scan)
        if not login_api:
            raise Exception("No login API found")
        
        # Perform login
        token_data = view._perform_login_request(scan, login_api)
        
        # Save tokens
        view._save_tokens(scan, token_data, login_api)
        
        logger.info(f"Successfully refreshed tokens for scan: {scan.scan_name}")
        return {"status": "success", "scan_id": scan_id}
        
    except Exception as e:
        logger.error(f"Failed to perform full login for scan {scan_id}: {str(e)}")
        
        # Save error to database
        try:
            scan = Scan.objects.get(id=scan_id)
            view = ScanTokenManagementView()
            view._save_login_error(scan, str(e))
        except:
            pass
        
        return {"status": "failed", "scan_id": scan_id, "error": str(e)}

@shared_task
def refresh_with_refresh_token(scan_id):
    """
    Celery task to refresh tokens using refresh token for a specific scan
    """
    try:
        scan = Scan.objects.get(id=scan_id)
        scan_tokens = scan.tokens
        
        logger.info(f"Refreshing tokens using refresh token for scan: {scan.scan_name}")
        
        # Import here to avoid circular imports
        from .views import ScanTokenRefreshView
        
        view = ScanTokenRefreshView()
        view._refresh_using_refresh_token(scan, scan_tokens)
        
        logger.info(f"Successfully refreshed tokens using refresh token for scan: {scan.scan_name}")
        return {"status": "success", "scan_id": scan_id, "method": "refresh_token"}
        
    except Exception as e:
        logger.error(f"Failed to refresh using refresh token for scan {scan_id}: {str(e)}")
        # This will cause the main task to fall back to full login
        raise e