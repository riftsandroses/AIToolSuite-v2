from django.utils import timezone
from datetime import timedelta
from ..models import ScanTokens
import logging

logger = logging.getLogger(__name__)

class TokenManager:
    """Utility class for managing scan tokens"""
    
    @staticmethod
    def get_valid_token(scan):
        """
        Get a valid access token for a scan, refreshing if necessary
        Returns the token string or None if unable to get a valid token
        """
        try:
            scan_tokens = scan.tokens
            
            # Check if token is valid
            if not scan_tokens.is_token_expired():
                return scan_tokens.access_token
            
            # Token is expired, try to refresh
            logger.info(f"Token expired for scan {scan.id}, attempting refresh")
            
            if scan_tokens.refresh_token:
                try:
                    from ..views import ScanTokenRefreshView
                    refresh_view = ScanTokenRefreshView()
                    refresh_view._refresh_using_refresh_token(scan, scan_tokens)
                    
                    # Reload the token after refresh
                    scan_tokens.refresh_from_db()
                    return scan_tokens.access_token
                
                except Exception as refresh_error:
                    logger.warning(f"Refresh token failed for scan {scan.id}: {str(refresh_error)}")
            
            # Fall back to full login
            logger.info(f"Attempting full login for scan {scan.id}")
            
            from ..views import ScanTokenManagementView
            
            class MockRequest:
                def __init__(self, user):
                    self.user = user
            
            mock_request = MockRequest(scan.created_by)
            
            login_view = ScanTokenManagementView()
            login_view.request = mock_request
            
            # Find login API
            login_api = login_view._find_login_api(scan)
            if not login_api:
                logger.error(f"No login API found for scan {scan.id}")
                return None
            
            # Perform login
            token_data = login_view._perform_login_request(scan, login_api)
            
            # Save tokens
            login_view._save_tokens(scan, token_data, login_api)
            
            # Reload and return new token
            scan_tokens.refresh_from_db()
            return scan_tokens.access_token
            
        except ScanTokens.DoesNotExist:
            logger.error(f"No tokens found for scan {scan.id}")
            return None
        
        except Exception as e:
            logger.error(f"Failed to get valid token for scan {scan.id}: {str(e)}")
            return None
    
    @staticmethod
    def get_authenticated_headers(scan, base_headers=None):
        """
        Get headers with authentication token for API requests
        """
        headers = base_headers.copy() if base_headers else {}
        
        token = TokenManager.get_valid_token(scan)
        if token:
            # Common authorization header formats
            if 'Authorization' not in headers:
                headers['Authorization'] = f'Bearer {token}'
        
        return headers, token is not None
    
    @staticmethod
    def get_token_status(scan):
        """
        Get detailed token status for a scan
        """
        try:
            scan_tokens = scan.tokens
            
            return {
                'has_tokens': bool(scan_tokens.access_token),
                'is_expired': scan_tokens.is_token_expired(),
                'expires_at': scan_tokens.token_expires_at,
                'expires_in_minutes': (
                    int((scan_tokens.token_expires_at - timezone.now()).total_seconds() / 60)
                    if scan_tokens.token_expires_at else 0
                ),
                'last_login_attempt': scan_tokens.last_login_attempt,
                'login_successful': scan_tokens.login_successful,
                'has_refresh_token': bool(scan_tokens.refresh_token)
            }
        
        except ScanTokens.DoesNotExist:
            return {
                'has_tokens': False,
                'is_expired': True,
                'expires_at': None,
                'expires_in_minutes': 0,
                'last_login_attempt': None,
                'login_successful': False,
                'has_refresh_token': False
            }
