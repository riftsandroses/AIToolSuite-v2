from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from api_orch.models import ScanTokens
from api_orch.views import ScanTokenManagementView
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Refresh authentication tokens for all scans'

    def add_arguments(self, parser):
        parser.add_argument(
            '--scan-id',
            type=int,
            help='Refresh tokens for a specific scan ID only',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force refresh even if tokens are not expired',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be refreshed without actually doing it',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting token refresh process...'))
        
        # Determine which tokens to refresh
        if options['scan_id']:
            # Refresh specific scan
            try:
                scan_tokens = ScanTokens.objects.get(scan__id=options['scan_id'])
                tokens_to_refresh = [scan_tokens]
                self.stdout.write(f"Targeting specific scan ID: {options['scan_id']}")
            except ScanTokens.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"No tokens found for scan ID: {options['scan_id']}")
                )
                return
        else:
            # Find tokens that need refreshing
            if options['force']:
                # Refresh all tokens
                tokens_to_refresh = ScanTokens.objects.filter(login_successful=True)
                self.stdout.write("Force refresh mode: targeting all successful logins")
            else:
                # Only refresh expired or soon-to-expire tokens
                threshold_time = timezone.now() + timedelta(minutes=5)
                tokens_to_refresh = ScanTokens.objects.filter(
                    token_expires_at__lte=threshold_time,
                    login_successful=True
                )
                self.stdout.write(f"Targeting tokens expiring before: {threshold_time}")

        if not tokens_to_refresh:
            self.stdout.write(self.style.WARNING('No tokens need refreshing'))
            return

        self.stdout.write(f"Found {len(tokens_to_refresh)} tokens to refresh")

        if options['dry_run']:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No actual refreshing will occur'))
            for token in tokens_to_refresh:
                self.stdout.write(
                    f"Would refresh: {token.scan.scan_name} (ID: {token.scan.id}) - "
                    f"Expires: {token.token_expires_at}"
                )
            return

        # Perform actual refresh
        success_count = 0
        error_count = 0

        for scan_token in tokens_to_refresh:
            try:
                self.stdout.write(f"Refreshing tokens for: {scan_token.scan.scan_name}")
                
                # Create mock request for the view
                class MockRequest:
                    def __init__(self, user):
                        self.user = user

                mock_request = MockRequest(scan_token.scan.created_by)
                
                # Try refresh token first if available
                if scan_token.refresh_token and not options['force']:
                    try:
                        from api_orch.views import ScanTokenRefreshView
                        refresh_view = ScanTokenRefreshView()
                        refresh_view._refresh_using_refresh_token(scan_token.scan, scan_token)
                        
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"✓ Refreshed using refresh token: {scan_token.scan.scan_name}"
                            )
                        )
                        success_count += 1
                        continue
                        
                    except Exception as refresh_error:
                        self.stdout.write(
                            self.style.WARNING(
                                f"Refresh token failed for {scan_token.scan.scan_name}, "
                                f"trying full login: {str(refresh_error)}"
                            )
                        )

                # Fall back to full login
                login_view = ScanTokenManagementView()
                login_view.request = mock_request
                
                # Find login API
                login_api = login_view._find_login_api(scan_token.scan)
                if not login_api:
                    raise Exception("No login API found")
                
                # Perform login
                token_data = login_view._perform_login_request(scan_token.scan, login_api)
                
                # Save tokens
                login_view._save_tokens(scan_token.scan, token_data, login_api)
                
                self.stdout.write(
                    self.style.SUCCESS(f"✓ Full login successful: {scan_token.scan.scan_name}")
                )
                success_count += 1

            except Exception as e:
                error_msg = f"✗ Failed to refresh {scan_token.scan.scan_name}: {str(e)}"
                self.stdout.write(self.style.ERROR(error_msg))
                logger.error(error_msg)
                error_count += 1
                
                # Save error to database
                try:
                    login_view = ScanTokenManagementView()
                    login_view._save_login_error(scan_token.scan, str(e))
                except:
                    pass

        # Summary
        self.stdout.write(
            self.style.SUCCESS(
                f"\nToken refresh completed:\n"
                f"  Successful: {success_count}\n"
                f"  Failed: {error_count}\n"
                f"  Total: {success_count + error_count}"
            )
        )
