from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.utils import timezone
import logging
from api_4.services import FileUploadVulnerabilityScanner
from api_4.models import ScanSession

class Command(BaseCommand):
    help = 'Run file upload vulnerability scan from command line'
    
    def add_arguments(self, parser):
        parser.add_argument('scan_id', type=int, help='Scan ID to process')
        parser.add_argument(
            '--user-id',
            type=int,
            default=1,
            help='User ID to associate with the scan (default: 1)'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose logging'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be scanned without actually running tests'
        )
    
    def handle(self, *args, **options):
        # Set up logging
        log_level = logging.DEBUG if options['verbose'] else logging.INFO
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        
        scan_id = options['scan_id']
        user_id = options['user_id']
        dry_run = options['dry_run']
        
        try:
            # Get user
            user = User.objects.get(id=user_id)
            
            self.stdout.write(
                self.style.SUCCESS(f'Starting file upload vulnerability scan for scan_id: {scan_id}')
            )
            
            # Create scanner
            scanner = FileUploadVulnerabilityScanner(scan_id, user)
            
            if dry_run:
                # Just show what would be scanned
                apis = scanner.get_apis_for_scan()
                jwt_token = scanner.get_jwt_token()
                
                self.stdout.write(f'Would scan {len(apis)} APIs:')
                for api in apis:
                    self.stdout.write(f'  - {api["name"]} ({api["method"]} {api["url"]})')
                
                if jwt_token:
                    self.stdout.write(f'JWT token available: {jwt_token[:20]}...')
                else:
                    self.stdout.write(self.style.WARNING('No JWT token found'))
                
                return
            
            # Run actual scan
            start_time = timezone.now()
            scanner.start_scan()
            end_time = timezone.now()
            
            # Get results
            scan_session = ScanSession.objects.get(scan_id=scan_id)
            
            duration = (end_time - start_time).total_seconds()
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Scan completed in {duration:.2f} seconds\n'
                    f'Total APIs: {scan_session.total_apis}\n'
                    f'Vulnerable APIs: {scan_session.vulnerable_apis}\n'
                    f'Status: {scan_session.status}'
                )
            )
            
        except User.DoesNotExist:
            raise CommandError(f'User with ID {user_id} not found')
        except Exception as e:
            raise CommandError(f'Scan failed: {str(e)}')