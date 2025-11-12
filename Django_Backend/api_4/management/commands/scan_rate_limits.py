from django.core.management.base import BaseCommand
from api_4.utils.rate_limit_scanner import RateLimitScanner

class Command(BaseCommand):
    help = 'Run rate limiting vulnerability scan'
    
    def add_arguments(self, parser):
        parser.add_argument('scan_id', type=int, help='Scan ID to process')
        parser.add_argument('--max-requests', type=int, default=100, help='Maximum requests per API')
        parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests')
        
    def handle(self, *args, **options):
        scanner = RateLimitScanner(
            scan_id=options['scan_id'],
            max_requests=options['max_requests'],
            delay=options['delay']
        )
        
        try:
            results = scanner.scan_all_apis()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully scanned {len(results)} APIs for scan_id {options["scan_id"]}'
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Scan failed: {str(e)}')
            )
