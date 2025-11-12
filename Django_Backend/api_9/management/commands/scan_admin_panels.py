from django.core.management.base import BaseCommand
from django.apps import apps
from api_9.utils import AdminPanelScanner
from api_9.models import AdminPanelScanResult
import time


class Command(BaseCommand):
    help = 'Scan for admin panels based on scan_id'
    
    def add_arguments(self, parser):
        parser.add_argument('scan_id', type=str, help='Scan ID to process')
        parser.add_argument(
            '--timeout', 
            type=int, 
            default=10, 
            help='Request timeout in seconds'
        )
        parser.add_argument(
            '--workers', 
            type=int, 
            default=5, 
            help='Number of concurrent workers'
        )
        parser.add_argument(
            '--clear-previous', 
            action='store_true', 
            help='Clear previous scan results'
        )
        
    def handle(self, *args, **options):
        scan_id = options['scan_id']
        timeout = options['timeout']
        workers = options['workers']
        clear_previous = options['clear_previous']
        
        try:
            # Get the api_orch_postmanapi model
            PostmanAPI = apps.get_model('api_orch', 'postmanapi')
            
            # Fetch APIs based on scan_id
            apis = PostmanAPI.objects.filter(scan_id=scan_id)
            
            if not apis.exists():
                self.stdout.write(
                    self.style.ERROR(f'No APIs found for scan_id: {scan_id}')
                )
                return
                
            if clear_previous:
                deleted_count = AdminPanelScanResult.objects.filter(scan_id=scan_id).count()
                AdminPanelScanResult.objects.filter(scan_id=scan_id).delete()
                self.stdout.write(
                    self.style.WARNING(f'Cleared {deleted_count} previous results')
                )
                
            # Initialize scanner
            scanner = AdminPanelScanner(timeout=timeout, max_workers=workers)
            
            self.stdout.write(f'Starting scan for {apis.count()} APIs...')
            start_time = time.time()
            
            accessible_count = 0
            total_results = 0
            
            for i, api in enumerate(apis, 1):
                self.stdout.write(f'Scanning API {i}/{apis.count()}: {api.url}')
                
                scan_results = scanner.scan_url(api.url)
                
                for result in scan_results:
                    scan_result, created = AdminPanelScanResult.objects.update_or_create(
                        scan_id=scan_id,
                        admin_panel_url=result['url'],
                        defaults={
                            'api_url': api.url,
                            'is_accessible': result['is_accessible'],
                            'status_code': result['status_code'],
                            'response_time': result['response_time'],
                            'admin_panel_type': result['admin_panel_type'],
                            'error_message': result['error_message']
                        }
                    )
                    
                    total_results += 1
                    if result['is_accessible']:
                        accessible_count += 1
                        self.stdout.write(
                            self.style.SUCCESS(
                                f'  ✓ Found accessible admin panel: {result["url"]} '
                                f'({result["admin_panel_type"]})'
                            )
                        )
                        
            scan_duration = time.time() - start_time
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'\nScan completed in {scan_duration:.2f} seconds:\n'
                    f'  • Total APIs scanned: {apis.count()}\n'
                    f'  • Total admin panels checked: {total_results}\n'
                    f'  • Accessible admin panels found: {accessible_count}\n'
                    f'  • Inaccessible admin panels: {total_results - accessible_count}'
                )
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error during scan: {str(e)}')
            )
