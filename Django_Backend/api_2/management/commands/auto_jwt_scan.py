import os
import django
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import time
import threading
from django.db import connection

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'AIToolSuite_prod.settings')
django.setup()

from api_2.services import JWTScanServiceTC4
from api_2.models import JWTScanTC4

User = get_user_model()


class Command(BaseCommand):
    help = 'Automatically start JWT scans for new scan_ids in api_orch_postmanapi table'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=60,
            help='Check interval in seconds (default: 60)'
        )
        parser.add_argument(
            '--daemon',
            action='store_true',
            help='Run as daemon (continuous monitoring)'
        )
        parser.add_argument(
            '--scan-id',
            type=int,
            help='Run scan for specific scan_id (one-time execution)'
        )

    def handle(self, *args, **options):
        interval = options['interval']
        daemon_mode = options['daemon']
        specific_scan_id = options.get('scan_id')

        if specific_scan_id:
            self.run_single_scan(specific_scan_id)
        elif daemon_mode:
            self.stdout.write(f'Starting JWT scanner daemon (check interval: {interval}s)')
            self.run_daemon(interval)
        else:
            self.stdout.write('Running single check for new scans')
            self.check_and_start_scans()

    def run_single_scan(self, scan_id):
        """Run scan for a specific scan_id"""
        try:
            # Check if scan already exists
            if JWTScanTC4.objects.filter(scan_id=scan_id).exists():
                self.stdout.write(
                    self.style.WARNING(f'Scan {scan_id} already exists')
                )
                return

            # Check if APIs exist for this scan_id
            if not self.check_apis_exist(scan_id):
                self.stdout.write(
                    self.style.ERROR(f'No APIs found for scan_id {scan_id}')
                )
                return

            # Get or create system user for automated scans
            user = self.get_system_user()

            # Start scan
            scan_service = JWTScanServiceTC4()
            scan = scan_service.start_scan(scan_id, user)

            self.stdout.write(
                self.style.SUCCESS(f'Started JWT scan for scan_id {scan_id}')
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to start scan {scan_id}: {str(e)}')
            )

    def run_daemon(self, interval):
        """Run as daemon - continuous monitoring"""
        self.stdout.write('JWT Scanner Daemon started. Press Ctrl+C to stop.')
        
        try:
            while True:
                try:
                    self.check_and_start_scans()
                    time.sleep(interval)
                except KeyboardInterrupt:
                    self.stdout.write('\nShutting down JWT Scanner Daemon...')
                    break
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'Error in daemon loop: {str(e)}')
                    )
                    time.sleep(interval)
        
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Daemon crashed: {str(e)}')
            )

    def check_and_start_scans(self):
        """Check for new scan_ids and start JWT scans"""
        try:
            # Get all unique scan_ids from api_orch_postmanapi
            new_scan_ids = self.get_new_scan_ids()
            
            if not new_scan_ids:
                self.stdout.write('No new scans to process')
                return

            self.stdout.write(f'Found {len(new_scan_ids)} new scan(s): {new_scan_ids}')

            # Get system user
            user = self.get_system_user()
            scan_service = JWTScanServiceTC4()

            # Start scans in separate threads
            for scan_id in new_scan_ids:
                try:
                    def run_scan(sid):
                        try:
                            scan_service.start_scan(sid, user)
                            self.stdout.write(
                                self.style.SUCCESS(f'Started JWT scan for scan_id {sid}')
                            )
                        except Exception as e:
                            self.stdout.write(
                                self.style.ERROR(f'Failed to start scan {sid}: {str(e)}')
                            )

                    thread = threading.Thread(target=run_scan, args=(scan_id,))
                    thread.daemon = True
                    thread.start()

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'Error starting scan {scan_id}: {str(e)}')
                    )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error checking for new scans: {str(e)}')
            )

    def get_new_scan_ids(self):
        """Get scan_ids that exist in api_orch_postmanapi but not in JWTScanTC4"""
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT aop.scan_id
                    FROM api_orch_postmanapi aop
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM jwt_scan_tc4 jst
                        WHERE jst.scan_id = aop.scan_id
                    )
                    ORDER BY aop.scan_id
                """)
                                
                return [row[0] for row in cursor.fetchall()]

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error querying new scan_ids: {str(e)}')
            )
            return []

    def check_apis_exist(self, scan_id):
        """Check if APIs exist for given scan_id"""
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM api_orch_postmanapi 
                    WHERE "scan_id" = %s
                """, [scan_id])
                
                count = cursor.fetchone()[0]
                return count > 0

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error checking APIs for scan_id {scan_id}: {str(e)}')
            )
            return False

    def get_system_user(self):
        """Get or create system user for automated scans"""
        try:
            user, created = User.objects.get_or_create(
                username='jwt_scanner_system',
                defaults={
                    'email': 'jwt.scanner@system.local',
                    'first_name': 'JWT',
                    'last_name': 'Scanner',
                    'is_active': True,
                    'is_staff': True,
                }
            )
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS('Created system user: jwt_scanner_system')
                )
            
            return user

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error getting system user: {str(e)}')
            )
            # Fallback to first superuser
            return User.objects.filter(is_superuser=True).first()


# Auto-run the command when this module is imported
if __name__ == '__main__':
    import sys
    from django.core.management import execute_from_command_line
    
    # Auto-start daemon mode
    command = Command()
    command.handle(daemon=True, interval=30)  # Check every 30 seconds