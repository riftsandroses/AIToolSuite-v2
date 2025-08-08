import os
from django.core.management.base import BaseCommand
from api_7.models import Payload

class Command(BaseCommand):
    help = 'Imports SSRF payloads from text files into the database'
    def add_arguments(self, parser):
        parser.add_argument(
            '--category',
            type=str,
            help='Import payloads for a specific category only',
        )
    def handle(self, *args, **kwargs):
        # Define a mapping from your filenames to the database categories
        payload_files = {
            'cloud_metadata.txt': 'cloud_metadata',
            'dns_rebinding.txt': 'dns_rebinding',
            'encoded_payloads.txt': 'encoded',
            'headers.txt': 'headers',
            'local_ips.txt': 'local_ips',
            'parameter_payloads.txt': 'parameters',
            'port_payloads.txt': 'ports',
            'protocols.txt': 'protocols',
            'waf_bypass.txt': 'waf_bypass',
        }

        # Clear existing payloads to avoid duplicates on re-runs
        self.stdout.write(self.style.WARNING('Clearing existing payloads...'))
        Payload.objects.all().delete()
        self.stdout.write(self.style.SUCCESS('Payloads cleared.'))

        # Path to the 'Payloads' directory inside the 'ssrf' app
        payloads_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'payloads')


        for filename, category in payload_files.items():
            file_path = os.path.join(payloads_dir, filename)
            
            try:
                with open(file_path, 'r') as f:
                    # Read all lines, stripping whitespace and filtering out empty lines or comments
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    
                    for p_str in payloads:
                        Payload.objects.create(
                            category=category,
                            payload=p_str
                        )
                self.stdout.write(self.style.SUCCESS(f'Successfully imported payloads from {filename}'))

            except FileNotFoundError:
                self.stdout.write(self.style.ERROR(f'File not found: {file_path}. Please ensure your Payloads folder and files are correctly placed.'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'An error occurred with {filename}: {e}'))

        self.stdout.write(self.style.SUCCESS('Payload import complete!'))