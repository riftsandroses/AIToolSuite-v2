"""
Django management command to populate test credentials
Usage: python manage.py populate_credentials --limit 200 --clear
"""

from django.core.management.base import BaseCommand
from api_2.utils.credential_generator import CredentialGeneratorTC2
from api_2.models import TestCredentialTC2


class Command(BaseCommand):
    help = 'Populate test credentials for vulnerability scanning'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=200,
            help='Number of credentials to generate (default: 200)'
        )
        
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing credentials before populating'
        )
        
        parser.add_argument(
            '--type',
            choices=['all', 'common', 'service', 'weak'],
            default='all',
            help='Type of credentials to generate'
        )
        
        parser.add_argument(
            '--company',
            type=str,
            help='Company name for targeted credentials'
        )
        
        parser.add_argument(
            '--domain',
            type=str,
            help='Domain name for targeted credentials'
        )
    
    def handle(self, *args, **options):
        limit = options['limit']
        clear = options['clear']
        cred_type = options['type']
        company = options.get('company')
        domain = options.get('domain')
        
        if clear:
            count = TestCredentialTC2.objects.count()
            TestCredentialTC2.objects.all().delete()
            self.stdout.write(
                self.style.WARNING(f'Cleared {count} existing test credentials')
            )
        
        # Generate targeted credentials if company/domain provided
        if company or domain:
            target_info = {
                'company': company or 'company',
                'domain': domain or 'example.com',
                'year': 2025
            }
            credentials = CredentialGeneratorTC2.generate_targeted_credentials(target_info)
            
            created_count = 0
            for cred_data in credentials[:limit]:
                obj, created = TestCredentialTC2.objects.get_or_create(
                    username=cred_data['username'],
                    password=cred_data['password'],
                    defaults={
                        'email': cred_data['email'],
                        'credential_type': cred_data['credential_type'],
                        'is_active': True
                    }
                )
                if created:
                    created_count += 1
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created {created_count} targeted credentials'
                )
            )
        else:
            # Generate standard credentials
            created_count = CredentialGeneratorTC2.populate_test_credentials(limit)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created {created_count} test credentials'
                )
            )
        
        # Display statistics
        total_creds = TestCredentialTC2.objects.count()
        active_creds = TestCredentialTC2.objects.filter(is_active=True).count()
        
        type_stats = {}
        for cred_type_choice in TestCredentialTC2.objects.values_list('credential_type', flat=True).distinct():
            type_stats[cred_type_choice] = TestCredentialTC2.objects.filter(
                credential_type=cred_type_choice
            ).count()
        
        self.stdout.write('\nCredential Statistics:')
        self.stdout.write(f'Total credentials: {total_creds}')
        self.stdout.write(f'Active credentials: {active_creds}')
        self.stdout.write('\nBy Type:')
        for ctype, count in type_stats.items():
            self.stdout.write(f'  {ctype}: {count}')
        
        # Show sample credentials
        self.stdout.write('\nSample credentials:')
        samples = TestCredentialTC2.objects.filter(is_active=True)[:5]
        for cred in samples:
            self.stdout.write(f'  {cred.username}:{cred.password} ({cred.credential_type})')
        
        if not samples.exists():
            self.stdout.write('  No credentials found')
        
        self.stdout.write(
            self.style.SUCCESS('\nCredential population completed successfully!')
        )