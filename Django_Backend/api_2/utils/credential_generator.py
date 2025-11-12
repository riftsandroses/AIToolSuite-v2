"""
Utility for generating and managing test credentials for vulnerability scanning
"""
import random
import string
from typing import List, Dict, Any
from django.core.management.base import BaseCommand
from ..models import TestCredentialTC2


class CredentialGeneratorTC2:
    """Generate common credentials for brute force testing"""
    
    # Common usernames
    COMMON_USERNAMES = [
        'admin', 'administrator', 'root', 'user', 'test', 'guest', 'demo',
        'support', 'service', 'operator', 'manager', 'supervisor', 'owner',
        'dev', 'developer', 'api', 'system', 'backup', 'monitor',
        'sa', 'sysadmin', 'webmaster', 'postmaster', 'mail', 'email',
        'ftp', 'ssh', 'web', 'www', 'mysql', 'postgres', 'oracle',
        'student', 'teacher', 'employee', 'client', 'customer', 'member'
    ]
    
    # Common passwords
    COMMON_PASSWORDS = [
        'password', 'admin', '123456', 'password123', 'admin123',
        'qwerty', 'letmein', 'welcome', 'monkey', '1234567890',
        'password1', 'abc123', 'Password1', 'root', 'toor',
        'pass', 'test', 'guest', 'demo', 'user', 'default',
        'login', 'secret', 'master', 'super', 'god', 'security',
        '000000', '111111', '123123', '654321', '987654321',
        'Password@123', 'Admin@123', 'Test@123', 'Welcome123',
        'company', 'business', 'office', 'enterprise', 'corporate'
    ]
    
    # Weak passwords patterns
    WEAK_PATTERNS = [
        'password{year}', 'admin{year}', '{company}123', '{company}@123',
        'Welcome{year}', 'Password{month}', '{username}123', '{username}@123',
        '{username}{year}', 'temp123', 'temp@123', 'changeme',
        'newuser', 'newpass', 'initial', 'setup', 'config'
    ]
    
    # Default service credentials
    DEFAULT_SERVICE_CREDS = [
        ('admin', 'admin'),
        ('root', 'root'),
        ('administrator', 'administrator'),
        ('sa', ''),  # SQL Server
        ('postgres', 'postgres'),
        ('mysql', 'mysql'),
        ('oracle', 'oracle'),
        ('tomcat', 'tomcat'),
        ('jenkins', 'jenkins'),
        ('elastic', 'changeme'),
        ('kibana', 'changeme'),
        ('grafana', 'admin'),
        ('nagios', 'nagios'),
        ('zabbix', 'zabbix'),
        ('cacti', 'admin'),
        ('openfire', 'admin'),
        ('gitlab', 'root'),
        ('nexus', 'admin123'),
        ('sonar', 'admin'),
        ('splunk', 'changeme'),
    ]
    
    @classmethod
    def generate_credential_combinations(cls, limit: int = 100) -> List[Dict[str, str]]:
        """Generate common credential combinations"""
        credentials = []
        
        # Add default service credentials
        for username, password in cls.DEFAULT_SERVICE_CREDS:
            credentials.append({
                'username': username,
                'email': f'{username}@example.com',
                'password': password if password else username,
                'credential_type': 'default_service'
            })
        
        # Add common combinations
        for username in cls.COMMON_USERNAMES[:20]:
            for password in cls.COMMON_PASSWORDS[:10]:
                if len(credentials) >= limit:
                    break
                
                credentials.append({
                    'username': username,
                    'email': f'{username}@{random.choice(["example.com", "test.com", "demo.com", "company.com"])}',
                    'password': password,
                    'credential_type': 'common'
                })
            
            if len(credentials) >= limit:
                break
        
        # Add username-based passwords
        for username in cls.COMMON_USERNAMES[:15]:
            if len(credentials) >= limit:
                break
                
            # username + numbers
            for suffix in ['123', '1', '2024', '2025', '@123']:
                credentials.append({
                    'username': username,
                    'email': f'{username}@example.com',
                    'password': f'{username}{suffix}',
                    'credential_type': 'username_based'
                })
        
        # Add weak pattern passwords
        current_year = 2025
        current_month = 'jan'
        company_names = ['company', 'corp', 'inc', 'ltd', 'org']
        
        for pattern in cls.WEAK_PATTERNS[:10]:
            if len(credentials) >= limit:
                break
                
            for username in cls.COMMON_USERNAMES[:5]:
                password = pattern.replace('{year}', str(current_year))
                password = password.replace('{month}', current_month)
                password = password.replace('{username}', username)
                password = password.replace('{company}', random.choice(company_names))
                
                credentials.append({
                    'username': username,
                    'email': f'{username}@example.com',
                    'password': password,
                    'credential_type': 'weak_pattern'
                })
        
        return credentials[:limit]
    
    @classmethod
    def populate_test_credentials(cls, limit: int = 200):
        """Populate database with test credentials"""
        credentials = cls.generate_credential_combinations(limit)
        
        # Clear existing credentials
        TestCredentialTC2.objects.all().delete()
        
        # Create new credentials
        created_count = 0
        for cred_data in credentials:
            try:
                TestCredentialTC2.objects.get_or_create(
                    username=cred_data['username'],
                    password=cred_data['password'],
                    defaults={
                        'email': cred_data['email'],
                        'credential_type': cred_data['credential_type'],
                        'is_active': True
                    }
                )
                created_count += 1
            except Exception as e:
                continue
        
        return created_count
    
    @classmethod
    def generate_targeted_credentials(cls, target_info: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate credentials targeted to specific application/company"""
        credentials = []
        
        # Extract target information
        company_name = target_info.get('company', 'company')
        app_name = target_info.get('application', 'app')
        domain = target_info.get('domain', 'example.com')
        year = target_info.get('year', 2025)
        
        # Company-based credentials
        company_variations = [
            company_name.lower(),
            company_name.upper(),
            company_name.capitalize(),
        ]
        
        for company in company_variations:
            for suffix in ['', '123', '2024', '2025', '@123', '!']:
                credentials.append({
                    'username': 'admin',
                    'email': f'admin@{domain}',
                    'password': f'{company}{suffix}',
                    'credential_type': 'targeted_company'
                })
        
        # Application-based credentials
        app_variations = [
            app_name.lower(),
            app_name.upper(),
            app_name.capitalize(),
        ]
        
        for app in app_variations:
            for suffix in ['', '123', 'admin', 'user', 'test']:
                credentials.append({
                    'username': app,
                    'email': f'{app}@{domain}',
                    'password': f'{app}{suffix}',
                    'credential_type': 'targeted_app'
                })
        
        # Domain-based usernames
        domain_parts = domain.split('.')
        if len(domain_parts) > 0:
            base_domain = domain_parts[0]
            for password in cls.COMMON_PASSWORDS[:10]:
                credentials.append({
                    'username': base_domain,
                    'email': f'{base_domain}@{domain}',
                    'password': password,
                    'credential_type': 'targeted_domain'
                })
        
        return credentials
    
    @staticmethod
    def validate_credential_strength(password: str) -> Dict[str, Any]:
        """Validate credential strength"""
        score = 0
        issues = []
        
        if len(password) < 8:
            issues.append("Password too short")
        else:
            score += 1
        
        if not any(c.islower() for c in password):
            issues.append("No lowercase letters")
        else:
            score += 1
        
        if not any(c.isupper() for c in password):
            issues.append("No uppercase letters")
        else:
            score += 1
        
        if not any(c.isdigit() for c in password):
            issues.append("No numbers")
        else:
            score += 1
        
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            issues.append("No special characters")
        else:
            score += 1
        
        # Check for common passwords
        if password.lower() in [p.lower() for p in CredentialGeneratorTC2.COMMON_PASSWORDS]:
            issues.append("Common password")
            score = max(0, score - 2)
        
        strength = "Very Weak"
        if score >= 4:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        elif score >= 2:
            strength = "Weak"
        
        return {
            'score': score,
            'max_score': 5,
            'strength': strength,
            'issues': issues
        }


class Command(BaseCommand):
    """Django management command to populate test credentials"""
    help = 'Populate test credentials for vulnerability scanning'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=200,
            help='Number of credentials to generate'
        )
        
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing credentials before populating'
        )
    
    def handle(self, *args, **options):
        limit = options['limit']
        clear = options['clear']
        
        if clear:
            TestCredentialTC2.objects.all().delete()
            self.stdout.write(
                self.style.WARNING('Cleared existing test credentials')
            )
        
        created_count = CredentialGeneratorTC2.populate_test_credentials(limit)
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created {created_count} test credentials'
            )
        )