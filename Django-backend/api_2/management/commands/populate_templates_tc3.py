from django.core.management.base import BaseCommand
from api_2.models import VulnerabilityTemplateTC3


class Command(BaseCommand):
    help = 'Populate vulnerability templates with default data'

    def handle(self, *args, **options):
        templates = [
            {
                'name': 'weak_password_policy',
                'vulnerability_type': 'weak_password_policy',
                'title': 'Weak or Default Password Policy',
                'description': '''
                The API accepts weak passwords that can be easily guessed or brute-forced. 
                This vulnerability occurs when password validation is insufficient or missing entirely.
                Common weak passwords include dictionary words, sequential numbers, default credentials,
                and passwords that don't meet complexity requirements.
                ''',
                'impact': '''
                - Unauthorized access to user accounts
                - Account takeover attacks
                - Data breach and information disclosure
                - Privilege escalation
                - Reputational damage and compliance violations
                ''',
                'recommendation': '''
                1. Implement strong password policy with minimum 12 characters
                2. Require combination of uppercase, lowercase, numbers, and special characters
                3. Implement rate limiting and account lockout mechanisms
                4. Use password strength meters during registration
                5. Implement multi-factor authentication (MFA)
                6. Regular password expiration and history checks
                7. Block common passwords and dictionary words
                ''',
                'test_payloads': [
                    '123456', 'password', 'qwerty', 'abc123', '12345678',
                    'welcome', 'admin', 'letmein', 'Password1', 'password123'
                ],
                'detection_patterns': [
                    'login successful', 'authenticated', 'welcome', 'dashboard',
                    'access granted', 'token', 'session'
                ]
            },
            {
                'name': 'sql_injection',
                'vulnerability_type': 'sql_injection',
                'title': 'SQL Injection Vulnerability',
                'description': '''
                The API is vulnerable to SQL injection attacks where malicious SQL code
                can be injected through user inputs, potentially allowing attackers to
                view, manipulate, or delete database information.
                ''',
                'impact': '''
                - Data breach and unauthorized data access
                - Database manipulation and data corruption
                - Authentication bypass
                - Remote code execution in some cases
                - Complete system compromise
                ''',
                'recommendation': '''
                1. Use parameterized queries and prepared statements
                2. Implement input validation and sanitization
                3. Use stored procedures where appropriate
                4. Apply principle of least privilege for database connections
                5. Regular security code reviews and testing
                6. Use Web Application Firewall (WAF)
                ''',
                'test_payloads': [
                    "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users --",
                    "admin'--", "' OR 1=1 --", "'; EXEC xp_cmdshell('dir'); --"
                ],
                'detection_patterns': [
                    'sql syntax error', 'mysql error', 'oracle error', 'database error',
                    'syntax error', 'unexpected token'
                ]
            },
            {
                'name': 'xss_vulnerability',
                'vulnerability_type': 'xss',
                'title': 'Cross-Site Scripting (XSS)',
                'description': '''
                The API or web interface is vulnerable to Cross-Site Scripting attacks
                where malicious scripts can be injected and executed in users' browsers.
                ''',
                'impact': '''
                - Session hijacking and account takeover
                - Malicious script execution in user browsers
                - Phishing attacks and credential theft
                - Website defacement
                - Malware distribution
                ''',
                'recommendation': '''
                1. Implement proper output encoding/escaping
                2. Use Content Security Policy (CSP) headers
                3. Input validation and sanitization
                4. Use secure templating engines
                5. Regular security testing and code reviews
                ''',
                'test_payloads': [
                    '<script>alert("XSS")</script>', 
                    '<img src=x onerror=alert("XSS")>',
                    '"><script>alert(document.cookie)</script>',
                    "';alert('XSS');//"
                ],
                'detection_patterns': [
                    'script', 'alert', 'onerror', 'onload', 'javascript:'
                ]
            },
            {
                'name': 'auth_bypass',
                'vulnerability_type': 'auth_bypass',
                'title': 'Authentication Bypass',
                'description': '''
                The API has flaws in authentication mechanisms that allow attackers
                to bypass login procedures and gain unauthorized access.
                ''',
                'impact': '''
                - Unauthorized access to protected resources
                - Account takeover
                - Data breach and privacy violations
                - Privilege escalation
                - System compromise
                ''',
                'recommendation': '''
                1. Implement robust authentication mechanisms
                2. Use secure session management
                3. Implement proper access controls
                4. Regular security audits of authentication logic
                5. Multi-factor authentication implementation
                ''',
                'test_payloads': [
                    '{"username":"admin","password":""}',
                    '{"username":"","password":""}',
                    '{"username":"admin\' --","password":"anything"}'
                ],
                'detection_patterns': [
                    'access granted', 'login successful', 'authenticated',
                    'authorized', 'welcome'
                ]
            },
            {
                'name': 'csrf_vulnerability',
                'vulnerability_type': 'csrf',
                'title': 'Cross-Site Request Forgery (CSRF)',
                'description': '''
                The API lacks proper CSRF protection, allowing attackers to perform
                unauthorized actions on behalf of authenticated users.
                ''',
                'impact': '''
                - Unauthorized actions performed on behalf of users
                - Account modifications without user consent
                - Financial transactions fraud
                - Data manipulation
                - Privilege abuse
                ''',
                'recommendation': '''
                1. Implement CSRF tokens for state-changing operations
                2. Use SameSite cookie attributes
                3. Verify referrer headers
                4. Implement proper CORS policies
                5. Use double-submit cookies pattern
                ''',
                'test_payloads': [],
                'detection_patterns': [
                    'action completed', 'updated successfully', 'changes saved'
                ]
            }
        ]

        for template_data in templates:
            template, created = VulnerabilityTemplateTC3.objects.get_or_create(
                name=template_data['name'],
                defaults=template_data
            )
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'Created template: {template.name}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'Template already exists: {template.name}')
                )
        
        self.stdout.write(
            self.style.SUCCESS('Successfully populated vulnerability templates')
        )