class TestCaseDefinitions:
    """Centralized test case definitions to avoid code duplication"""
    
    @staticmethod
    def get_test_case_definitions():
        """Define test cases for each API category"""
        return {
            'API1:2023': {
                'TC-1': 'Broken Object Level Authorization',
                'TC-2': 'Broken User Authentication',  
                'TC-3': 'Excessive Data Exposure',
                'TC-4': 'Lack of Resources & Rate Limiting',
                'TC-5': 'Broken Function Level Authorization',
                'TC-6': 'Mass Assignment',
                'TC-7': 'Security Misconfiguration'
            },
            'API2:2023': {
                'TC-1': 'Broken Authentication',
                'TC-2': 'Unrestricted Resource Consumption',
                'TC-3': 'Broken Object Property Level Authorization',
                'TC-4': 'Unrestricted Access to Sensitive Business Flows',
                'TC-5': 'Server Side Request Forgery',
                'TC-6': 'Security Misconfiguration',
                'TC-7': 'Improper Inventory Management'
            },
            'API3:2023': {
                'TC-1': 'Broken Object Property Level Authorization',
                'TC-2': 'Unrestricted Resource Consumption',
                'TC-3': 'Broken Authentication',
                'TC-4': 'Unrestricted Access to Sensitive Business Flows',
                'TC-5': 'Server Side Request Forgery',
                'TC-6': 'Security Misconfiguration',
                'TC-7': 'Improper Inventory Management'
            },
            'API4:2023': {
                'TC-1': 'Unbounded Pagination',
                'TC-2': 'No Rate Limiting',
                'TC-3': 'Unrestricted File Upload',
                'TC-4': 'Async Task Overload',
                'TC-5': 'Unthrottled File Download',
                'TC-6': 'Unbounded Session'
            },
            'API5:2023': {
                'TC-1': 'Broken Function Level Authorization',
                'TC-2': 'Unrestricted Resource Consumption',
                'TC-3': 'Broken Authentication',
                'TC-4': 'Broken Object Property Level Authorization',
                'TC-5': 'Unrestricted Access to Sensitive Business Flows',
                'TC-6': 'Server Side Request Forgery',
                'TC-7': 'Security Misconfiguration'
            },
            'API6:2023': {
                'TC-1': 'Unrestricted Access to Sensitive Business Flows',
                'TC-2': 'Broken Function Level Authorization',
                'TC-3': 'Unrestricted Resource Consumption',
                'TC-4': 'Broken Authentication',
                'TC-5': 'Broken Object Property Level Authorization',
                'TC-6': 'Server Side Request Forgery',
                'TC-7': 'Security Misconfiguration'
            },
            'API7:2023': {
                'TC-1': 'Server Side Request Forgery'
            },
            'API8:2023': {
                'TC-1': 'CORS Headers Misconfiguration',
                'TC-2': 'TLS & Security Headers Misconfiguration',
                'TC-3': 'Excessive Debug Information'
            },
            'API9:2023': {
                'TC-1': 'Unlisted Endpoints',
                'TC-2': 'Access Staging/Dev Environments',
                'TC-3': 'API Documentation Exposure',
                'TC-4': 'Verb Tunneling',
                'TC-5': 'Version Enumeration of APIs',
                'TC-6': 'Monitoring/Health Endpoints',
                'TC-7': 'Admin APIs'
            },
            'Custom Testing': {
                'TC-1': 'SQL Injection Attacks'
            }
        }
    
    @staticmethod
    def get_category_descriptions():
        """Define descriptions for each API category"""
        return {
            'API1:2023': 'API Security Top 10 2023 - First Category: Object Level Authorization',
            'API2:2023': 'API Security Top 10 2023 - Second Category: Authentication & Resource Control',
            'API3:2023': 'API Security Top 10 2023 - Third Category: Property Level Authorization',
            'API4:2023': 'API Security Top 10 2023 - Fourth Category: Resource Consumption & Access Control',
            'API5:2023': 'API Security Top 10 2023 - Fifth Category: Function Level Authorization',
            'API6:2023': 'API Security Top 10 2023 - Sixth Category: Business Flow & Access Control',
            'API7:2023': 'API Security Top 10 2023 - Seventh Category: Server Side Request Forgery',
            'API8:2023': 'API Security Top 10 2023 - Eighth Category: Security Misconfiguration',
            'API9:2023': 'API Security Top 10 2023 - Ninth Category: Improper Inventory Management',
            'Custom Testing': 'Custom security testing scenarios defined by the user'
        }
    
    @staticmethod
    def get_valid_categories():
        """Get list of valid API categories"""
        return [
            'API1:2023', 'API2:2023', 'API3:2023', 'API4:2023', 'API5:2023',
            'API6:2023', 'API7:2023', 'API8:2023', 'API9:2023', 'Custom Testing'
        ]
    
    @classmethod
    def get_valid_test_cases_for_category(cls, category):
        """Get valid test cases for a specific category"""
        test_case_definitions = cls.get_test_case_definitions()
        test_cases = test_case_definitions.get(category, {})
        return [f"{tc_code}: {tc_name}" for tc_code, tc_name in test_cases.items()]
    
    @classmethod
    def get_all_test_case_names(cls):
        """Get all unique test case names across all categories"""
        test_case_definitions = cls.get_test_case_definitions()
        all_test_cases = set()
        
        for category_tests in test_case_definitions.values():
            for tc_code, tc_name in category_tests.items():
                all_test_cases.add(f"{tc_code}: {tc_name}")
        
        return list(all_test_cases)
    
    @classmethod
    def validate_category(cls, category):
        """Validate if category is valid"""
        return category in cls.get_valid_categories()
    
    @classmethod
    def validate_test_case_for_category(cls, category, test_case):
        """Validate if test case is valid for given category"""
        valid_test_cases = cls.get_valid_test_cases_for_category(category)
        return test_case in valid_test_cases