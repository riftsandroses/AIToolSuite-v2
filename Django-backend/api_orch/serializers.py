# api_orch/serializers.py
import json
import re
from rest_framework import serializers
from .models import Scan, PostmanAPI, TestCaseSelection

class PostmanAPISerializer(serializers.ModelSerializer):
    class Meta:
        model = PostmanAPI
        fields = ['id', 'name', 'method', 'url', 'headers', 'body', 
                 'authorization', 'query_params', 'folder_path', 
                 'pre_request_script', 'test_script',
                 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class ScanSerializer(serializers.ModelSerializer):
    postman_apis = PostmanAPISerializer(many=True, read_only=True)
    
    class Meta:
        model = Scan
        fields = ['id', 'scan_name', 'description', 'client_name', 
                 'client_app_name', 'username', 'password', 
                 'postman_collection_file', 'postman_apis', 
                 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        scan = super().create(validated_data)
        
        # Parse Postman collection file after the scan is saved
        if scan.postman_collection_file:
            try:
                self._parse_postman_collection(scan)
            except Exception as e:
                # Log the error for debugging
                print(f"Error parsing Postman collection: {str(e)}")
                raise serializers.ValidationError(f"Error parsing Postman collection: {str(e)}")
        
        return scan
    
    def _parse_postman_collection(self, scan):
        """Parse Postman collection file and create PostmanAPI objects"""
        try:
            # Open the file and read its content
            with scan.postman_collection_file.open('r') as file:
                collection_data = json.load(file)
            
            # Handle nested collection structure
            if 'collection' in collection_data:
                collection = collection_data['collection']
            else:
                collection = collection_data
            
            # Extract items from collection
            items = collection.get('item', [])
            if not items:
                print("No items found in Postman collection")
                return
            
            # Parse the items
            self._parse_items(items, scan)
            print(f"Successfully parsed {scan.postman_apis.count()} APIs from collection")
            
        except json.JSONDecodeError as e:
            raise serializers.ValidationError(f"Invalid JSON in Postman collection file: {str(e)}")
        except KeyError as e:
            raise serializers.ValidationError(f"Missing required field in Postman collection: {str(e)}")
        except Exception as e:
            raise serializers.ValidationError(f"Error reading Postman collection file: {str(e)}")
    
    def _parse_items(self, items, scan, folder_path=""):
        """Recursively parse items from Postman collection"""
        for item in items:
            if 'item' in item:  # This is a folder
                folder_name = item.get('name', '')
                new_folder_path = f"{folder_path}/{folder_name}" if folder_path else folder_name
                self._parse_items(item['item'], scan, new_folder_path)
            else:  # This is a request
                self._create_postman_api(item, scan, folder_path)
    
    def _extract_scripts(self, item):
        """Extract pre-request and test scripts from item"""
        pre_request_script = ""
        test_script = ""
        
        events = item.get('event', [])
        for event in events:
            if event.get('listen') == 'prerequest':
                script = event.get('script', {})
                if 'exec' in script:
                    pre_request_script = '\n'.join(script['exec'])
            elif event.get('listen') == 'test':
                script = event.get('script', {})
                if 'exec' in script:
                    test_script = '\n'.join(script['exec'])
        
        return pre_request_script, test_script
    
    def _normalize_url(self, url):
        """Normalize URL format and handle Postman variables"""
        if isinstance(url, dict):
            # Handle object format URL
            url_raw = url.get('raw', '')
            if not url_raw:
                # Try to construct from parts
                host = url.get('host', [])
                path = url.get('path', [])
                protocol = url.get('protocol', 'https')
                
                if host:
                    if isinstance(host, list):
                        host_str = '.'.join(host)
                    else:
                        host_str = str(host)
                    
                    if path:
                        if isinstance(path, list):
                            path_str = '/' + '/'.join(path)
                        else:
                            path_str = str(path)
                    else:
                        path_str = ''
                    
                    url_raw = f"{protocol}://{host_str}{path_str}"
            
            return url_raw
        else:
            return str(url)
    
    def _extract_query_params(self, url):
        """Extract query parameters from URL object"""
        query_params = {}
        
        if isinstance(url, dict) and 'query' in url:
            for param in url['query']:
                if not param.get('disabled', False):
                    key = param.get('key', '')
                    value = param.get('value', '')
                    if key:  # Only add if key is not empty
                        query_params[key] = value
        
        return query_params
    
    def _create_postman_api(self, item, scan, folder_path):
        """Create PostmanAPI object from parsed item"""
        try:
            request = item.get('request', {})
            
            # Extract method
            method = request.get('method', 'GET')
            
            # Extract and normalize URL
            url = request.get('url', {})
            url_raw = self._normalize_url(url)
            
            # Skip if URL is empty
            if not url_raw:
                print(f"Skipping API '{item.get('name', 'Unnamed')}' - no URL found")
                return
            
            # Extract headers
            headers = {}
            for header in request.get('header', []):
                if not header.get('disabled', False):
                    key = header.get('key', '')
                    value = header.get('value', '')
                    if key:  # Only add if key is not empty
                        headers[key] = value
            
            # Extract body
            body = {}
            request_body = request.get('body', {})
            if request_body:
                body_mode = request_body.get('mode', '')
                if body_mode == 'raw':
                    body['raw'] = request_body.get('raw', '')
                    body['mode'] = 'raw'
                elif body_mode == 'formdata':
                    body['formdata'] = request_body.get('formdata', [])
                    body['mode'] = 'formdata'
                elif body_mode == 'urlencoded':
                    body['urlencoded'] = request_body.get('urlencoded', [])
                    body['mode'] = 'urlencoded'
                elif body_mode == 'file':
                    body['file'] = request_body.get('file', {})
                    body['mode'] = 'file'
                elif body_mode == 'binary':
                    body['binary'] = request_body.get('binary', {})
                    body['mode'] = 'binary'
            
            # Extract authorization
            authorization = {}
            auth = request.get('auth', {})
            if auth:
                auth_type = auth.get('type', '')
                authorization['type'] = auth_type
                if auth_type in auth:
                    authorization[auth_type] = auth[auth_type]
            
            # Extract query parameters
            query_params = self._extract_query_params(url)
            
            # Extract scripts
            pre_request_script, test_script = self._extract_scripts(item)
            
            # Create the PostmanAPI object
            postman_api = PostmanAPI.objects.create(
                scan=scan,
                name=item.get('name', 'Unnamed Request'),
                method=method,
                url=url_raw,
                headers=headers,
                body=body,
                authorization=authorization,
                query_params=query_params,
                folder_path=folder_path,
                pre_request_script=pre_request_script,
                test_script=test_script
            )
            
            print(f"Created API: {postman_api.method} {postman_api.name}")
            
        except Exception as e:
            print(f"Error creating PostmanAPI for '{item.get('name', 'Unknown')}': {str(e)}")
            # Continue processing other items instead of failing completely
            pass


class ScanListSerializer(serializers.ModelSerializer):
    postman_apis_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = ['id', 'scan_name', 'description', 'client_name', 
                 'client_app_name', 'postman_apis_count', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_postman_apis_count(self, obj):
        return obj.postman_apis.count()


class ScanUpdateSerializer(ScanSerializer):
    class Meta:
        model = Scan
        fields = ['id', 'scan_name', 'description', 'client_name', 
                 'client_app_name', 'username', 'password', 
                 'postman_collection_file', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def update(self, instance, validated_data):
        # If new postman collection file is uploaded, reparse it
        if 'postman_collection_file' in validated_data:
            # Delete existing PostmanAPI objects
            instance.postman_apis.all().delete()
            
            # Update the instance
            instance = super().update(instance, validated_data)
            
            # Parse new collection file
            if instance.postman_collection_file:
                try:
                    self._parse_postman_collection(instance)
                except Exception as e:
                    print(f"Error parsing updated Postman collection: {str(e)}")
                    raise serializers.ValidationError(f"Error parsing Postman collection: {str(e)}")
        else:
            instance = super().update(instance, validated_data)
        
        return instance

class TestCaseSelectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestCaseSelection
        fields = ['id', 'api_category', 'test_case', 'name', 'description', 'is_active']


class ScanTestCaseSelectionSerializer(serializers.Serializer):
    """Serializer for updating test case selections for a scan"""
    
    VALID_API_CATEGORIES = [
        'API1:2023', 'API2:2023', 'API3:2023', 'API4:2023', 'API5:2023',
        'API6:2023', 'API7:2023', 'API8:2023', 'API9:2023'
    ]
    
    VALID_TEST_CASES = [
        'TC-1: Unlisted Endpoints',
        'TC-2: Access Staging/Dev Environments', 
        'TC-3: API Documentation Exposure',
        'TC-4: Verb Tunneling',
        'TC-5: Version Enumeration of APIs',
        'TC-6: Monitoring/Health Endpoints',
        'TC-7: Admin APIs'
    ]
    
    selected_categories = serializers.ListField(
        child=serializers.CharField(max_length=50),
        required=False,
        allow_empty=True,
        help_text="List of API categories to select (e.g., ['API1:2023', 'API2:2023'])"
    )
    
    category_test_cases = serializers.DictField(
        child=serializers.ListField(
            child=serializers.CharField(max_length=100)
        ),
        required=False,
        allow_empty=True,
        help_text="Dictionary mapping API categories to their selected test cases"
    )
    
    def validate_selected_categories(self, value):
        """Validate that all selected categories are valid"""
        if not value:
            return value
            
        invalid_categories = [cat for cat in value if cat not in self.VALID_API_CATEGORIES]
        if invalid_categories:
            raise serializers.ValidationError(
                f"Invalid API categories: {invalid_categories}. "
                f"Valid categories are: {self.VALID_API_CATEGORIES}"
            )
        return value
    
    def validate_category_test_cases(self, value):
        """Validate that all test cases are valid for their categories"""
        if not value:
            return value
            
        for category, test_cases in value.items():
            if category not in self.VALID_API_CATEGORIES:
                raise serializers.ValidationError(
                    f"Invalid API category: {category}. "
                    f"Valid categories are: {self.VALID_API_CATEGORIES}"
                )
            
            invalid_test_cases = [tc for tc in test_cases if tc not in self.VALID_TEST_CASES]
            if invalid_test_cases:
                raise serializers.ValidationError(
                    f"Invalid test cases for {category}: {invalid_test_cases}. "
                    f"Valid test cases are: {self.VALID_TEST_CASES}"
                )
        
        return value
    
    def validate(self, attrs):
        """Cross-field validation"""
        selected_categories = attrs.get('selected_categories', [])
        category_test_cases = attrs.get('category_test_cases', {})
        
        # If category_test_cases is provided, ensure all keys are in selected_categories
        if category_test_cases:
            for category in category_test_cases.keys():
                if category not in selected_categories:
                    raise serializers.ValidationError(
                        f"Category '{category}' in category_test_cases must also be in selected_categories"
                    )
        
        return attrs


class ScanTestCaseUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating scan with test case selections"""
    
    class Meta:
        model = Scan
        fields = ['id', 'scan_name', 'test_case_selections', 'updated_at']
        read_only_fields = ['id', 'scan_name', 'updated_at']
    
    def validate_test_case_selections(self, value):
        """Validate the test case selections JSON structure"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("test_case_selections must be a dictionary")
        
        valid_categories = [
            'API1:2023', 'API2:2023', 'API3:2023', 'API4:2023', 'API5:2023',
            'API6:2023', 'API7:2023', 'API8:2023', 'API9:2023'
        ]
        
        valid_test_cases = [
            'TC-1: Unlisted Endpoints',
            'TC-2: Access Staging/Dev Environments', 
            'TC-3: API Documentation Exposure',
            'TC-4: Verb Tunneling',
            'TC-5: Version Enumeration of APIs',
            'TC-6: Monitoring/Health Endpoints',
            'TC-7: Admin APIs'
        ]
        
        for category, test_cases in value.items():
            if category not in valid_categories:
                raise serializers.ValidationError(f"Invalid API category: {category}")
            
            if not isinstance(test_cases, list):
                raise serializers.ValidationError(f"Test cases for {category} must be a list")
            
            for test_case in test_cases:
                if test_case not in valid_test_cases:
                    raise serializers.ValidationError(f"Invalid test case: {test_case}")
        
        return value