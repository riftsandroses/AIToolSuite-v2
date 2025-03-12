from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth.models import User
from .models import ProbeControlMapping

class ProbeControlMappingTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser', password='testpassword'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        
        # Create test mapping
        self.mapping = ProbeControlMapping.objects.create(
            probe_name='test.Probe',
            control_title='Test Control',
            control_description='Description',
            control_observation='Observation',
            control_impact='Impact',
            control_recommendation='Recommendation'
        )
    
    def test_get_mappings(self):
        url = reverse('probecontrolmapping-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['probe_name'], 'test.Probe')