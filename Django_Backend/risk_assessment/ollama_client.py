import requests
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from django.conf import settings # Import Django settings to get the API key

# This module will handle OpenAI API requests

class OpenAIClient:
    def __init__(self, model="gpt-4.1", max_workers=5):
        self.base_url = "https://api.openai.com/v1"
        self.api_key = settings.OPENAI_API_KEY
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not found in settings. Please set it.")
            
        self.model = model
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = threading.Semaphore(max_workers)
        
    def generate_response(self, prompt, temperature=0.7, max_tokens=1000):
        """Generate a response from OpenAI with thread safety"""
        
        # Acquire semaphore to limit concurrent requests
        with self.semaphore:
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                # OpenAI uses a different payload structure (messages array)
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": temperature,
                    "max_tokens": max_tokens
                }

                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    # The response content is nested differently in OpenAI's API
                    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    return content.strip()
                else:
                    return f"Error: Received status code {response.status_code} from OpenAI API: {response.text}"
                    
            except Exception as e:
                return f"Error connecting to OpenAI: {str(e)}"

# Create a singleton OpenAI client
_openai_client = None
_client_lock = threading.Lock()

def get_openai_client():
    global _openai_client
    with _client_lock:
        if _openai_client is None:
            _openai_client = OpenAIClient()
    return _openai_client

def get_application_description(prompt):
    """Get application description using OpenAI"""
    client = get_openai_client()
    
    # Submit the task to the thread pool
    future = client.executor.submit(client.generate_response, prompt)
    
    # Get the result (blocks until complete)
    result = future.result()
    
    # The result from OpenAI client is already cleaned up
    return result