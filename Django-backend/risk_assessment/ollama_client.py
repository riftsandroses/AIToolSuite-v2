import requests
import json
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor

# This module will handle Ollama API requests

class OllamaClient:
    def __init__(self, base_url="http://localhost:11434", model="mistral", max_workers=5):
        self.base_url = base_url
        self.model = model
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = threading.Semaphore(max_workers)
        
    def generate_response(self, prompt, temperature=0.7, max_tokens=1000):
        """Generate a response from Ollama with thread safety"""
        
        # Acquire semaphore to limit concurrent requests
        with self.semaphore:
            try:
                response = requests.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "temperature": temperature,
                        "max_tokens": max_tokens
                    },
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    # Parse streaming response 
                    full_response = ""
                    for line in response.text.splitlines():
                        if line:
                            try:
                                data = json.loads(line)
                                if "response" in data:
                                    full_response += data["response"]
                            except json.JSONDecodeError:
                                pass
                    
                    return full_response
                else:
                    return f"Error: Received status code {response.status_code} from Ollama API"
                    
            except Exception as e:
                return f"Error connecting to Ollama: {str(e)}"

# Create a singleton Ollama client
_ollama_client = None
_client_lock = threading.Lock()

def get_ollama_client():
    global _ollama_client
    with _client_lock:
        if _ollama_client is None:
            _ollama_client = OllamaClient()
    return _ollama_client

def get_application_description(prompt):
    """Get application description using Ollama"""
    client = get_ollama_client()
    
    # Submit the task to the thread pool
    future = client.executor.submit(client.generate_response, prompt)
    
    # Get the result (blocks until complete)
    result = future.result()
    
    # Clean up the response
    result = result.strip()
    
    return result