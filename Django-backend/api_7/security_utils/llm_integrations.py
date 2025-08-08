import json
import openai
import logging
from typing import Dict, Any, List
from abc import ABC, abstractmethod
from django.conf import settings

logger = logging.getLogger(__name__)

class BaseLLMProvider(ABC):
    """Base class for LLM providers."""
    @abstractmethod
    def analyze_ssrf(self, prompt: str) -> Dict[str, Any]:
        pass

class OpenAIProvider(BaseLLMProvider):
    """Integration with the official OpenAI API."""

    def __init__(self):
        self.api_key = getattr(settings, 'OPENAI_API_KEY', None)
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not set in Django settings.")
        self.client = openai.OpenAI(api_key=self.api_key)
        self.model = getattr(settings, 'OPENAI_MODEL', 'gpt-4o') # Default to a powerful model

    def analyze_ssrf(self, prompt: str) -> Dict[str, Any]:
        """Analyze SSRF using the OpenAI API."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in API security. Your task is to analyze potential SSRF vulnerabilities and provide a structured JSON response to guide automated testing."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=5000,  # Increased token limit for detailed analysis
                response_format={"type": "json_object"} # Enforce JSON output
            )
            
            llm_response_content = response.choices[0].message.content
            parsed_analysis = self._parse_llm_response(llm_response_content)

            return {
                "success": True,
                "provider": "openai",
                "model": self.model,
                "analysis": parsed_analysis,
                "raw_response": llm_response_content,
                "metadata": {"usage": response.usage}
            }

        except openai.APIError as e:
            logger.error(f"OpenAI API Error: {str(e)}")
            return {"success": False, "error": f"OpenAI API Error: {e.body.get('message', str(e))}", "provider": "openai"}
        except Exception as e:
            logger.error(f"An unexpected error occurred during OpenAI analysis: {str(e)}")
            return {"success": False, "error": str(e), "provider": "openai"}

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse the JSON response from the LLM."""
        try:
            # The response should be a valid JSON string as requested
            return json.loads(response)
        except json.JSONDecodeError:
            logger.error("Failed to parse JSON response from OpenAI.")
            return {"parse_error": "LLM did not return valid JSON.", "raw_analysis": response}

class LLMManager:
    """Manager to handle LLM providers."""
    def __init__(self):
        self.providers = {}
        self._initialize_providers()

    def _initialize_providers(self):
        """Initialize available LLM providers."""
        if hasattr(settings, 'OPENAI_API_KEY'): # This check runs only once
            try:
                self.providers['openai'] = OpenAIProvider()
                logger.info("OpenAI provider initialized successfully.") #
            except ValueError as e:
                logger.error(e)
        else:
            logger.warning("OPENAI_API_KEY not found in settings. OpenAI provider is disabled.")

    def analyze_ssrf(self, prompt: str, provider_name: str = 'openai') -> Dict[str, Any]:
        """Analyze SSRF using the specified or default provider."""
        provider = self.providers.get(provider_name)
        if provider:
            return provider.analyze_ssrf(prompt)
        
        return {
            "success": False,
            "error": "No valid LLM provider is configured. Please set OPENAI_API_KEY in your settings.",
        }

# Global instance
llm_manager = LLMManager()

def analyze_ssrf_with_llm(prompt: str, provider: str = 'openai') -> Dict[str, Any]:
    """Convenience function to analyze SSRF with an LLM."""
    return llm_manager.analyze_ssrf(prompt, provider)