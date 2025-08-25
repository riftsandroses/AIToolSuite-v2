# utils/ai_generator.py
import json
import random
import string
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from openai import OpenAI
from django.conf import settings


class AIPayloadGeneratorTC1:
    """AI-powered payload generator for vulnerability testing"""
    
    def __init__(self):
        # Initialize OpenAI client
        if hasattr(settings, 'OPENAI_API_KEY'):
            self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        else:
            # Use environment variable or set to None for fallback
            self.client = None
    
    async def generate_signup_payloads(self, base_payload: Dict, count: int = 5) -> List[Dict]:
        """Generate realistic signup payloads using GPT"""
        if not self.client:
            return []
        
        try:
            prompt = self._create_signup_prompt(base_payload, count)
            
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a security testing assistant that generates realistic but fake user registration payloads for API vulnerability testing. Always return valid JSON arrays."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.7
            )
            
            content = response.choices[0].message.content.strip()
            
            # Parse the JSON response
            if content.startswith('```json'):
                content = content.replace('```json', '').replace('```', '').strip()
            
            payloads = json.loads(content)
            
            # Validate and enhance payloads
            validated_payloads = []
            for payload in payloads[:count]:
                if isinstance(payload, dict):
                    enhanced = self._enhance_payload(payload, base_payload)
                    validated_payloads.append(enhanced)
            
            return validated_payloads
            
        except Exception as e:
            print(f"AI payload generation failed: {e}")
            return []
    
    def _create_signup_prompt(self, base_payload: Dict, count: int) -> str:
        """Create prompt for signup payload generation"""
        return f"""
Generate {count} realistic but fake user registration payloads for API security testing.
Base payload structure: {json.dumps(base_payload, indent=2)}

Requirements:
1. Generate diverse, realistic user data
2. Use various email providers and domains
3. Include different name patterns (first/last, full names, etc.)
4. Use strong password patterns but vary them
5. Include realistic phone numbers with different country codes
6. Add variety in optional fields if present
7. Ensure all required fields from base payload are included
8. Return as a valid JSON array

Focus on creating payloads that would bypass basic validation but are still realistic user registrations.
Do not include any malicious or harmful content.

Return only the JSON array of payloads, no additional text.
"""
    
    def _enhance_payload(self, ai_payload: Dict, base_payload: Dict) -> Dict:
        """Enhance AI-generated payload with additional security testing elements"""
        enhanced = ai_payload.copy()
        
        # Ensure all base fields are present
        for key in base_payload.keys():
            if key not in enhanced:
                enhanced[key] = base_payload[key]
        
        # Add timestamp for uniqueness
        timestamp = str(int(datetime.now().timestamp()))
        
        # Enhance email with timestamp if present
        if 'email' in enhanced and '@' in str(enhanced['email']):
            email_parts = enhanced['email'].split('@')
            enhanced['email'] = f"{email_parts[0]}{timestamp}@{email_parts[1]}"
        
        # Enhance username with timestamp if present
        if 'username' in enhanced:
            enhanced['username'] = f"{enhanced['username']}{timestamp[-4:]}"
        
        return enhanced