# File: methodologies/llm_callers.py

import json
import re
from openai import OpenAI

# --- Main Service Function ---

def generate_json_response(provider, api_key, model_name, system_prompt, user_prompt):
    """
    Calls the specified LLM provider to generate a JSON response.
    """
    if provider == 'openai':
        # Always call with json_mode=True
        raw_response = _call_openai(api_key, model_name, system_prompt, user_prompt, json_mode=True)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")

    # --- JSON Repair Pass ---
    try:
        return json.loads(raw_response)
    except json.JSONDecodeError:
        repaired_json = _repair_json(raw_response)
        if repaired_json:
            return repaired_json
        else:
            raise ValueError("LLM returned invalid JSON that could not be repaired.")

def generate_text_response(provider, api_key, model_name, system_prompt, user_prompt):
    """
    Calls the specified LLM provider to generate a raw text response.
    Needed for non-JSON outputs like Mermaid code.
    """
    if provider == 'openai':
        # Always call with json_mode=False
        raw_response = _call_openai(api_key, model_name, system_prompt, user_prompt, json_mode=False)
        
        # Clean up markdown code blocks if they exist (e.g., for Mermaid)
        match = re.search(r'```mermaid\s*([\s\S]*?)\s*```', raw_response, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        match = re.search(r'```.*\s*([\s\S]*?)\s*```', raw_response, re.DOTALL)
        if match:
            return match.group(1).strip()
            
        return raw_response.strip()
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")

# --- Provider-Specific Implementations ---

def _call_openai(api_key, model_name, system_prompt, user_prompt, json_mode=False):
    """Handles the API call to OpenAI."""
    client = OpenAI(api_key=api_key)

    # Conditionally set the response format based on the json_mode flag
    request_params = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "max_tokens": 6000, # Note: Parameter is max_tokens not max_completion_tokens
        "temperature": 0.3
    }
    
    if json_mode:
        request_params["response_format"] = {"type": "json_object"}

    response = client.chat.completions.create(**request_params)
    
    return response.choices[0].message.content


# --- Utility Functions ---

def _repair_json(bad_json_string):
    """
    Enhanced JSON repair function that handles multiple common formatting issues.
    """
    # First try to extract from markdown code blocks
    json_pattern = r'```json\s*([\s\S]*?)\s*```'
    match = re.search(json_pattern, bad_json_string, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        # Try generic code blocks
        code_pattern = r'```\s*([\s\S]*?)\s*```'
        match = re.search(code_pattern, bad_json_string, re.DOTALL)
        if match:
            json_str = match.group(1)
        else:
            json_str = bad_json_string
    
    # Common JSON repair attempts
    repairs = [
        # Original string
        json_str,
        # Remove trailing commas
        re.sub(r',(\s*[}\]])', r'\1', json_str),
        # Fix single quotes to double quotes
        re.sub(r"'([^']*)':", r'"\1":', json_str),
        # Add missing closing brackets
        json_str + '}',
        json_str + ']',
        json_str + '}]',
        # Remove potential prefix text
        re.sub(r'^[^{[]*([{[].*)', r'\1', json_str, flags=re.DOTALL),
        # Remove potential suffix text  
        re.sub(r'([}\]]).*$', r'\1', json_str, flags=re.DOTALL)
    ]
    
    # Try each repair attempt
    for repair_attempt in repairs:
        try:
            return json.loads(repair_attempt.strip())
        except (json.JSONDecodeError, ValueError):
            continue
    
    # If all repairs fail, try a more aggressive approach
    # Look for JSON-like structures
    json_like_pattern = r'(\{.*\}|\[.*\])'
    match = re.search(json_like_pattern, bad_json_string, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    
    return None