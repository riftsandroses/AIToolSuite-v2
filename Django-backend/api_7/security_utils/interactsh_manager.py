import json
import time
import threading
import subprocess
import logging
import select
import os
import re
from queue import Queue, Empty
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

class InteractshManager:
    """
    Enhanced Interactsh manager with robust interaction detection and improved domain extraction
    """
    
    def __init__(self, domain: str = None, custom_server: str = None):
        self.domain = domain
        self.custom_server = custom_server
        self.process = None
        self.output_queue = Queue()
        self.reader_thread = None
        self.is_running = False
        self.interactions_cache = []
        self.domain_extracted = threading.Event()  # Event to signal domain extraction
        
    def start_client(self, max_retries: int = 3) -> bool:
        """Start interactsh-client subprocess with improved domain detection"""
        for attempt in range(max_retries):
            try:
                logger.info(f"Starting interactsh-client (attempt {attempt + 1}/{max_retries})")
                
                # Build command
                cmd = ['interactsh-client', '-json']  # Use JSON output for better parsing
                if self.custom_server:
                    cmd.extend(['-s', self.custom_server])
                elif self.domain:
                    cmd.extend(['-s', self.domain])

                logger.info(f"Command: {' '.join(cmd)}")

                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # ⬅ merge stderr into stdout so reader thread sees it
                    text=True,
                    bufsize=0,
                    universal_newlines=True
                )

                
                # Start background thread to read output
                self.is_running = True
                self.domain_extracted.clear()
                
                self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
                self.reader_thread.start()
                
                # Wait for process to start and domain to be extracted
                start_time = time.time()
                process_check_timeout = 15.0
                
                while time.time() - start_time < process_check_timeout:
                    if self.process.poll() is not None:
                        # Process died
                        logger.error(f"Interactsh client process died early (exit code: {self.process.returncode})")
                        self._cleanup_attempt()
                        break
                    
                    # Check if we got domain
                    if self.domain_extracted.wait(timeout=0.5):
                        logger.info(f"Successfully started interactsh client with domain: {self.domain}")
                        return True
                    
                    time.sleep(0.1)
                
                # If we're here, either process died or no domain was extracted
                if self.process and self.process.poll() is None:
                    logger.error("Process is running but no domain extracted within timeout")
                    self._cleanup_attempt()
                else:
                    logger.error("Process failed to start or died early")
                
            except FileNotFoundError:
                logger.error("interactsh-client not found. Make sure it is installed and in PATH")
                return False
            except Exception as e:
                logger.error(f"Failed to start interactsh client (attempt {attempt + 1}): {e}")
                self._cleanup_attempt()
            
            # Wait before retry
            if attempt < max_retries - 1:
                wait_time = 2 * (attempt + 1)  # Progressive backoff
                logger.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
        
        logger.error(f"Failed to start interactsh client after {max_retries} attempts")
        return False
    
    def _cleanup_attempt(self):
        """Cleanup failed attempt"""
        self.is_running = False
        if self.process:
            try:
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait()
            except Exception as e:
                logger.debug(f"Error during cleanup: {e}")
            finally:
                self.process = None
        
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=1)
    
    def _read_output(self):
        """Background thread to continuously read combined stdout/stderr"""
        logger.debug("Starting output reader thread")
        
        while self.is_running and self.process and self.process.poll() is None:
            try:
                # Use a simple readline approach for better compatibility
                line = self.process.stdout.readline()
                if line:
                    line = line.strip()
                    if line:  # Only process non-empty lines
                        logger.debug(f"Raw interactsh output: {line}")  # Add debug logging
                        self.output_queue.put(line)
                        self._try_extract_domain(line)
                else:
                    # If no line, sleep briefly to avoid busy waiting
                    time.sleep(0.1)
                            
            except Exception as e:
                logger.error(f"Error in output reader: {e}")
                break
        
        logger.debug("Output reader thread finished")
    
    def _try_extract_domain(self, line: str):
        """Try to extract domain from a line and signal if successful"""
        if self.domain:  # Already have domain
            return
            
        domain = self._extract_domain_from_line(line)
        if domain:
            self.domain = domain
            logger.info(f"Successfully extracted domain: {domain}")
            self.domain_extracted.set()  # Signal that domain was found
    
    def get_domain_url(self, timeout: int = 30) -> Optional[str]:  # Increased from 20 to 30
        """Get the interactsh domain URL with improved extraction and timeout"""
        if self.domain:
            return self.domain
            
        logger.info(f"Waiting for interactsh domain extraction (timeout: {timeout}s)")
        
        # Wait for domain extraction event
        if self.domain_extracted.wait(timeout=timeout):
            return self.domain
        
        # If event-based approach failed, try manual extraction from queue
        logger.warning("Event-based domain extraction failed, trying manual extraction")
        return self._manual_domain_extraction(timeout=10)  # Increased from 5 to 10
    
    def _manual_domain_extraction(self, timeout: int = 5) -> Optional[str]:
        """Manual domain extraction as fallback"""
        start_time = time.time()
        processed_lines = []
        
        while time.time() - start_time < timeout:
            try:
                line = self.output_queue.get(timeout=0.5)
                processed_lines.append(line)
                
                domain = self._extract_domain_from_line(line)
                if domain:
                    self.domain = domain
                    logger.info(f"Manual extraction successful: {domain}")
                    return domain
                        
            except Empty:
                continue
            except Exception as e:
                logger.debug(f"Error in manual extraction: {e}")
                continue
        
        # Debug output
        logger.error("Manual domain extraction failed")
        self._debug_extraction_failure(processed_lines)
        return None
    
    def _extract_domain_from_line(self, line: str) -> Optional[str]:
        """Extract domain using comprehensive patterns from Interactsh client output."""
        if not line or not line.strip():
            return None

        # Clean up leading/trailing spaces
        line_clean = line.strip()

        # Strip ProjectDiscovery log prefixes like [INF], [ERR], [WRN]
        if line_clean.startswith("[INF]") or line_clean.startswith("[ERR]") or line_clean.startswith("[WRN]"):
            parts = line_clean.split(maxsplit=1)
            if len(parts) == 2:
                line_clean = parts[1].strip()

        logger.debug(f"Trying to extract domain from: {line_clean}")

        # --- Strategy 1: JSON parsing ---
        try:
            if line_clean.startswith('{') and line_clean.endswith('}'):
                data = json.loads(line_clean)
                if isinstance(data, dict):
                    for key in ['domain', 'host', 'server', 'url', 'hostname']:
                        if key in data:
                            value = str(data[key]).lower().strip()
                            if self._is_valid_domain(value):
                                logger.debug(f"Found domain in JSON key '{key}': {value}")
                                return value
        except (json.JSONDecodeError, ValueError):
            pass

        # --- Strategy 2: Regex patterns for known OOB domains ---
        domain_patterns = [
            r'([a-zA-Z0-9]{6,}\.interact\.sh)',
            r'([a-zA-Z0-9]{6,}\.oast\.pro)',
            r'([a-zA-Z0-9]{6,}\.oast\.live)',
            r'([a-zA-Z0-9]{6,}\.oast\.site)',
            r'([a-zA-Z0-9]{6,}\.oast\.online)',
            r'([a-zA-Z0-9]{6,}\.oast\.fun)',
            r'([a-zA-Z0-9-]{4,}\.(?:interact\.sh|oast\.(?:pro|live|site|online|fun)))',
        ]

        for pattern in domain_patterns:
            matches = re.findall(pattern, line_clean, re.IGNORECASE)
            if matches:
                domain = matches[0].lower()
                logger.debug(f"Found domain with pattern '{pattern}': {domain}")
                return domain

        # --- Strategy 3: Context-based extraction ---
        if any(phrase in line_clean.lower() for phrase in ['listening', 'started', 'server', 'using domain']):
            words = re.split(r'[\s\[\](){},"\']+', line_clean)
            for word in words:
                if word and self._is_valid_domain(word.lower()):
                    logger.debug(f"Found domain via context extraction: {word.lower()}")
                    return word.lower()

        return None


    def _is_valid_domain(self, domain: str) -> bool:
        """Validate if a string looks like a valid interactsh domain"""
        if not domain or len(domain) < 10:
            return False
        
        # Must contain valid TLDs for interactsh services
        valid_tlds = ['.interact.sh', '.oast.pro', '.oast.live', '.oast.site', '.oast.online', '.oast.fun']
        if not any(tld in domain for tld in valid_tlds):
            return False
        
        # Must not contain unwanted characters
        if any(char in domain for char in [' ', '\t', '\n', '\r', '"', "'", '(', ')', '[', ']']):
            return False
        
        # Should have reasonable length
        if len(domain) > 100:
            return False
        
        # Basic domain format check
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        return True
    
    def _debug_extraction_failure(self, processed_lines: List[str]):
        """Debug function to analyze extraction failure"""
        logger.warning("=== Domain Extraction Debug Info ===")
        logger.warning(f"Process status: {self.process.poll() if self.process else 'No process'}")
        logger.warning(f"Total lines processed: {len(processed_lines)}")
        
        if processed_lines:
            logger.warning("Recent output lines:")
            for i, line in enumerate(processed_lines[-10:], 1):  # Last 10 lines
                logger.warning(f"  {i}: {repr(line)}")
        else:
            logger.warning("No output received from interactsh-client")
        
        # Check if process is still running
        if self.process:
            try:
                stdout, stderr = self.process.communicate(timeout=1)
                if stdout:
                    logger.warning(f"Final stdout: {repr(stdout)}")
                if stderr:
                    logger.warning(f"Final stderr: {repr(stderr)}")
            except subprocess.TimeoutExpired:
                logger.warning("Process still running")
            except Exception as e:
                logger.warning(f"Error checking final output: {e}")
        
        logger.warning("=== End Debug Info ===")
    
    def wait_for_interactions(self, expected_subdomain: str, timeout: int = 10) -> List[Dict]:
        """Wait specifically for interactions with expected subdomain"""
        interactions = []
        end_time = time.time() + timeout
        
        logger.info(f"Waiting for interactions with subdomain: {expected_subdomain}")
        
        while time.time() < end_time:
            try:
                line = self.output_queue.get(timeout=0.5)
                
                if not line.strip():
                    continue
                
                # Try to parse as interaction
                interaction_data = self._parse_interaction_line(line)
                if interaction_data and self._matches_expected_subdomain(interaction_data, expected_subdomain):
                    interactions.append(interaction_data)
                    self.interactions_cache.append(interaction_data)
                    logger.info(f"Found matching interaction for {expected_subdomain}")
                    break  # Found what we're looking for
                
            except Empty:
                continue
            except Exception as e:
                logger.debug(f"Error processing interaction line: {e}")
                continue
        
        return interactions
    
    def _parse_interaction_line(self, line: str) -> Optional[Dict]:
        """Parse interaction line with multiple format support"""
        try:
            # Try JSON parsing first
            data = json.loads(line)
            
            # Standard interactsh JSON format
            if isinstance(data, dict) and ('protocol' in data or 'full-id' in data):
                return {
                    'type': 'json',
                    'protocol': data.get('protocol', 'unknown'),
                    'full_id': data.get('full-id', ''),
                    'raw_request': data.get('raw-request', ''),
                    'remote_address': data.get('remote-address', ''),
                    'timestamp': data.get('timestamp', ''),
                    'unique_id': data.get('unique-id', ''),
                    'raw_data': data
                }
            
        except json.JSONDecodeError:
            # Handle non-JSON format
            if any(indicator in line.lower() for indicator in ['http', 'dns', 'interaction', 'received', 'request']):
                return self._parse_text_interaction(line)
        
        return None
    
    def _parse_text_interaction(self, line: str) -> Optional[Dict]:
        """Parse text-based interaction format"""
        line_lower = line.lower()
        
        # Common patterns in interactsh output
        if ('http' in line_lower or 'dns' in line_lower) and any(word in line_lower for word in ['received', 'request', 'query', 'lookup', 'interaction']):
            return {
                'type': 'text',
                'protocol': 'http' if 'http' in line_lower else 'dns',
                'raw_line': line,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'detected_from': 'text_parsing'
            }
        
        return None
    
    def _matches_expected_subdomain(self, interaction: Dict, expected_subdomain: str) -> bool:
        """Check if interaction matches expected subdomain"""
        
        # For JSON format
        if interaction.get('type') == 'json':
            fields_to_check = [
                interaction.get('full_id', ''),
                interaction.get('unique_id', ''),
                interaction.get('raw_request', ''),
                str(interaction.get('raw_data', ''))
            ]
            
            return any(expected_subdomain in field for field in fields_to_check)
        
        # For text format
        elif interaction.get('type') == 'text':
            raw_line = interaction.get('raw_line', '')
            return expected_subdomain in raw_line
        
        return False
    
    def stop_client(self):
        """Stop the interactsh client"""
        logger.info("Stopping interactsh client...")
        self.is_running = False
        
        if self.process:
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    logger.warning("Process didn't terminate gracefully, killing it")
                    self.process.kill()
                    self.process.wait()
                self.process = None
                logger.info("Interactsh process terminated")
            except Exception as e:
                logger.error(f"Error stopping interactsh process: {e}")
        
        # Wait for reader thread to finish
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=2)
            if self.reader_thread.is_alive():
                logger.warning("Reader thread didn't stop within timeout")
    
    def is_healthy(self) -> bool:
        """Check if the interactsh client is running and healthy"""
        return (self.is_running and 
                self.process and 
                self.process.poll() is None and 
                self.domain is not None)