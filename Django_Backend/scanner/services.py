# scanner/services.py
import os
import json
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from django.conf import settings
from .models import OpenAIDB, AzureDB, ScanResult

logger = logging.getLogger(__name__)

class HitlogHandler(FileSystemEventHandler):
    def __init__(self):
        self.processed_lines = {}  # Dictionary to track processed lines per file
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('.hitlog.jsonl'):
            self.process_hitlog_file(event.src_path)
    
    def process_hitlog_file(self, file_path):
        # Extract the base filename to match with yaml_file field
        base_path = os.path.basename(file_path)
        report_prefix = base_path.replace('.hitlog.jsonl', '')
        
        # Find the related scan
        openai_scan = None
        azure_scan = None
        
        try:
            # Try to find the related OpenAI scan
            openai_scan = OpenAIDB.objects.filter(yaml_file__startswith=report_prefix).first()
        except OpenAIDB.DoesNotExist:
            pass
            
        if not openai_scan:
            try:
                # Try to find the related Azure scan
                azure_scan = AzureDB.objects.filter(yaml_file__startswith=report_prefix).first()
            except AzureDB.DoesNotExist:
                logger.warning(f"No scan found for file: {file_path}")
                return
        
        # Initialize the processed lines counter for this file if it doesn't exist
        if file_path not in self.processed_lines:
            self.processed_lines[file_path] = 0
        
        # Process the file
        line_count = 0
        with open(file_path, 'r') as f:
            for line_count, line in enumerate(f, 1):
                # Skip already processed lines
                if line_count <= self.processed_lines[file_path]:
                    continue
                
                try:
                    data = json.loads(line.strip())
                    
                    # Create a new ScanResult
                    scan_result = ScanResult(
                        openai_scan=openai_scan,
                        azure_scan=azure_scan,
                        goal=data.get('goal'),
                        prompt=data.get('prompt'),
                        output=data.get('output'),
                        trigger=data.get('trigger'),
                        score=data.get('score'),
                        run_id=data.get('run_id'),
                        attempt_id=data.get('attempt_id'),
                        attempt_seq=data.get('attempt_seq'),
                        attempt_idx=data.get('attempt_idx'),
                        generator=data.get('generator'),
                        probe=data.get('probe'),
                        detector=data.get('detector'),
                        generations_per_prompt=data.get('generations_per_prompt')
                    )
                    scan_result.save()
                    logger.info(f"Saved scan result for file: {file_path}, line: {line_count}")
                    
                except json.JSONDecodeError:
                    logger.error(f"Error decoding JSON at line {line_count} in file {file_path}")
                except Exception as e:
                    logger.error(f"Error processing line {line_count} in file {file_path}: {str(e)}")
            
            # Update the processed lines counter
            self.processed_lines[file_path] = line_count