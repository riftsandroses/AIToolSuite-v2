import os
import time
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from django.utils.timezone import now
from scanner.models import ScanResult  # Import your database model


class JSONLFileHandler(FileSystemEventHandler):
    def __init__(self, file_path, user):
        self.file_path = file_path
        self.user = user

        # Wait for the file to be created before proceeding
        self.wait_for_file()

        # Initialize last modified time after file creation
        self.last_modified = os.path.getmtime(self.file_path)

    def wait_for_file(self, timeout=300):
        """Wait for the file to appear (max wait time: 30 seconds)."""
        start_time = time.time()
        while not os.path.exists(self.file_path):
            if time.time() - start_time > timeout:
                print(f"Error: File {self.file_path} not found after {timeout} seconds.")
                return
            time.sleep(1)  # Check every second

    def on_modified(self, event):
        """Process file updates when the file is modified."""
        if event.src_path == self.file_path:
            current_mtime = os.path.getmtime(self.file_path)

            if current_mtime > self.last_modified:
                self.last_modified = current_mtime
                self.process_jsonl_file()

    def on_created(self, event):
        """Process file when it is first created."""
        if event.src_path == self.file_path:
            self.process_jsonl_file()

    def process_jsonl_file(self):
        """Read the JSONL file and insert data into the database."""
        print(f"Processing file: {self.file_path}")

        with open(self.file_path, 'r') as file:
            for line in file:
                try:
                    data = json.loads(line.strip())
                    file_name = Path(self.file_path).name

                    # Insert into database
                    ScanResult.objects.create(
                        report_name=file_name,
                        user=self.user,
                        goal=data.get("goal", ""),
                        prompt=data.get("prompt", ""),
                        output=data.get("output", ""),
                        trigger=data.get("trigger", ""),
                        score=data.get("score", 0),
                        run_id=data.get("run_id", ""),
                        attempt_id=data.get("attempt_id", ""),
                        attempt_seq=data.get("attempt_seq", ""),
                        attempt_idx=data.get("attempt_idx", ""),
                        generator=data.get("generator", ""),
                        probe=data.get("probe", ""),
                        detector=data.get("detector", ""),
                        generations_per_prompt=data.get("generations_per_prompt", 0),
                        created_at=now(),
                    )
                except json.JSONDecodeError:
                    print("Error decoding JSON line:", line)


def start_file_watch(file_path, user):
    """Start the Watchdog observer in a separate thread."""
    event_handler = JSONLFileHandler(file_path, user)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(file_path), recursive=False)
    observer.start()
    
    print(f"Started watching: {file_path}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()
