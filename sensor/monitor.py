import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from sensor.entropy import calculate_entropy
from sensor.ai_brain import RenameHeuristic  # Import the new Heuristic

MAGIC_NUMBERS = {
    '.pdf': b'%PDF', '.zip': b'PK', '.xlsx': b'PK', '.docx': b'PK',
    '.jar': b'PK', '.png': b'\x89PNG', '.jpg': b'\xFF\xD8\xFF', '.db': b'SQLite format 3'
}

def is_valid_header(filepath):
    _, ext = os.path.splitext(filepath)
    ext = ext.lower()
    if ext not in MAGIC_NUMBERS: return True
    try:
        if os.path.getsize(filepath) == 0: return True
        with open(filepath, 'rb') as f:
            header = f.read(len(MAGIC_NUMBERS[ext]))
            return header.startswith(MAGIC_NUMBERS[ext])
    except: return True 

class AegisHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        self.last_scan = {}

    def on_moved(self, event):
        """
        Triggered when a file is renamed.
        Example: data.docx -> data.docx.locked
        """
        if event.is_directory: return
        
        src = event.src_path
        dest = event.dest_path
        
        # Check against Rename Heuristics (Double extension, random characters)
        is_threat, reason = RenameHeuristic.is_malicious_rename(src, dest)
        
        if is_threat:
            print(f"🚨 [RENAMED] THREAT DETECTED: {reason}")
            # We send RENAME:1 so app.py knows the specific vector
            # We spike entropy to 9.9 to ensure graph spikes red immediately
            packet = f"ENTROPY:9.9|TRAP:0|BADHEADER:0|RENAME:1|PATH:{dest}"
            self.callback(packet)

    def on_modified(self, event):
        if event.is_directory: return
        filepath = event.src_path
        filename = os.path.basename(filepath)
        
        # Debounce (Prevent scanning same file multiple times per second)
        if time.time() - self.last_scan.get(filepath, 0) < 1.0: return
        self.last_scan[filepath] = time.time()
        time.sleep(0.1)

        trap = 1 if "config.sys" in filename else 0
        entropy = calculate_entropy(filepath)
        
        bad_header = 0
        if not is_valid_header(filepath):
            bad_header = 1

        # Added RENAME:0 for normal modified events
        packet = f"ENTROPY:{entropy:.2f}|TRAP:{trap}|BADHEADER:{bad_header}|RENAME:0|PATH:{filepath}"
        self.callback(packet)

def start_monitoring(path, callback):
    event_handler = AegisHandler(callback)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    print(f"👁️ WATCHDOG ACTIVE: Scanning {path}...")