import json
import os
import sys
import threading
from src.models.event import IDSEvent

class JSONLLogger:
    """
    A thread-safe logger that writes IDSEvent objects to a file in JSONL format.
    Ensures safe, append-only writing with immediate disk flushing to prevent data loss.
    """

    def __init__(self, file_path: str = "output/events.jsonl", sync_every_write: bool = False):
        """
        Initialize the logger, creates necessary directories, and opens the file.
        
        Args:
            file_path: The path to the output JSONL file.
            sync_every_write: If True, forces OS to write to physical disk (fsync) per event.
                This ensures data durability but at a significant performance cost. So, default is False.
        """
        self.file_path = file_path
        self.sync_every_write = sync_every_write
        
        # Lock ensures thread-safety if multiple consumer threads process packets concurrently
        self._lock = threading.Lock()
        
        try:
            # Ensure the output directory exists
            directory = os.path.dirname(self.file_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            
            # Open the file in append mode with UTF-8 encoding
            self._file = open(self.file_path, "a", encoding="utf-8")
        except PermissionError:
            print(f"[CRITICAL] Permission denied: Cannot write to '{self.file_path}'. "
                  f"Please check folder permissions or run with elevated privileges.")
            raise
        except OSError as e:
            print(f"[CRITICAL] OS Error initializing logger at '{self.file_path}': {e}")
            raise

    def log_event(self, event: IDSEvent) -> None:
        """
        Serializes an IDSEvent to a JSON string and appends it as a new line.
        Thread-safe for multi-worker environments.
        """
        try:
            json_str = json.dumps(event.to_dict(), ensure_ascii=False)
            
            # Acquire lock before writing to prevent interleaved/corrupted JSON lines
            with self._lock:
                self._file.write(json_str + "\n")
                
                # Push data from Python's internal buffer to the OS buffer
                self._file.flush()
                
                # Hardware-level flush (only if explicitly enabled due to severe performance hit)
                if self.sync_every_write:
                    os.fsync(self._file.fileno())
                    
        except Exception as e:
            print(f"[ERROR] Failed to write event to JSONL log: {e}")

    def close(self) -> None:
        """
        Gracefully closes the file handle.
        """
        # hasattr check prevents errors if __init__ failed before _file was created
        if hasattr(self, '_file') and self._file and not self._file.closed:
            self._file.close()

    # Context Manager support
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()