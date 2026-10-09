import json
import os
import sys
import threading
from typing import Any

class JSONLLogger:
    """
    A thread-safe logger that writes dataclass objects (like IDSEvent or Flow) to a file in JSONL format.
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
        
        # Number of records that could not be written (serialization or I/O errors).
        # Errors never stop the pipeline, so callers and tests check this counter instead.
        self.write_errors = 0
        
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

    def log(self, record: Any) -> None:
        """
        Serializes a dataclass object (IDSEvent, Flow) to a JSON string and appends it as a new line.
        Thread-safe for multi-worker environments.
        """
        try:
            # Relies on the standard to_dict() method implemented in both IDSEvent and Flow schemas
            json_str = json.dumps(record.to_dict(), ensure_ascii=False)
            
            # Acquire lock before writing to prevent interleaved/corrupted JSON lines
            with self._lock:
                self._file.write(json_str + "\n")
                
                # Push data from Python's internal buffer to the OS buffer
                self._file.flush()
                
                # Hardware-level flush (only if explicitly enabled due to severe performance hit)
                if self.sync_every_write:
                    os.fsync(self._file.fileno())
                    
        except Exception as e:
            self.write_errors += 1
            print(f"[ERROR] Failed to write record to JSONL log: {e}", file=sys.stderr)

    # Backward compatibility alias for Bai 1
    # Bai 1 detector pipeline calls `logger.log_event(event)`
    def log_event(self, event: Any) -> None:
        self.log(event)

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