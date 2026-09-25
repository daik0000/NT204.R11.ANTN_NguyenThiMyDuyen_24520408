import os
import logging
import queue
import threading
from typing import Iterator, Tuple, Optional
from scapy.sendrecv import sniff

# Initialize module-level logger
logger = logging.getLogger(__name__)

def check_admin_privileges() -> bool:
    """
    Checks for root privileges.
    Required for live traffic capture (raw socket access) on Linux.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        # geteuid is not available on non-POSIX systems (e.g., Windows)
        return False

def capture_live(interface: Optional[str] = None, bpf_filter: str = "") -> Iterator[Tuple[float, bytes]]:
    """
    Captures live network traffic from a specified interface.
    Uses a Generator Pattern backed by a thread-safe Queue to stream data.
    
    Args:
        interface: Network interface name (e.g., 'eth0'). If None, Scapy uses the default.
        bpf_filter: BPF filter string (e.g., 'tcp port 80') for kernel-level optimization.
        
    Yields:
        Tuple containing the packet timestamp and raw bytes.
    """
    if not check_admin_privileges():
        raise PermissionError(
            "Root privileges are required to capture live traffic. "
            "Please run the script with 'sudo'."
        )

    # Queue with maxsize prevents memory exhaustion if the consumer (parser) is slower than the network.
    packet_queue: queue.Queue = queue.Queue(maxsize=2000)
    
    # Event flag to signal the sniffing thread to terminate gracefully.
    stop_event = threading.Event()

    def _packet_handler(pkt):
        """Callback invoked by Scapy for each captured packet."""
        try:
            # Use put_nowait to avoid blocking the Scapy sniffer thread.
            # Extract timestamp directly from kernel-stamped pkt.time and preserve raw bytes.
            packet_queue.put_nowait((float(pkt.time), pkt.original))
        except queue.Full:
            # Explicitly drop the packet and log a warning to handle backpressure,
            # instead of blocking the kernel socket implicitly.
            logger.warning("Packet queue is full. Dropping 1 packet to prevent memory exhaustion.")
        except Exception as e:
            logger.warning("Error extracting live packet: %s", e)

    def _start_sniffing():
        """Blocking function executed in a background daemon thread."""
        try:
            logger.info("Listening on interface: %s | Filter: '%s'", interface or "Default", bpf_filter)
            sniff(
                iface=interface,
                filter=bpf_filter,
                prn=_packet_handler,
                store=False,  # CRITICAL: Prevents Scapy from storing packets in RAM
                stop_filter=lambda pkt: stop_event.is_set()  # Allows graceful termination from the main thread
            )
        except Exception as e:
            logger.error("Capture Engine failed or stopped unexpectedly: %s", e)
        finally:
            try:
                # Send a Poison Pill (None) to notify the consumer that sniffing has ended
                # This ensures the generator can exit cleanly even if the sniffing thread terminates unexpectedly.
                packet_queue.put_nowait(None)
            except queue.Full:
                try:
                    packet_queue.get_nowait()
                    packet_queue.put_nowait(None)
                except queue.Empty:
                    logger.warning("Packet queue became empty before sending stop signal.")
                except queue.Full:
                    logger.warning("Packet queue is full. Failed to enqueue stop signal.")

    # Start the background sniffing thread
    sniffer_thread = threading.Thread(target=_start_sniffing, daemon=True)
    sniffer_thread.start()

    try:
        # Consumer loop: continuously pull packets from the queue and yield them
        while True:
            item = packet_queue.get()
            if item is None:  # Poison Pill received
                break
            yield item
    finally:
        # This block executes even if the generator is closed early (e.g., via break or GeneratorExit).
        # It sets the stop_event, signaling the Scapy stop_filter to terminate the background thread cleanly.
        stop_event.set()

if __name__ == "__main__":
    # Standalone module testing
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    
    try:
        count = 0
        # Capture 10 TCP packets for testing
        for ts, raw in capture_live(bpf_filter="tcp"):
            count += 1
            print(f"Captured packet {count} | Timestamp: {ts} | Size: {len(raw)} bytes")
            if count >= 10:
                print("Successfully captured 10 packets. Breaking the loop to test graceful shutdown...")
                break  # This will trigger the 'finally' block and stop the background thread
    except PermissionError as pe:
        logger.critical(pe)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")