import time
import socket
import random
import errno
from marscan.scanner.base import BaseScan

class ConnectScan(BaseScan):
    """
    Performs a TCP Connect scan.

    This scan type attempts to complete a full TCP handshake with the target
    port. If the connection is successful, the port is considered open.
    This method is reliable but easily detectable.
    """
    def _scan_single_port(self, port: int, retries: int = 2) -> str | None:
        """
        Scans a single port using the TCP Connect scan technique with retries.

        Args:
            port (int): The port to scan.
            retries (int): The number of times to retry if a port appears filtered.

        Returns:
            str | None: The status of the port ('open', 'closed', 'filtered') or None on error.
        """
        for attempt in range(retries + 1):
            try:
                if self.scan_jitter > 0:
                    time.sleep(random.uniform(0, self.scan_jitter))
                elif self.scan_delay > 0:
                    time.sleep(self.scan_delay)
                
                if attempt == 0 and self.decoy_ips:
                    self._send_decoy_packets(port, flags="S")

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((self.host, port))
                    
                    if result == 0:
                        return 'open'
                    elif result == errno.ECONNREFUSED:
                        return 'closed'
                    
                    # If we are on the last attempt, return filtered. Otherwise, loop and retry.
                    if attempt == retries:
                        return 'filtered'
                    else:
                        self.logger.debug(f"[*] Port {port}: Filtered on attempt {attempt+1}, retrying...")
                        time.sleep(self.timeout * (attempt + 1)) # Exponential backoff

            except socket.timeout:
                if attempt == retries:
                    return 'filtered'
                else:
                    self.logger.debug(f"[*] Port {port}: Timed out on attempt {attempt+1}, retrying...")
                    time.sleep(self.timeout * (attempt + 1)) # Exponential backoff
            except Exception as e:
                self.logger.debug(f"[*] Port {port}: Exception during Connect scan: {e}")
                return None
        
        return 'filtered' # Should not be reached, but as a fallback
