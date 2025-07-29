import time
import socket
import random
from marscan.scanner.base import BaseScan

class ConnectScan(BaseScan):
    """
    Performs a TCP Connect scan.

    This scan type attempts to complete a full TCP handshake with the target
    port. If the connection is successful, the port is considered open.
    This method is reliable but easily detectable.
    """
    def _scan_single_port(self, port: int) -> bool:
        """
        Scans a single port using the TCP Connect scan technique.

        Args:
            port (int): The port to scan.

        Returns:
            bool: True if the port is open, False otherwise.
        """
        try:
            if self.scan_jitter > 0:
                time.sleep(random.uniform(0, self.scan_jitter))
            elif self.scan_delay > 0:
                time.sleep(self.scan_delay)
            
            if self.decoy_ips:
                self._send_decoy_packets(port, flags="S")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.host, port))
                
                if result == 0:
                    self.logger.info(f"[*] Port {port}: Open (Connection successful)")
                    return True
                elif result == 111:  # ECONNREFUSED
                    self.logger.info(f"[*] Port {port}: Closed (Connection refused)")
                    return False
                else:
                    self.logger.info(f"[*] Port {port}: Filtered/Other error (Error code: {result})")
                    return False
        except Exception as e:
            self.logger.debug(f"[*] Port {port}: Exception during Connect scan: {e}")
            return False
