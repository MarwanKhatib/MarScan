import time
import random
from scapy.all import IP, TCP, sr1
from marscan.scanner.base import BaseScan

class FinScan(BaseScan):
    """
    Performs a TCP FIN scan.

    This scan type sends a TCP packet with only the FIN flag set.
    - A RST response indicates the port is closed.
    - No response indicates the port is open or filtered.
    This scan is stealthy and can bypass some non-stateful firewalls.
    """
    def _scan_single_port(self, port: int) -> bool:
        """
        Scans a single port using the TCP FIN scan technique.

        Args:
            port (int): The port to scan.

        Returns:
            bool: True if the port is likely open, False if it is closed.
        """
        try:
            if self.scan_jitter > 0:
                time.sleep(random.uniform(0, self.scan_jitter))
            elif self.scan_delay > 0:
                time.sleep(self.scan_delay)

            ip_layer = IP(dst=self.host)
            if self.ttl:
                ip_layer.ttl = self.ttl

            tcp_layer = TCP(dport=port, sport=random.randint(1024, 65535), flags="F")
            if self.tcp_window:
                tcp_layer.window = self.tcp_window
            if self.tcp_options:
                tcp_layer.options = self.tcp_options

            packet = ip_layer / tcp_layer
            resp = sr1(packet, timeout=self.timeout, verbose=0)

            if resp is None:
                self.logger.info(f"[*] Port {port}: Open|Filtered (No response)")
                return True
            elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                self.logger.info(f"[*] Port {port}: Closed (RST-ACK received)")
                return False
            else:
                self.logger.debug(f"[*] Port {port}: Received unexpected response")
                return False

        except Exception as e:
            self.logger.debug(f"[*] Port {port}: Exception during FIN scan: {e}")
            return False
