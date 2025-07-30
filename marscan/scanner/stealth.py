import time
import random
from scapy.all import IP, TCP, sr1, RandShort
from marscan.scanner.base import BaseScan

class StealthScan(BaseScan):
    """
    A base class for stealth scanning techniques (FIN, NULL, XMAS).

    This class encapsulates the common logic for scans that determine port
    status based on the presence or absence of a RST packet in response to
    a specially crafted probe.
    """
    flags: str = ""  # Must be overridden by subclasses

    def _scan_single_port(self, port: int) -> str | None:
        """
        Scans a single port using the configured stealth technique.

        Args:
            port (int): The port to scan.

        Returns:
            str | None: The status of the port ('open|filtered', 'closed') or None on error.
        """
        try:
            if self.scan_jitter > 0:
                time.sleep(random.uniform(0, self.scan_jitter))
            elif self.scan_delay > 0:
                time.sleep(self.scan_delay)

            if self.decoy_ips:
                self._send_decoy_packets(port, flags=self.flags)

            ip_layer = IP(dst=self.host)
            if self.ttl:
                ip_layer.ttl = self.ttl

            tcp_layer = TCP(dport=port, sport=RandShort(), flags=self.flags)
            if self.tcp_window:
                tcp_layer.window = self.tcp_window
            if self.tcp_options:
                tcp_layer.options = self.tcp_options

            packet = ip_layer / tcp_layer
            resp = sr1(packet, timeout=self.timeout, verbose=0)

            if resp is None:
                return 'open|filtered'
            elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                return 'closed'
            else:
                self.logger.debug(f"[*] Port {port}: Received unexpected response for {self.__class__.__name__}")
                return 'filtered'

        except Exception as e:
            self.logger.debug(f"[*] Port {port}: Exception during {self.__class__.__name__}: {e}")
            return None
