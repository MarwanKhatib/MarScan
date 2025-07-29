import time
import random
from scapy.all import IP, TCP, send, sr1, RandShort
from marscan.scanner.base import BaseScan

class SynScan(BaseScan):
    """
    Performs a TCP SYN (half-open) scan.

    This scan type sends a SYN packet and analyzes the response. A SYN-ACK
    response indicates an open port, while a RST-ACK response indicates a
    closed port. This method is stealthier than a connect scan as it
    doesn't complete the TCP handshake.
    """
    def _scan_single_port(self, port: int) -> bool:
        """
        Scans a single port using the TCP SYN scan technique.

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

            # Base IP layer
            ip_layer = IP(dst=self.host)
            if self.ttl:
                ip_layer.ttl = self.ttl

            # Base TCP layer
            tcp_layer_base = TCP(dport=port, sport=RandShort(), flags="S")
            if self.tcp_window:
                tcp_layer_base.window = self.tcp_window
            if self.tcp_options:
                tcp_layer_base.options = self.tcp_options

            packet = ip_layer/tcp_layer_base
            resp = sr1(packet, timeout=self.timeout, verbose=0)

            if resp and resp.haslayer(TCP):
                tcp_resp_layer = resp.getlayer(TCP)
                if tcp_resp_layer.flags == 0x12:  # SYN-ACK
                    self.logger.info(f"[*] Port {port}: Open (SYN-ACK received)")
                    send(IP(dst=self.host)/TCP(dport=port, sport=resp.sport, flags="R"), verbose=0)
                    return True
                elif tcp_resp_layer.flags == 0x14:  # RST-ACK
                    self.logger.info(f"[*] Port {port}: Closed (RST-ACK received)")
                    return False
                else:
                    self.logger.debug(f"[*] Port {port}: Received unexpected flags: {hex(tcp_resp_layer.flags)}")
            else:
                self.logger.info(f"[*] Port {port}: Filtered/No response")
            return False
        except Exception as e:
            self.logger.debug(f"[*] Port {port}: Exception during SYN scan: {e}")
            return False
