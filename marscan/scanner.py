import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, send, sr1, RandShort
import socket

class BaseScan:
    """
    Base class for all scan types.
    """
    def __init__(self, host: str, timeout: float = 1.0, decoy_ips: list[str] = None, scan_delay: float = 0.0, verbose: int = 0):
        self.host = host
        self.timeout = timeout
        self.decoy_ips = decoy_ips if decoy_ips is not None else []
        self.scan_delay = scan_delay
        self.verbose = verbose

    def _send_decoy_packets(self, port: int, flags: str):
        """
        Sends decoy packets from spoofed IP addresses.
        """
        for decoy_ip in self.decoy_ips:
            # Send a simple packet from the decoy IP
            decoy_packet = IP(src=decoy_ip, dst=self.host)/TCP(dport=port, sport=RandShort(), flags=flags)
            send(decoy_packet, verbose=0)

    def _scan_single_port(self, port: int) -> bool:
        """
        Abstract method to be implemented by subclasses for scanning a single port.
        """
        raise NotImplementedError

    def scan_ports(self, ports: list[int], max_threads: int = 100) -> list[int]:
        """
        Scans a list of ports on the host concurrently using a thread pool.
        """
        open_ports = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self._scan_single_port, port): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    # print(f"Error scanning port {port}: {e}") # For debugging
                    pass
        return sorted(open_ports)

class SynScan(BaseScan):
    """
    Performs a TCP SYN (half-open) scan.
    """
    def _scan_single_port(self, port: int) -> bool:
        try:
            if self.scan_delay > 0:
                time.sleep(self.scan_delay)
            # Send decoy packets before the actual scan
            if self.decoy_ips:
                self._send_decoy_packets(port, flags="S")

            # Craft SYN packet
            # RandShort() for random source port
            # flags="S" for SYN flag
            packet = IP(dst=self.host)/TCP(dport=port, sport=RandShort(), flags="S")
            # sr1 sends packet and waits for first response
            # verbose=0 suppresses Scapy output
            resp = sr1(packet, timeout=self.timeout, verbose=0)

            if resp and resp.haslayer(TCP):
                tcp_layer = resp.getlayer(TCP)
                # If SYN-ACK received, port is open
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    if self.verbose >= 1:
                        print(f"[*] Port {port}: Open (SYN-ACK received)")
                    # Send RST to close the connection cleanly
                    send(IP(dst=self.host)/TCP(dport=port, sport=resp.sport, flags="R"), verbose=0)
                    return True
                # If RST-ACK received, port is closed
                elif tcp_layer.flags == 0x14:  # RST-ACK
                    if self.verbose >= 1:
                        print(f"[*] Port {port}: Closed (RST-ACK received)")
                    return False
                else:
                    if self.verbose >= 2:
                        print(f"[*] Port {port}: Received unexpected flags: {hex(tcp_layer.flags)}")
            else:
                if self.verbose >= 1:
                    print(f"[*] Port {port}: Filtered/No response (Timeout or no TCP layer)")
            return False
        except Exception as e:
            if self.verbose >= 2:
                print(f"[*] Port {port}: Exception during SYN scan: {e}")
            return False

class ConnectScan(BaseScan):
    """
    Performs a TCP Connect scan.
    """
    def _scan_single_port(self, port: int) -> bool:
        try:
            if self.scan_delay > 0:
                time.sleep(self.scan_delay)
            
            # Send decoy packets before the actual scan
            if self.decoy_ips:
                self._send_decoy_packets(port, flags="S")

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.host, port))
            s.close()
            
            if result == 0:
                if self.verbose >= 1:
                    print(f"[*] Port {port}: Open (Connection successful)")
                return True
            elif result == 111: # ECONNREFUSED
                if self.verbose >= 1:
                    print(f"[*] Port {port}: Closed (Connection refused)")
                return False
            else:
                if self.verbose >= 1:
                    print(f"[*] Port {port}: Filtered/Other error (Error code: {result})")
                return False
        except Exception as e:
            if self.verbose >= 2:
                print(f"[*] Port {port}: Exception during Connect scan: {e}")
            return False
