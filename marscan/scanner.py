import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, UDP, sr1, ICMP, Raw, send, RandShort

class BaseScan:
    """
    Base class for all scan types.
    """
    def __init__(self, host: str, timeout: float = 1.0):
        self.host = host
        self.timeout = timeout

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

class ConnectScan(BaseScan):
    """
    Performs a TCP Connect scan.
    """
    def _scan_single_port(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.host, port))
                return result == 0
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        except Exception:
            return False

class SynScan(BaseScan):
    """
    Performs a TCP SYN (half-open) scan.
    """
    def _scan_single_port(self, port: int) -> bool:
        try:
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
                    # Send RST to close the connection cleanly
                    send(IP(dst=self.host)/TCP(dport=port, sport=resp.sport, flags="R"), verbose=0)
                    return True
                # If RST-ACK received, port is closed
                elif tcp_layer.flags == 0x14:  # RST-ACK
                    return False
            return False
        except Exception:
            return False

class AckScan(BaseScan):
    """
    Performs a TCP ACK scan. Used to map firewall rules and determine if a port is filtered.
    """
    def _scan_single_port(self, port: int) -> bool:
        try:
            packet = IP(dst=self.host)/TCP(dport=port, sport=RandShort(), flags="A")
            resp = sr1(packet, timeout=self.timeout, verbose=0)

            if resp and resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x04:  # RST
                    # If RST received, port is unfiltered
                    return True
                # Other responses (e.g., no response) indicate filtered
            return False
        except Exception:
            return False

class UdpScan(BaseScan):
    """
    Performs a UDP scan.
    """
    def _scan_single_port(self, port: int) -> bool:
        try:
            # Send a UDP packet to the target port
            # For common services, a small payload might elicit a response
            # For this example, we send an empty UDP packet
            packet = IP(dst=self.host)/UDP(dport=port)
            resp = sr1(packet, timeout=self.timeout, verbose=0)

            if resp is None:
                # No response usually means the port is open or filtered
                # In UDP, no response often means open (no service to reply or firewall drops)
                # This is an ambiguous state, but we'll treat it as potentially open for now.
                return True
            elif resp.haslayer(ICMP):
                # ICMP Port Unreachable (type 3, code 3) means port is closed
                if resp.getlayer(ICMP).type == 3 and resp.getlayer(ICMP).code == 3:
                    return False
            return False # Any other response means closed or filtered
        except Exception:
            return False

class FinScan(BaseScan):
    """
    Performs a TCP FIN scan. Open ports should ignore FIN packets, closed ports should respond with RST.
    """
    def _scan_single_port(self, port: int) -> bool:
        try:
            packet = IP(dst=self.host)/TCP(dport=port, sport=RandShort(), flags="F")
            resp = sr1(packet, timeout=self.timeout, verbose=0)

            if resp is None:
                # No response means port is open (or filtered)
                return True
            elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x04:  # RST
                # RST response means port is closed
                return False
            return False
        except Exception:
            return False

class XmasScan(BaseScan):
    """
    Performs a TCP Xmas scan (FIN, PSH, URG flags set).
    Open ports should ignore, closed ports should respond with RST.
    """
    def _scan_single_port(self, port: int) -> bool:
        try:
            # Flags "FPU" for FIN, PSH, URG
            packet = IP(dst=self.host)/TCP(dport=port, sport=RandShort(), flags="FPU")
            resp = sr1(packet, timeout=self.timeout, verbose=0)

            if resp is None:
                # No response means port is open (or filtered)
                return True
            elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x04:  # RST
                # RST response means port is closed
                return False
            return False
        except Exception:
            return False
