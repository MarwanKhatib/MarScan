import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, send, sr1, RandShort
import socket
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from marscan.utils import get_logger

class BaseScan:
    """
    A base class for network port scanners.

    This class provides the core functionality for scanning a target host,
    including multi-threaded port scanning, decoy IP support, and scan delays.
    It is designed to be subclassed by specific scan type implementations.

    Attributes:
        host (str): The target host's IP address or domain name.
        timeout (float): The timeout in seconds for each port scan attempt.
        decoy_ips (list[str]): A list of IP addresses to use as decoys.
        scan_delay (float): The delay in seconds between scan probes.
        verbose (int): The verbosity level for logging.
        logger: The configured logger instance.
    """
    def __init__(self, host: str, timeout: float = 1.0, decoy_ips: list[str] = None, scan_delay: float = 0.0, scan_jitter: float = 0.0, verbose: int = 0, ttl: int = None, tcp_window: int = None, tcp_options: list = None):
        self.host = host
        self.timeout = timeout
        self.decoy_ips = decoy_ips if decoy_ips is not None else []
        self.scan_delay = scan_delay
        self.scan_jitter = scan_jitter
        self.verbose = verbose
        self.logger = get_logger(verbose)
        self.ttl = ttl
        self.tcp_window = tcp_window
        self.tcp_options = tcp_options if tcp_options is not None else []
        self.lock = threading.Lock()

    def _send_decoy_packets(self, port: int, flags: str):
        """
        Sends decoy TCP packets to a specific port from a list of decoy IPs.

        Args:
            port (int): The target port.
            flags (str): The TCP flags to use in the decoy packets.
        """
        for decoy_ip in self.decoy_ips:
            self.logger.debug(f"Sending decoy packet from {decoy_ip} to port {port}")
            decoy_packet = IP(src=decoy_ip, dst=self.host)/TCP(dport=port, sport=RandShort(), flags=flags)
            send(decoy_packet, verbose=0)

    def _scan_single_port(self, port: int) -> str | None:
        """
        An abstract method for scanning a single port.

        This method must be implemented by subclasses to define the specific
        logic for a particular scan type.

        Args:
            port (int): The port to scan.

        Returns:
            str | None: The status of the port ('open', 'closed', 'filtered', 'open|filtered')
                        or None if the scan fails unexpectedly.
        """
        raise NotImplementedError

    def scan_ports(self, ports: list[int], max_threads: int = 100) -> dict[int, str]:
        """
        Scans a list of ports on the target host concurrently.

        Uses a thread pool and a rich progress bar to show scan progress.

        Args:
            ports (list[int]): A list of port numbers to scan.
            max_threads (int): The maximum number of threads to use for scanning.

        Returns:
            dict[int, str]: A dictionary mapping port numbers to their state.
        """
        port_states = {}
        
        progress_columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed} of {task.total})"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ]

        with Progress(*progress_columns, transient=True) as progress:
            scan_task = progress.add_task("[cyan]Scanning Ports...", total=len(ports))
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(self._scan_single_port, port): port for port in ports}
                
                for future in as_completed(futures):
                    port = futures[future]
                    try:
                        state = future.result()
                        if state and state != 'closed':
                            self.logger.info(f"Port [bold green]{port}[/bold green] is {state}.")
                            with self.lock:
                                port_states[port] = state
                    except Exception as e:
                        self.logger.debug(f"Error scanning port {port}: {e}")
                    finally:
                        progress.update(scan_task, advance=1)

        return dict(sorted(port_states.items()))
