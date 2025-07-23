import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Attempts to connect to a specific port on a given host to determine if it's open.

    Args:
        host (str): The target host (IP address or domain name).
        port (int): The port number to scan.
        timeout (float): The maximum time in seconds to wait for a connection attempt.

    Returns:
        bool: True if the port is open (connection successful), False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # connect_ex returns 0 for success, or an error code otherwise
            result = sock.connect_ex((host, port))
            return result == 0
    except (socket.timeout, ConnectionRefusedError, OSError):
        # Handle specific network-related exceptions
        return False
    except Exception:
        # Catch any other unexpected exceptions
        return False

def scan_ports(host: str, ports: list[int], max_threads: int = 100, timeout: float = 1.0) -> list[int]:
    """
    Scans a list of ports on a given host concurrently using a thread pool.

    Args:
        host (str): The target host (IP address or domain name).
        ports (list[int]): A list of port numbers to scan.
        max_threads (int): The maximum number of concurrent threads to use for scanning.
                           This helps manage CPU and memory consumption.
        timeout (float): The connection timeout in seconds for each port scan.

    Returns:
        list[int]: A sorted list of open port numbers found on the host.
    """
    open_ports = []

    # Using ThreadPoolExecutor for efficient concurrent scanning
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit scan_port tasks for each port and map them to their original port numbers
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}

        # Iterate over completed futures as they finish
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():  # Get the result of the scan_port call
                    open_ports.append(port)
            except Exception:
                # Exceptions from scan_port are already handled internally,
                # but this catches any unexpected issues from future.result()
                pass

    return sorted(open_ports)
