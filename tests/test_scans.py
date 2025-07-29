import pytest
import socket
from marscan.scanner import SynScan, ConnectScan

# NOTE: Scapy-based scans (SYN) often require root/administrator privileges
# to send and receive raw packets. If these tests fail, try running pytest with sudo:
# sudo PYTHONPATH=. pytest tests/test_scans.py

# For ConnectScan, we can use a local port if available, or a known open port on TEST_HOST
# For SYN scan, we must use a remote host like scanme.nmap.org

# Use a well-known test target
TEST_HOST = "scanme.nmap.org"
# Common ports that are often open on scanme.nmap.org for testing TCP scans
COMMON_TCP_PORTS = [22, 80, 443, 31337]

def test_syn_scan():
    """
    Tests TCP SYN scan against a known host and expected open ports.
    """
    scanner = SynScan(host=TEST_HOST, timeout=2.0) # Increased timeout for network stability
    
    try:
        open_ports = scanner.scan_ports(COMMON_TCP_PORTS, max_threads=50)
    except Exception as e:
        pytest.fail(f"SYN scan failed with exception: {e}")

    print(f"\n--- SynScan Results for {TEST_HOST} ---")
    print(f"Scanned Ports: {COMMON_TCP_PORTS}")
    print(f"Open Ports Found: {open_ports}")

    # Assert that at least some of the expected ports are found.
    # Scanme.nmap.org might not have all of them open all the time,
    # but we expect a reasonable subset.
    assert any(port in open_ports for port in COMMON_TCP_PORTS), \
        f"Expected at least one of {COMMON_TCP_PORTS} to be open with SynScan"

def test_connect_scan():
    """
    Tests TCP Connect scan against a known host and expected open ports.
    """
    scanner = ConnectScan(host=TEST_HOST, timeout=2.0) # Increased timeout for network stability
    
    try:
        open_ports = scanner.scan_ports(COMMON_TCP_PORTS, max_threads=50)
    except Exception as e:
        pytest.fail(f"Connect scan failed with exception: {e}")

    print(f"\n--- ConnectScan Results for {TEST_HOST} ---")
    print(f"Scanned Ports: {COMMON_TCP_PORTS}")
    print(f"Open Ports Found: {open_ports}")

    # Assert that at least some of the expected ports are found.
    assert any(port in open_ports for port in COMMON_TCP_PORTS), \
        f"Expected at least one of {COMMON_TCP_PORTS} to be open with ConnectScan"
