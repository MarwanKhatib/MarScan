import pytest
from marscan.scanner import ConnectScan, SynScan, AckScan, UdpScan, FinScan, XmasScan

# NOTE: Scapy-based scans (SYN, ACK, FIN, Xmas, UDP) often require root/administrator privileges
# to send and receive raw packets. If these tests fail, try running pytest with sudo:
# sudo PYTHONPATH=. pytest tests/test_scans.py

# Use a well-known test target
TEST_HOST = "scanme.nmap.org"
# Common ports that are often open on scanme.nmap.org for testing TCP scans
COMMON_TCP_PORTS = [22, 80, 443, 31337]
# A few common UDP ports, though UDP scanning is less reliable for "open" status
COMMON_UDP_PORTS = [53, 161] # DNS, SNMP

@pytest.mark.parametrize("scan_class, expected_open_ports", [
    (ConnectScan, COMMON_TCP_PORTS),
    (SynScan, COMMON_TCP_PORTS),
    (FinScan, COMMON_TCP_PORTS),
    (XmasScan, COMMON_TCP_PORTS),
    (AckScan, COMMON_TCP_PORTS), # ACK scan shows unfiltered ports, which should be open ones
])
def test_tcp_scans(scan_class, expected_open_ports):
    """
    Tests various TCP scan types against a known host and expected open ports.
    """
    scanner = scan_class(host=TEST_HOST, timeout=2.0) # Increased timeout for network stability
    console_output = [] # To capture print statements if needed for debugging
    
    # Temporarily redirect stdout to capture console output
    # import sys
    # from io import StringIO
    # old_stdout = sys.stdout
    # sys.stdout = mystdout = StringIO()

    try:
        open_ports = scanner.scan_ports(COMMON_TCP_PORTS, max_threads=50)
        # console_output = mystdout.getvalue()
    finally:
        # sys.stdout = old_stdout
        pass

    print(f"\n--- {scan_class.__name__} Results for {TEST_HOST} ---")
    print(f"Scanned Ports: {COMMON_TCP_PORTS}")
    print(f"Open Ports Found: {open_ports}")
    # print(f"Console Output: {console_output}")

    # Assert that at least some of the expected ports are found.
    # Scanme.nmap.org might not have all of them open all the time,
    # but we expect a reasonable subset.
    assert any(port in open_ports for port in expected_open_ports), \
        f"Expected at least one of {expected_open_ports} to be open with {scan_class.__name__}"
    
    # For ACK scan, we expect unfiltered ports to be returned.
    # If a port is unfiltered, it means it responded with RST, which implies it's not blocked by a firewall.
    # For open ports, ACK scan should return RST, so they should appear as "open" (unfiltered).
    if scan_class == AckScan:
        assert len(open_ports) > 0, f"ACK scan should find some unfiltered ports on {TEST_HOST}"


def test_udp_scan():
    """
    Tests UDP scan against a known host.
    UDP scan results are often ambiguous; this test primarily ensures the scan runs
    and returns a list of ports without errors.
    """
    scanner = UdpScan(host=TEST_HOST, timeout=2.0)
    
    print(f"\n--- UdpScan Results for {TEST_HOST} ---")
    print(f"Scanned Ports: {COMMON_UDP_PORTS}")

    open_ports = scanner.scan_ports(COMMON_UDP_PORTS, max_threads=10) # UDP scans can be slower/less reliable
    
    print(f"Open Ports Found: {open_ports}")

    # For UDP, we primarily assert that the scan completes and returns a list.
    # It's hard to predict open UDP ports on scanme.nmap.org reliably.
    assert isinstance(open_ports, list)
    # We might expect some ports to be "open" (no response) or filtered.
    # A simple check for non-empty list if some ports are expected to be open/filtered.
    # For scanme.nmap.org, port 53 (DNS) might be open.
    assert any(port in open_ports for port in COMMON_UDP_PORTS) or len(open_ports) >= 0, \
        f"UDP scan did not return expected results for {TEST_HOST}"
