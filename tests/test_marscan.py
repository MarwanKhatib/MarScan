import pytest
from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP
from marscan.scanner import ConnectScan, SynScan, FinScan, NullScan, XmasScan

# Fixture to initialize scanners
@pytest.fixture(params=[ConnectScan, SynScan, FinScan, NullScan, XmasScan])
def scanner_instance(request):
    """Provides an instance of each scanner class."""
    return request.param(host="127.0.0.1", timeout=0.1)

# --- Test Connect Scan ---

@patch('socket.socket')
def test_connect_scan_open_port(mock_socket):
    """Test ConnectScan correctly identifies an open port."""
    mock_sock_instance = MagicMock()
    mock_sock_instance.connect_ex.return_value = 0  # 0 indicates success
    mock_socket.return_value.__enter__.return_value = mock_sock_instance

    scanner = ConnectScan(host="127.0.0.1", timeout=0.1)
    assert scanner._scan_single_port(80) == 'open'
    mock_sock_instance.connect_ex.assert_called_once_with(("127.0.0.1", 80))

@patch('socket.socket')
def test_connect_scan_closed_port(mock_socket):
    """Test ConnectScan correctly identifies a closed port."""
    mock_sock_instance = MagicMock()
    mock_sock_instance.connect_ex.return_value = 111  # ECONNREFUSED
    mock_socket.return_value.__enter__.return_value = mock_sock_instance

    scanner = ConnectScan(host="127.0.0.1", timeout=0.1)
    assert scanner._scan_single_port(80) == 'closed'

# --- Test SYN Scan ---

@patch('marscan.scanner.syn.sr1')
def test_syn_scan_open_port(mock_sr1):
    """Test SynScan correctly identifies an open port (SYN-ACK response)."""
    mock_response = MagicMock()
    mock_response.haslayer.return_value = True
    mock_response.getlayer.return_value.flags = 0x12  # SYN-ACK
    mock_sr1.return_value = mock_response

    scanner = SynScan(host="127.0.0.1", timeout=0.1)
    assert scanner._scan_single_port(80) == 'open'

@patch('marscan.scanner.syn.sr1')
def test_syn_scan_closed_port(mock_sr1):
    """Test SynScan correctly identifies a closed port (RST-ACK response)."""
    mock_response = MagicMock()
    mock_response.haslayer.return_value = True
    mock_response.getlayer.return_value.flags = 0x14  # RST-ACK
    mock_sr1.return_value = mock_response

    scanner = SynScan(host="127.0.0.1", timeout=0.1)
    assert scanner._scan_single_port(80) == 'closed'

@patch('marscan.scanner.syn.sr1')
def test_syn_scan_filtered_port(mock_sr1):
    """Test SynScan correctly identifies a filtered port (no response)."""
    mock_sr1.return_value = None  # No response

    scanner = SynScan(host="127.0.0.1", timeout=0.1)
    assert scanner._scan_single_port(80) == 'filtered'

# --- Test Stealth Scans (FIN, NULL, XMAS) ---

@pytest.mark.parametrize("scanner_class, flags", [
    (FinScan, "F"),
    (NullScan, ""),
    (XmasScan, "FPU")
])
@patch('marscan.scanner.stealth.sr1')
def test_stealth_scans_open_port(mock_sr1, scanner_class, flags):
    """Test stealth scans correctly identify an open/filtered port (no response)."""
    mock_sr1.return_value = None  # No response indicates open|filtered

    scanner = scanner_class(host="127.0.0.1", timeout=0.1)
    assert scanner._scan_single_port(80) == 'open|filtered'
    
    # Verify the correct flags were used in the packet
    mock_sr1.assert_called_once()
    sent_packet = mock_sr1.call_args[0][0]
    assert sent_packet[TCP].flags == flags

@pytest.mark.parametrize("scanner_class", [FinScan, NullScan, XmasScan])
@patch('marscan.scanner.stealth.sr1')
def test_stealth_scans_closed_port(mock_sr1, scanner_class):
    """Test stealth scans correctly identify a closed port (RST-ACK response)."""
    mock_response = MagicMock()
    mock_response.haslayer.return_value = True
    mock_response.getlayer.return_value.flags = 0x14  # RST-ACK
    mock_sr1.return_value = mock_response

    scanner = scanner_class(host="127.0.0.1", timeout=0.1)
    assert scanner._scan_single_port(80) == 'closed'
