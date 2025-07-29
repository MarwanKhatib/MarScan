import unittest
from marscan.scanner import ConnectScan, SynScan

class TestSimpleScans(unittest.TestCase):

    def test_connect_scan_instantiation(self):
        """Test that ConnectScan can be instantiated without errors."""
        try:
            scanner = ConnectScan(host="127.0.0.1")
            self.assertIsInstance(scanner, ConnectScan)
        except Exception as e:
            self.fail(f"ConnectScan instantiation failed: {e}")

    def test_syn_scan_instantiation(self):
        """Test that SynScan can be instantiated without errors."""
        try:
            scanner = SynScan(host="127.0.0.1")
            self.assertIsInstance(scanner, SynScan)
        except Exception as e:
            self.fail(f"SynScan instantiation failed: {e}")

    def test_connect_scan_empty_ports(self):
        """Test ConnectScan with an empty list of ports."""
        scanner = ConnectScan(host="127.0.0.1")
        open_ports = scanner.scan_ports([])
        self.assertEqual(open_ports, [])

    def test_syn_scan_empty_ports(self):
        """Test SynScan with an empty list of ports."""
        scanner = SynScan(host="127.0.0.1")
        open_ports = scanner.scan_ports([])
        self.assertEqual(open_ports, [])

if __name__ == '__main__':
    unittest.main()
