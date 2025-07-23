import unittest
import socket
from unittest.mock import patch, MagicMock
import re # Import re for regex assertions

from marscan.main import parse_port_string, save_results
from marscan.scanner import scan_port, scan_ports

class TestMarScan(unittest.TestCase):

    def test_parse_port_string_single(self):
        self.assertEqual(parse_port_string("80"), [80])

    def test_parse_port_string_list(self):
        self.assertEqual(parse_port_string("22,80,443"), [22, 80, 443])

    def test_parse_port_string_range(self):
        self.assertEqual(parse_port_string("20-25"), [20, 21, 22, 23, 24, 25])

    def test_parse_port_string_mixed(self):
        self.assertEqual(parse_port_string("20-21,80,443"), [20, 21, 80, 443])

    def test_parse_port_string_duplicates(self):
        self.assertEqual(parse_port_string("80,80,22"), [22, 80])

    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.connect_ex.return_value = 0 # 0 indicates success

        self.assertTrue(scan_port("localhost", 80))
        mock_sock_instance.connect_ex.assert_called_with(("localhost", 80))

    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.connect_ex.return_value = 111 # Non-zero indicates failure (e.g., Connection Refused)

        self.assertFalse(scan_port("localhost", 80))
        mock_sock_instance.connect_ex.assert_called_with(("localhost", 80))

    @patch('socket.socket')
    def test_scan_port_exception(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.connect_ex.side_effect = socket.timeout # Simulate a timeout

        self.assertFalse(scan_port("localhost", 80))
        mock_sock_instance.connect_ex.assert_called_with(("localhost", 80))

    @patch('marscan.scanner.scan_port')
    def test_scan_ports(self, mock_scan_port):
        # Mock scan_port to return True for 80 and 443, False for 22
        def mock_side_effect(host, port, timeout):
            if port in [80, 443]:
                return True
            return False
        mock_scan_port.side_effect = mock_side_effect

        host = "localhost"
        ports_to_scan = [22, 80, 443, 8080]
        open_ports = scan_ports(host, ports_to_scan, max_threads=2, timeout=0.1)

        self.assertEqual(open_ports, [80, 443])
        # Ensure scan_port was called for all ports
        expected_calls = [
            unittest.mock.call(host, 22, 0.1),
            unittest.mock.call(host, 80, 0.1),
            unittest.mock.call(host, 443, 0.1),
            unittest.mock.call(host, 8080, 0.1),
        ]
        mock_scan_port.assert_has_calls(expected_calls, any_order=True)

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    @patch('json.dump')
    def test_save_results_json(self, mock_json_dump, mock_open):
        host = "example.com"
        open_ports = [80, 443]
        output_file = "results.json"
        output_format = "json"

        save_results(host, open_ports, output_file, output_format)

        mock_open.assert_called_once_with(output_file, 'w', encoding='utf-8')
        mock_json_dump.assert_called_once_with(
            {"host": host, "open_ports": open_ports, "total_open_ports": len(open_ports), "timestamp": unittest.mock.ANY},
            mock_open(),
            indent=4
        )

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    @patch('csv.writer')
    def test_save_results_csv(self, mock_csv_writer, mock_open):
        mock_writer_instance = MagicMock()
        mock_csv_writer.return_value = mock_writer_instance

        host = "example.com"
        open_ports = [80, 443]
        output_file = "results.csv"
        output_format = "csv"

        save_results(host, open_ports, output_file, output_format)

        mock_open.assert_called_once_with(output_file, 'w', newline='', encoding='utf-8')
        mock_csv_writer.assert_called_once_with(mock_open())
        mock_writer_instance.writerow.assert_has_calls([
            unittest.mock.call(['Host', 'Open Ports', 'Total Open Ports', 'Timestamp']),
            unittest.mock.call([host, '80, 443', len(open_ports), unittest.mock.ANY])
        ])

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_save_results_txt(self, mock_open):
        host = "example.com"
        open_ports = [80, 443]
        output_file = "results.txt"
        output_format = "txt"

        save_results(host, open_ports, output_file, output_format)

        mock_open.assert_called_once_with(output_file, 'w', encoding='utf-8')
        written_content = "".join(call.args[0] for call in mock_open().write.call_args_list)

        expected_content_start = f"--- MarScan Port Scan Results ---\n" \
                                 f"Target Host: {host}\n" \
                                 f"Scan Time: "
        expected_content_end = f"\nTotal Open Ports Found: {len(open_ports)}\n" \
                               f"{'-' * 35}\n" \
                               f"Open Ports: {', '.join(map(str, open_ports))}\n" \
                               f"---------------------------------\n"

        self.assertTrue(written_content.startswith(expected_content_start))
        self.assertTrue(written_content.endswith(expected_content_end))
        timestamp_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}"
        self.assertRegex(written_content, rf"Scan Time: {timestamp_pattern}\n")

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_save_results_txt_no_open_ports(self, mock_open):
        host = "example.com"
        open_ports = []
        output_file = "results.txt"
        output_format = "txt"

        save_results(host, open_ports, output_file, output_format)

        mock_open.assert_called_once_with(output_file, 'w', encoding='utf-8')
        written_content = "".join(call.args[0] for call in mock_open().write.call_args_list)

        expected_content_start = f"--- MarScan Port Scan Results ---\n" \
                                 f"Target Host: {host}\n" \
                                 f"Scan Time: "
        expected_content_end = f"\nTotal Open Ports Found: {len(open_ports)}\n" \
                               f"{'-' * 35}\n" \
                               f"No open ports found in the specified range.\n" \
                               f"---------------------------------\n"

        self.assertTrue(written_content.startswith(expected_content_start))
        self.assertTrue(written_content.endswith(expected_content_end))
        timestamp_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}"
        self.assertRegex(written_content, rf"Scan Time: {timestamp_pattern}\n")

if __name__ == '__main__':
    unittest.main()
