# MarScan

A blazing-fast, lightweight, and highly extensible TCP port scanner built with Python. MarScan is designed for ethical hackers, penetration testers, and network security professionals who require a reliable and efficient tool for identifying open ports on target hosts.

## Features

- **Concurrent Scanning**: Utilizes multithreading to scan multiple ports simultaneously, significantly speeding up the scanning process.
- **Flexible Port Specification**: Scan single ports, comma-separated lists of ports, or port ranges.
- **Customizable Performance**: Adjust the number of concurrent threads and connection timeout to optimize scans for different network conditions and resource availability.
- **Rich Command-Line Interface**: A modern and colorful terminal output powered by the `rich` library, providing clear and professional feedback.
- **Output Options**: Save scan results to various formats including plain text (`.txt`), JSON (`.json`), and CSV (`.csv`) for easy integration with other tools or reporting.
- **Modular Design**: Clean and well-documented codebase, making it easy to understand, extend, and integrate new features.

## Installation

MarScan can be easily installed using `pip`:

```bash
pip install .
```

## Usage

Once installed, you can run MarScan directly from your terminal:

```bash
marscan <host> [options]
```

### Examples:

- **Scan common ports (1-1024) on a target host:**

  ```bash
  marscan example.com
  ```

- **Scan specific ports:**

  ```bash
  marscan example.com -p 22,80,443,8080
  ```

- **Scan a range of ports:**

  ```bash
  marscan example.com -p 1-65535
  ```

- **Adjust concurrency and timeout:**

  ```bash
  marscan example.com -t 200 -o 0.5
  ```

  (Scans with 200 threads and a 0.5-second timeout per connection)

- **Save results to a JSON file:**

  ```bash
  marscan example.com -p 80,443 -s scan_results.json -f json
  ```

- **Save results to a CSV file:**

  ```bash
  marscan example.com -s open_ports.csv -f csv
  ```

- **Save results to a plain text file:**
  ```bash
  marscan example.com -s report.txt -f txt
  ```

## Future Enhancements

MarScan is designed for extensibility. Potential future features include:

- **Service Detection**: Identify the specific service running on open ports (e.g., HTTP, SSH, FTP).
- **OS Detection**: Attempt to identify the operating system of the target host.
- **Stealth Scans**: Implement different scan types like SYN scan (half-open scan) for less detectable operations.
- **Banner Grabbing**: Extract banner information from open ports for more detailed service identification.
- **IPv6 Support**: Extend scanning capabilities to IPv6 addresses.
- **Proxy Support**: Add support for scanning through SOCKS5 or HTTP proxies.
- **Performance Optimization**: Explore asynchronous I/O (`asyncio`) for even faster scans.
- **Port Status Differentiation**: Distinguish between "closed" and "filtered" ports for more accurate results.

## Contributing

Contributions are welcome! Please refer to the GitHub repository for guidelines.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

- **Author**: MarwanKhatib
- **GitHub**: [https://github.com/MarwanKhatib/MarScan](https://github.com/MarwanKhatib/MarScan)
- **LinkedIn**: [https://www.linkedin.com/in/marwan-alkhatib-426010323/](marwan-alkhatib)
- **X**: [https://x.com/MarwanAl56ib](MarwanAl56ib)
