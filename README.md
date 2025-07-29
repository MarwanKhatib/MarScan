# MarScan

[![PyPI - Version](https://img.shields.io/pypi/v/marscan)](https://pypi.org/project/marscan/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub last commit](https://img.shields.io/github/last-commit/MarwanKhatib/MarScan)](https://github.com/MarwanKhatib/MarScan)

A blazing-fast, lightweight, and highly extensible TCP port scanner built with Python. MarScan is designed for ethical hackers, penetration testers, and network security professionals who require a reliable and efficient tool for identifying open ports on target hosts.

## Features

- **Concurrent Scanning**: Utilizes multithreading to scan multiple ports simultaneously, significantly speeding up the scanning process.
- **Flexible Port Specification**: Scan single ports, comma-separated lists of ports, or port ranges.
- **Customizable Performance**: Adjust the number of concurrent threads and connection timeout to optimize scans for different network conditions and resource availability.
- **Rich Command-Line Interface**: A modern and colorful terminal output powered by the `rich` library, providing clear and professional feedback.
- **Output Options**: Save scan results to various formats including plain text (`.txt`), JSON (`.json`), and CSV (`.csv`) for easy integration with other tools or reporting.
- **Modular Design**: Clean and well-documented codebase, making it easy to understand, extend, and integrate new features.

## Installation

To get started with MarScan, first clone the repository:

```bash
git clone https://github.com/MarwanKhatib/MarScan.git
cd MarScan
```

Then, install the package using `pip`:

```bash
pip install .
```

## Quick Start

After installation, you can quickly scan a target host for common ports (1-1024) with a single command:

```bash
marscan example.com
```

For more advanced usage and options, refer to the "Usage" section below.

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

- **Perform a SYN stealth scan (requires root privileges):**

  ```bash
  sudo marscan example.com -sS
  ```

- **Perform a TCP connect scan:**

  ```bash
  marscan example.com -sT
  ```

- **Use decoy IP addresses:**

  ```bash
  marscan example.com --decoy-ips 192.168.1.100,10.0.0.5
  ```

- **Add a scan delay:**

  ```bash
  marscan example.com --scan-delay 0.1
  ```

- **Enable verbose output:**

  ```bash
  marscan example.com -v
  ```

- **Enable very verbose (debugging) output:**

  ```bash
  marscan example.com -vv
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

## Contributing

Contributions are welcome! Please refer to the GitHub repository for guidelines.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

- **Author**: MarwanKhatib
- **GitHub**: [https://github.com/MarwanKhatib/MarScan](https://github.com/MarwanKhatib/MarScan)
- **LinkedIn**: [https://www.linkedin.com/in/marwan-alkhatib-426010323/](https://www.linkedin.com/in/marwan-alkhatib-426010323/)
- **X**: [https://x.com/MarwanAl56ib](https://x.com/MarwanAl56ib)
