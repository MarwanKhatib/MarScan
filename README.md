# MarScan - A Modern TCP Port Scanner for Red Teamers

[![PyPI - Version](https://img.shields.io/pypi/v/marscan)](https://pypi.org/project/marscan/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub last commit](https://img.shields.io/github/last-commit/MarwanKhatib/MarScan)](https://github.com/MarwanKhatib/MarScan)

**MarScan** is a lightweight, fast, and highly extensible TCP port scanner designed for cybersecurity professionals. It provides fine-grained control over scan behavior and packet structure, enabling red teamers and penetration testers to customize their scans to evade detection by modern firewalls and intrusion detection systems (IDS).

---

## Key Features

- **Multiple Scan Techniques:** Choose from a variety of scan types, from the reliable TCP Connect scan to stealthy FIN, NULL, and XMAS scans designed to bypass firewalls.
- **Advanced Evasion Engine:** Avoid detection with features like decoy IP addresses, randomized port scanning, and scan jitter to mimic normal network traffic.
- **Granular Packet Crafting:** Manually control packet headers, including TTL, TCP window size, and TCP options, to create custom fingerprints and impersonate legitimate applications or operating systems.
- **Evasion Profiles:** Use built-in profiles (`win10`, `linux`, `stealth`) to easily apply complex evasion settings without manual configuration.
- **Rich & Readable Output:** Enjoy a clean, color-coded terminal interface that clearly distinguishes between `open`, `closed`, and `filtered` ports.
- **Flexible Reporting:** Save scan results in multiple formats, including JSON, CSV, or plain text, for easy integration into your workflow.

---

## Installation

MarScan can be installed directly from this repository using `pip`.

```bash
git clone https://github.com/MarwanKhatib/MarScan.git
cd MarScan
pip install .
```

---

## Usage

### Command-Line Options

This table provides a complete reference for all available command-line arguments.

| Flag(s)                       | Description                                                                 | Default      |
| ----------------------------- | --------------------------------------------------------------------------- | ------------ |
| `host`                        | The target host to scan. (Required)                                         | -            |
| `-p`, `--ports`               | Ports to scan (e.g., '80', '22,80', '1-1024').                              | `1-1024`     |
| `-t`, `--threads`             | Number of concurrent threads.                                               | `100`        |
| `-o`, `--timeout`             | Connection timeout in seconds for each probe.                               | `2.5`        |
| `-v`, `-vv`                   | Enable verbose output (`-v` for info, `-vv` for debug).                     | Off          |
| **Scan Techniques**           |                                                                             |              |
| `-sT`, `--tcp-connect-scan`   | Perform a TCP connect scan.                                                 | **Default**  |
| `-sS`, `--syn-scan`           | Perform a SYN stealth scan. (Requires root)                                 | Off          |
| `-sF`, `--fin-scan`           | Perform a FIN scan. (Requires root)                                         | Off          |
| `-sN`, `--null-scan`          | Perform a NULL scan. (Requires root)                                        | Off          |
| `-sX`, `--xmas-scan`          | Perform an XMAS scan. (Requires root)                                       | Off          |
| **Reporting**                 |                                                                             |              |
| `-s`, `--save-to-file`        | Path to save scan results.                                                  | -            |
| `-f`, `--format`              | Output format for saving results.                                           | `txt`        |
| **Evasion Techniques**        |                                                                             |              |
| `--profile`                   | Use a preset evasion profile (`win10`, `linux`, `stealth`).                 | -            |
| `--decoy-ips`                 | Comma-separated list of decoy IP addresses.                                 | -            |
| `--scan-delay`                | Add a fixed delay (in seconds) between probes.                              | `0.0`        |
| `--scan-jitter`               | Add a random delay (up to N seconds) between probes.                        | `0.0`        |
| `--randomize-ports`           | Scan ports in a random order instead of sequentially.                       | Off          |
| **Packet Crafting**           | (For Scapy-based scans like `-sS`, `-sF`, etc.)                             |              |
| `--ttl`                       | Set a custom TTL for outgoing packets.                                      | -            |
| `--tcp-window`                | Set a custom TCP window size.                                               | -            |
| `--tcp-options`               | Set custom TCP options (e.g., `'MSS=1460,SACK'`).                           | -            |

### Examples

- **Basic Connect Scan:**
  ```bash
  marscan example.com -p 1-1024
  ```

- **Standard Stealth (SYN) Scan of all ports:**
  ```bash
  sudo marscan example.com -p- -sS
  ```

- **Firewall Evasion with a FIN Scan:**
  ```bash
  sudo marscan example.com -p 80,443,8080 -sF
  ```

- **Highly Evasive Scan using a Profile:**
  Mimic a Windows 10 host to be less suspicious.
  ```bash
  sudo marscan example.com -p 1-1024 -sS --profile win10
  ```

- **Slow, Evasive Scan with Custom Jitter:**
  Randomize ports and add up to 3 seconds of jitter to avoid behavioral detection.
  ```bash
  sudo marscan example.com -p 1-1024 -sS --randomize-ports --scan-jitter 3
  ```

- **Save results to a JSON file with verbose output:**
  ```bash
  marscan example.com -p 80,443 -o scan_results.json -f json -v
  ```

---

## Scanning Techniques in Depth

Each scanning technique has a unique way of determining a port's status, with different trade-offs between accuracy, stealth, and privileges.

#### 1. TCP Connect Scan (`-sT`)
- **How it Works:** This is the most straightforward scanning method. It uses the operating system's standard networking functions to attempt a full three-way TCP handshake with the target port.
- **Dependencies:** Relies entirely on the host OS. It does not craft raw packets.
- **Use Case:** The most reliable scan for determining if a port is truly open. It's an excellent choice when stealth is not a concern.
- **Privileges:** Does **not** require root privileges.
- **Results:**
    - `open`: The handshake completed successfully.
    - `closed`: The target actively refused the connection (`RST` packet).
    - `filtered`: The connection timed out, indicating a firewall is likely present.

#### 2. TCP SYN Scan (`-sS`)
- **How it Works:** A "half-open" scan. It sends a `SYN` packet, and if it receives a `SYN-ACK` response (indicating the port is open), it immediately sends a `RST` packet to tear down the connection before the handshake is completed.
- **Dependencies:** Requires raw packet crafting via the **Scapy** library.
- **Use Case:** The classic "stealth" scan. Because the full connection is never established, it is often not logged by applications, making it much quieter.
- **Privileges:** **Requires root privileges.**
- **Results:**
    - `open`: The target responded with a `SYN-ACK`.
    - `closed`: The target responded with a `RST-ACK`.
    - `filtered`: No response was received, indicating the packet was likely dropped.

#### 3. FIN (`-sF`), NULL (`-sN`), and XMAS (`-sX`) Scans
These are highly stealthy scans designed to bypass older, stateless firewalls by sending non-standard packets.

- **How they Work:**
    - **FIN Scan (`-sF`):** Sends a packet with only the `FIN` flag.
    - **NULL Scan (`-sN`):** Sends a packet with **no flags**.
    - **XMAS Scan (`-sX`):** Sends a packet with the `FIN`, `PSH`, and `URG` flags.
- **Dependencies:** All three rely on **Scapy** for raw packet crafting.
- **Use Case:** Excellent for evading simple packet-filtering firewalls. A compliant system (per RFC 793) will not respond if the port is open and will send a `RST` if it's closed.
- **Privileges:** **Requires root privileges.**
- **Results:**
    - `open|filtered`: No response was received. The port is either open or a stateful firewall is blocking the probe.
    - `closed`: The target responded with a `RST-ACK`.

---

## Project Architecture

MarScan's architecture is designed to be modular and extensible.
- `marscan/main.py`: The main entry point and CLI argument parser.
- `marscan/scanner/`: Contains the different scan type implementations.
  - `base.py`: The base class for all scanners, handling threading and progress bars.
  - `stealth.py`: A common base class for stealthy scans (FIN, NULL, XMAS).
  - `connect.py`, `syn.py`, etc.: The specific scanner implementations.
- `marscan/utils/`: Contains utility functions for logging, display, and port parsing.
- `marscan/reporting.py`: Handles saving scan results to different file formats.

---

## Contributing
Contributions are welcome! Please feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact
- **Author**: MarwanKhatib
- **GitHub**: [https://github.com/MarwanKhatib/MarScan](https://github.com/MarwanKhatib/MarScan)
- **LinkedIn**: [https://www.linkedin.com/in/marwan-alkhatib-426010323/](https://www.linkedin.com/in/marwan-alkhatib-426010323/)
- **X**: [https://x.com/MarwanAl56ib](https://x.com/MarwanAl56ib)