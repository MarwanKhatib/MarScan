# MarScan - Your Custom Red Team Port Scanner

[![PyPI - Version](https://img.shields.io/pypi/v/marscan)](https://pypi.org/project/marscan/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub last commit](https://img.shields.io/github/last-commit/MarwanKhatib/MarScan)](https://github.com/MarwanKhatib/MarScan)

MarScan is a blazing-fast, lightweight, and highly extensible TCP port scanner built in Python. Originally a simple scanner, it has been evolved into a powerful tool for red teamers and penetration testers who need to **customize their scans to evade detection**.

By controlling every aspect of the packets you send, you can avoid the default fingerprints of common tools like Nmap and blend in with normal network traffic.

## Red Team Evasion Features

MarScan's power comes from its deep customization options, allowing you to control the trade-off between speed, stealth, and accuracy.

#### 1. Multiple Scan Techniques
Choose the right scan for the job. While `-sT` is reliable, stealth scans are better at slipping past firewalls.
- **TCP Connect Scan (`-sT`)**: Default, reliable, and noisy.
- **SYN Scan (`-sS`)**: The classic "stealth" scan. Often not logged by older systems.
- **FIN Scan (`-sF`)**: Can bypass simple, stateless firewalls.
- **NULL Scan (`-sN`)**: Even stealthier; sends packets with no flags.
- **XMAS Scan (`-sX`)**: Sets FIN, PSH, URG flags. Another classic firewall evasion technique.

#### 2. Advanced Scan Behavior
Avoid predictable, robotic scanning patterns that are easily flagged by behavioral analysis.
- **Randomize Port Order (`--randomize-ports`)**: Scan ports in a shuffled order instead of sequentially.
- **Scan Jitter (`--scan-jitter`)**: Use a *random* delay between probes instead of a fixed one, making your scan less predictable.

#### 3. Granular Packet Crafting
This is the core of fingerprint evasion. Modify the headers of your packets to mimic legitimate applications or different operating systems. (Note: These options apply to Scapy-based scans like `-sS`, `-sF`, etc.)
- **Set TTL (`--ttl`)**: Different OSes use different default Time-To-Live values.
- **Set TCP Window Size (`--tcp-window`)**: Another key OS fingerprinting indicator.
- **Set TCP Options (`--tcp-options`)**: Craft the exact TCP options (e.g., `MSS`, `SACK`, `WScale`) to match a specific browser or application.

#### 4. Evasion Profiles (`--profile`)
To make evasion easier, MarScan includes preset profiles that bundle common packet crafting settings. Instead of setting the TTL, window size, and options manually, you can use a single profile.

- **`win10`**: Mimics the network fingerprint of a standard Windows 10 machine.
- **`linux`**: Mimics a common Linux kernel fingerprint.
- **`stealth`**: A generic stealth profile that uses jitter and random port ordering to be less predictable.

## Installation

```bash
git clone https://github.com/MarwanKhatib/MarScan.git
cd MarScan
pip install .
```

## Usage

Run MarScan directly from your terminal:
```bash
marscan <host> [options]
```

### Red Team Scenarios & Examples

- **Default, Noisy Scan (Fastest):**
  ```bash
  marscan example.com -p 1-1024
  ```

- **Standard Stealth Scan (SYN):**
  ```bash
  sudo marscan example.com -p- -sS
  ```

- **Firewall Evasion Scan (FIN):**
  This is often effective against simple packet-filtering firewalls.
  ```bash
  sudo marscan example.com -p 80,443,8080 -sF
  ```

- **Highly Evasive, Slow Scan:**
  This example randomizes ports, adds up to 3 seconds of jitter, and sets a custom TTL to mimic a common Windows host.
  ```bash
  sudo marscan example.com -p 1-1024 -sS --randomize-ports --scan-jitter 3 --ttl 128
  ```

- **Custom Packet Crafting:**
  Mimic a specific application by setting the TCP window and options.
  ```bash
  sudo marscan example.com -p 443 -sS --tcp-window 65535 --tcp-options "MSS=1460,SACK,WScale=8"
  ```

- **Evasion using a Profile:**
  This is the easiest way to mimic a common OS. This example uses the Windows 10 profile.
  ```bash
  sudo marscan example.com -p 1-1024 -sS --profile win10
  ```

- **Save results to a JSON file with verbose output:**
  ```bash
  marscan example.com -p 80,443 -o scan_results.json -f json -v
  ```

## Project Architecture

MarScan's architecture is designed to be modular and extensible.
- `marscan/main.py`: The main entry point for the CLI.
- `marscan/scanner/`: Contains the different scan type implementations.
  - `base.py`: The base class for all scanners.
  - `stealth.py`: A common base class for stealthy scans (FIN, NULL, XMAS).
  - `connect.py`, `syn.py`, `fin.py`, etc.: The specific scanner implementations.
- `marscan/utils/`: Contains utility functions for logging, display, and port parsing.
- `marscan/reporting.py`: Handles saving scan results to different file formats.

## Contributing
Contributions are welcome! Please feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact
- **Author**: MarwanKhatib
- **GitHub**: [https://github.com/MarwanKhatib/MarScan](https://github.com/MarwanKhatib/MarScan)
- **LinkedIn**: [https://www.linkedin.com/in/marwan-alkhatib-426010323/](https://www.linkedin.com/in/marwan-alkhatib-426010323/)
- **X**: [https://x.com/MarwanAl56ib](https://x.com/MarwanAl56ib)
