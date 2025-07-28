"""
MarScan - A blazing-fast, lightweight Python port scanner.

This module provides the command-line interface for MarScan, handling argument parsing,
orchestrating the port scanning process, and managing output display and saving.
"""

import argparse
import json
import csv
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.traceback import install
from rich.table import Table # Import Table for structured output
import socket # Import socket for service name lookup

# Local imports from the MarScan package
from marscan.scanner import ConnectScan, SynScan, AckScan, UdpScan, FinScan, XmasScan
from marscan.utils import display_banner

# Install Rich traceback handler for better error reporting, showing local variables on error
install(show_locals=True)
console = Console()

def parse_port_string(port_string: str) -> list[int]:
    """
    Parses a string of ports into a sorted list of unique integers.

    The string can contain single ports (e.g., '80'), comma-separated lists
    (e.g., '22,80,443'), or ranges (e.g., '1-1024').
    Invalid port numbers (e.g., non-integers, out of range 0-65535) are ignored.

    Args:
        port_string (str): The string representation of ports.

    Returns:
        list[int]: A sorted list of unique and valid port numbers.
    """
    ports = set()
    parts = port_string.split(',')

    for part in parts:
        try:
            if '-' in part:
                start_str, end_str = part.split('-')
                start, end = int(start_str), int(end_str)
                # Ensure ports are within valid range and start <= end
                if 0 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
                else:
                    console.print(f"[bold red]Warning:[/bold red] Invalid port range '{part}'. Ports must be between 0 and 65535.")
            else:
                port = int(part)
                # Ensure port is within valid range
                if 0 <= port <= 65535:
                    ports.add(port)
                else:
                    console.print(f"[bold red]Warning:[/bold red] Invalid port '{part}'. Port must be between 0 and 65535.")
        except ValueError:
            console.print(f"[bold red]Warning:[/bold red] Skipping invalid port format: '{part}'.")
    return sorted(list(ports))

def save_results(host: str, open_ports: list[int], output_file: str, output_format: str):
    """
    Saves the port scan results to a specified file in the given format.

    Args:
        host (str): The target host that was scanned.
        open_ports (list[int]): A list of open port numbers found.
        output_file (str): The path to the output file.
        output_format (str): The desired output format ('txt', 'json', 'csv').
    """
    results_data = {
        "host": host,
        "open_ports": open_ports,
        "total_open_ports": len(open_ports),
        "timestamp": console.get_datetime().isoformat() # Add timestamp for professionalism
    }

    try:
        if output_format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=4)
            console.print(f"[bold green]Results successfully saved to[/bold green] [cyan]{output_file}[/cyan] [bold green]in JSON format.[/bold green]")
        elif output_format == 'csv':
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Host', 'Open Ports', 'Total Open Ports', 'Timestamp'])
                writer.writerow([
                    results_data['host'],
                    ', '.join(map(str, results_data['open_ports'])),
                    results_data['total_open_ports'],
                    results_data['timestamp']
                ])
            console.print(f"[bold green]Results successfully saved to[/bold green] [cyan]{output_file}[/cyan] [bold green]in CSV format.[/bold green]")
        elif output_format == 'txt':
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"--- MarScan Port Scan Results ---\n")
                f.write(f"Target Host: {results_data['host']}\n")
                f.write(f"Scan Time: {results_data['timestamp']}\n")
                f.write(f"Total Open Ports Found: {results_data['total_open_ports']}\n")
                f.write("-" * 35 + "\n")
                if results_data['open_ports']:
                    f.write(f"Open Ports: {', '.join(map(str, results_data['open_ports']))}\n")
                else:
                    f.write("No open ports found in the specified range.\n")
                f.write("---------------------------------\n")
            console.print(f"[bold green]Results successfully saved to[/bold green] [cyan]{output_file}[/cyan] [bold green]in TXT format.[/bold green]")
        else:
            console.print(f"[bold red]Error:[/bold red] Unsupported output format specified: '{output_format}'.")
    except IOError as e:
        console.print(f"[bold red]Error:[/bold red] Could not write to file '{output_file}': {e}")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred while saving results:[/bold red] {e}")

def main():
    """
    Main entry point for the MarScan command-line application.

    Parses command-line arguments, displays a professional banner,
    initiates the port scanning process, and presents the results
    to the user, with an option to save them to a file.
    """
    parser = argparse.ArgumentParser(
        description="MarScan - A blazing-fast, lightweight Python port scanner for ethical hackers and red teamers.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('host', help="The target host (IP address or domain name) to scan.")
    parser.add_argument('-p', '--ports',
                        help="""Ports to scan. Can be a single port (e.g., '80'),
a comma-separated list (e.g., '22,80,443'), or a range (e.g., '1-1024').
Use '-p-' to scan all 65536 ports (0-65535).
If not specified, scans common well-known ports (1-1024).""")
    parser.add_argument('-t', '--threads', type=int, default=100,
                        help="""Number of concurrent threads to use for scanning.
A higher number can speed up scans but may consume more CPU/memory.
Adjust based on your system's capabilities and network conditions.
Default: 100.""")
    parser.add_argument('-o', '--timeout', type=float, default=1.0,
                        help="""Connection timeout in seconds for each port attempt.
Lower values make scans faster but might miss ports on slow networks.
Default: 1.0.""")
    parser.add_argument('-s', '--save-to-file', dest='output_file',
                        help="""Path to a file where scan results will be saved.
If not specified, results are only printed to the console.""")
    parser.add_argument('-f', '--format', choices=['txt', 'json', 'csv'], default='txt',
                        help="""Output format for saving results.
Choices: 'txt' (plain text), 'json' (JSON format), 'csv' (CSV format).
This option is only used if '--save-to-file' is specified.
Default: 'txt'.""")
    parser.add_argument('-sT', '--scan-type', choices=['connect', 'syn', 'ack', 'udp', 'fin', 'xmas'], default='connect',
                        help="""Type of scan to perform.
Choices: 'connect' (TCP Connect), 'syn' (TCP SYN/Half-open),
'ack' (TCP ACK), 'udp' (UDP Scan), 'fin' (TCP FIN), 'xmas' (TCP Xmas).
Default: 'connect'.""")

    args = parser.parse_args()

    display_banner()

    if args.ports == '-':
        ports_to_scan = list(range(0, 65536)) # Scan all ports from 0 to 65535
        console.print("[bold yellow]Scanning all 65536 ports (0-65535) as requested by '-p-'.[/bold yellow]")
    elif args.ports:
        ports_to_scan = parse_port_string(args.ports)
    else:
        # Default behavior: scan common well-known ports (1-1024)
        ports_to_scan = parse_port_string('1-1024')
        console.print("[bold yellow]No specific ports provided. Scanning common well-known ports (1-1024) by default.[/bold yellow]")
    
    if not ports_to_scan:
        console.print("[bold red]Error:[/bold red] No valid ports to scan after parsing. Exiting.")
        sys.exit(1)

    # Determine scan class based on argument
    scan_class_map = {
        'connect': ConnectScan,
        'syn': SynScan,
        'ack': AckScan,
        'udp': UdpScan,
        'fin': FinScan,
        'xmas': XmasScan,
    }
    
    ScanClass = scan_class_map.get(args.scan_type)
    if not ScanClass:
        console.print(f"[bold red]Error:[/bold red] Invalid scan type '{args.scan_type}'. Exiting.")
        sys.exit(1)

    scanner = ScanClass(host=args.host, timeout=args.timeout)

    # Log scan initiation with detailed parameters
    console.print(
        f"[bold green]Initiating {args.scan_type.upper()} scan on[/bold green] [cyan]{args.host}[/cyan] "
        f"for ports: [yellow]{ports_to_scan[0]}-{ports_to_scan[-1]}[/yellow] "
        f"([magenta]{len(ports_to_scan)}[/magenta] ports) "
        f"using [purple]{args.threads}[/purple] concurrent threads "
        f"with a [red]{args.timeout}[/red]s timeout per port."
    )

    # Perform the port scan
    open_ports = scanner.scan_ports(ports_to_scan, max_threads=args.threads)

    # Display scan results in a table format
    if open_ports:
        console.print(Panel(
            Text.from_markup(f"[bold green]Scan Complete: Open ports found on {args.host} ({args.scan_type.upper()} Scan)[/bold green]"),
            border_style="green"
        ))

        table = Table(title=f"Open Ports on {args.host}", style="bold blue")
        table.add_column("PORT", justify="right", style="cyan", no_wrap=True)
        table.add_column("STATE", justify="left", style="green")
        table.add_column("SERVICE", justify="left", style="magenta")
        table.add_column("VERSION", justify="left", style="yellow") # Version column, intentionally left empty

        for port in open_ports:
            service_name = "unknown"
            try:
                service_name = socket.getservbyport(port)
            except OSError:
                pass # Service not found in common services file

            table.add_row(str(port), "open", service_name, "") # Empty string for version as requested
        
        console.print(table)
    else:
        console.print(Panel(
            Text.from_markup(
                f"[bold red]Scan Complete: No open ports found on {args.host} in the specified range.[/bold red]"
            ),
            border_style="red"
        ))

    # Save results if an output file is specified
    if args.output_file:
        save_results(args.host, open_ports, args.output_file, args.format)

if __name__ == '__main__':
    main()
