import argparse
import sys
import time
import socket
import os

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.traceback import install
from rich_argparse import RichHelpFormatter
from rich.table import Table

from marscan.scanner import (
    SynScan, ConnectScan, FinScan, NullScan, XmasScan
)
from marscan.utils import display_banner, get_logger, parse_port_string
from marscan.reporting import save_results

from rich_argparse import RichHelpFormatter

install(show_locals=True)
console = Console()

class CustomHelpFormatter(RichHelpFormatter):
    """Custom help formatter for a more professional and organized look."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.styles["argparse.groups"] = "bold cyan"
        self.styles["argparse.help"] = "default"
        self.styles["argparse.args"] = "bold"
        self.highlights.append(r"(?P<syntax>'(?:[^']|\')*')")

    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = '' # Remove the 'usage: ' prefix
        super().add_usage(usage, actions, groups, prefix)

def main():
    """
    Main entry point for the MarScan command-line application.
    """
    parser = argparse.ArgumentParser(
        description="MarScan - A blazing-fast, lightweight Python port scanner.",
        formatter_class=CustomHelpFormatter,
        conflict_handler='resolve' # Allow overriding default --help
    )
    
    # Core arguments
    core_group = parser.add_argument_group('Core Options')
    core_group.add_argument('host', help="The target host to scan.")
    core_group.add_argument('-p', '--ports',
                        help="Ports to scan (e.g., '80', '22,80,443', '1-1024', '-p-'). Defaults to 1-1024.")
    core_group.add_argument('-t', '--threads', type=int, default=100,
                        help="Number of concurrent threads. Default: 100.")
    core_group.add_argument('-o', '--timeout', type=float, default=2.5,
                        help="Connection timeout in seconds. Default: 2.5.")
    core_group.add_argument('-v', '--verbose', action='count', default=0,
                        help="Enable verbose output (-v for info, -vv for debug).")

    # Scan type arguments
    scan_group = parser.add_argument_group('Scan Techniques')
    scan_group.add_argument('-sT', '--tcp-connect-scan', action='store_true',
                        help="Perform a TCP connect scan (default).")
    scan_group.add_argument('-sS', '--syn-scan', action='store_true',
                        help="Perform a SYN stealth scan (requires root privileges).")
    scan_group.add_argument('-sF', '--fin-scan', action='store_true',
                        help="Perform a FIN scan (stealthy, may bypass firewalls).")
    scan_group.add_argument('-sN', '--null-scan', action='store_true',
                        help="Perform a NULL scan (stealthy, may bypass firewalls).")
    scan_group.add_argument('-sX', '--xmas-scan', action='store_true',
                        help="Perform an XMAS scan (stealthy, may bypass firewalls).")

    # Reporting arguments
    reporting_group = parser.add_argument_group('Reporting')
    reporting_group.add_argument('-s', '--save-to-file', dest='output_file',
                        help="Path to save scan results.")
    reporting_group.add_argument('-f', '--format', choices=['txt', 'json', 'csv'], default='txt',
                        help="Output format for saving results. Default: 'txt'.")

    # Evasion arguments
    evasion_group = parser.add_argument_group('Evasion Techniques')
    evasion_group.add_argument('--profile', choices=['win10', 'linux', 'stealth'],
                        help="Use a preset evasion profile. Overridden by specific options.")
    evasion_group.add_argument('--decoy-ips', type=str,
                        help="Comma-separated list of decoy IP addresses.")
    evasion_group.add_argument('--scan-delay', type=float,
                        help="Add a fixed delay in seconds between probes.")
    evasion_group.add_argument('--scan-jitter', type=float,
                        help="Add a random delay (up to N seconds) between probes. Overrides --scan-delay.")
    evasion_group.add_argument('--randomize-ports', action='store_true',
                        help="Scan ports in a random order instead of sequentially.")
    
    packet_group = parser.add_argument_group('Packet Crafting (for Scapy-based scans)')
    packet_group.add_argument('--ttl', type=int, help="Set a custom TTL for outgoing packets.")
    packet_group.add_argument('--tcp-window', type=int, help="Set a custom TCP window size.")
    packet_group.add_argument('--tcp-options', type=str, help="Set custom TCP options. E.g., 'MSS=1460,SACK,WScale=10'")


    args = parser.parse_args()

    display_banner()

    # --- Profile Application ---
    profiles = {
        'win10': {
            'ttl': 128,
            'tcp_window': 65535,
            'tcp_options': 'MSS=1460,SACK,WScale=8',
        },
        'linux': {
            'ttl': 64,
            'tcp_window': 5840,
            'tcp_options': 'MSS=1460,SACK,WScale=7',
        },
        'stealth': {
            'scan_jitter': 2.5,
            'randomize_ports': True,
            'ttl': 64
        }
    }

    if args.profile:
        profile_settings = profiles[args.profile]
        for key, value in profile_settings.items():
            # Only set the profile value if the user hasn't provided an explicit argument
            if getattr(args, key) is None or getattr(args, key) is False or getattr(args, key) == 0.0:
                setattr(args, key, value)
    
    logger = get_logger(args.verbose)

    if args.ports == '-':
        ports_to_scan = list(range(0, 65536))
        logger.info("Scanning all 65536 ports (0-65535).")
    elif args.ports:
        ports_to_scan = parse_port_string(args.ports)
    else:
        ports_to_scan = parse_port_string('1-1024')
        logger.info("No ports specified. Scanning common ports (1-1024) by default.")
    
    if not ports_to_scan:
        console.print("[bold red]Error:[/bold red] No valid ports to scan. Exiting.")
        sys.exit(1)

    if args.randomize_ports:
        import random
        # Check if it was already shuffled by a profile
        if not (args.profile and 'randomize_ports' in profiles[args.profile]):
             random.shuffle(ports_to_scan)
        logger.info("Port scan order has been randomized.")

    # Determine scan type
    scan_map = {
        'syn': ('syn_scan', SynScan),
        'connect': ('tcp_connect_scan', ConnectScan),
        'fin': ('fin_scan', FinScan),
        'null': ('null_scan', NullScan),
        'xmas': ('xmas_scan', XmasScan),
    }
    
    selected_scans = [name for name, (attr, _) in scan_map.items() if getattr(args, attr)]
    
    if len(selected_scans) > 1:
        console.print(f"[bold red]Error:[/bold red] Multiple scan types specified ({', '.join(selected_scans)}). Please choose only one.")
        sys.exit(1)
    
    if not selected_scans:
        scan_type = 'connect' # Default scan
    else:
        scan_type = selected_scans[0]

    # Check for root privileges if required by the scan type
    if scan_type in ['syn', 'fin', 'null', 'xmas']:
        if os.geteuid() != 0:
            console.print("[bold red]Error:[/bold red] This scan type requires root privileges. Please run with 'sudo'.")
            sys.exit(1)

    ScanClass = scan_map[scan_type][1]

    decoy_ips_list = [ip.strip() for ip in args.decoy_ips.split(',')] if args.decoy_ips else []

    # Parse TCP options string into a list of tuples
    tcp_options_list = []
    if args.tcp_options:
        if isinstance(args.tcp_options, str):
            try:
                for opt in args.tcp_options.split(','):
                    if '=' in opt:
                        key, value = opt.split('=', 1)
                        tcp_options_list.append((key, int(value)))
                    else:
                        tcp_options_list.append((opt, ''))
            except ValueError:
                console.print(f"[bold red]Error:[/bold red] Invalid TCP options format. Use 'Key=Value,Key' format. Exiting.")
                sys.exit(1)
        elif isinstance(args.tcp_options, list):
            tcp_options_list = args.tcp_options

    # --- Display Scan Configuration ---
    port_range_str = f"{ports_to_scan[0]}-{ports_to_scan[-1]}" if len(ports_to_scan) > 1 else str(ports_to_scan[0])
    
    config_lines = [
        f"[bold]Host:[/bold] [cyan]{args.host}[/cyan]",
        f"[bold]Ports:[/bold] [yellow]{port_range_str}[/yellow] ({len(ports_to_scan)} ports)",
        f"[bold]Scan Type:[/bold] [magenta]{scan_type.upper()} Scan[/magenta]",
        f"[bold]Threads:[/bold] {args.threads}",
        f"[bold]Timeout:[/bold] {args.timeout}s"
    ]
    
    if args.profile:
        config_lines.append(f"[bold]Profile:[/bold] [yellow]{args.profile}[/yellow]")
    if decoy_ips_list:
        config_lines.append(f"[bold]Decoys:[/bold] {len(decoy_ips_list)} IP(s)")

    config_string = "\n".join(config_lines)
    
    console.print(Panel(config_string, title="[bold blue]Scan Configuration[/bold blue]", border_style="blue", expand=False))


    scanner = ScanClass(
        host=args.host, 
        timeout=args.timeout, 
        decoy_ips=decoy_ips_list, 
        scan_delay=args.scan_delay if args.scan_delay is not None else 0.0,
        scan_jitter=args.scan_jitter if args.scan_jitter is not None else 0.0,
        verbose=args.verbose,
        ttl=args.ttl,
        tcp_window=args.tcp_window,
        tcp_options=tcp_options_list
    )

    start_time = time.time()
    port_results = scanner.scan_ports(ports_to_scan, max_threads=args.threads)
    duration = time.time() - start_time

    if port_results:
        table = Table(title=f"Open Ports on {args.host}", style="bold blue", show_header=True, header_style="bold magenta")
        table.add_column("PORT", justify="right", style="cyan", no_wrap=True)
        table.add_column("STATE", justify="left", style="green")
        table.add_column("SERVICE", justify="left", style="yellow")

        for port, state in port_results.items():
            service_name = "unknown"
            try:
                service_name = socket.getservbyport(port)
            except (OSError, socket.error):
                pass
            
            # Color-code the state for better readability
            if state == 'open':
                state_color = "bold green"
            elif state == 'filtered':
                state_color = "bold yellow"
            elif state == 'open|filtered':
                state_color = "bold orange3"
            else:
                state_color = "default"

            table.add_row(str(port), f"[{state_color}]{state}[/{state_color}]", service_name)
        
        console.print(table)
    else:
        console.print(Panel(
            Text(f"Scan Complete: No open ports found on {args.host}.", justify="center", style="bold red"),
            border_style="red"
        ))
    
    console.print(f"[bold green]Scan finished in[/bold green] [cyan]{duration:.2f}[/cyan] [bold green]seconds.[/bold green]")

    if args.output_file:
        save_results(args.host, port_results, args.output_file, args.format)

if __name__ == '__main__':
    main()