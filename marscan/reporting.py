import json
import csv
from rich.console import Console

console = Console()

def save_results(host: str, port_results: dict[int, str], output_file: str, output_format: str):
    """
    Saves the port scan results to a specified file in the given format.

    Args:
        host (str): The target host that was scanned.
        port_results (dict[int, str]): A dictionary mapping port numbers to their state.
        output_file (str): The path to the output file.
        output_format (str): The desired output format ('txt', 'json', 'csv').
    """
    results_data = {
        "host": host,
        "ports": port_results,
        "total_ports_found": len(port_results),
        "timestamp": console.get_datetime().isoformat()
    }

    try:
        if output_format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=4)
            console.print(f"[bold green]Results successfully saved to[/bold green] [cyan]{output_file}[/cyan] [bold green]in JSON format.[/bold green]")
        elif output_format == 'csv':
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Port', 'State'])
                for port, state in port_results.items():
                    writer.writerow([port, state])
            console.print(f"[bold green]Results successfully saved to[/bold green] [cyan]{output_file}[/cyan] [bold green]in CSV format.[/bold green]")
        elif output_format == 'txt':
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"--- MarScan Port Scan Results ---\n")
                f.write(f"Target Host: {results_data['host']}\n")
                f.write(f"Scan Time: {results_data['timestamp']}\n")
                f.write(f"Total Ports Found: {results_data['total_ports_found']}\n")
                f.write("-" * 35 + "\n")
                if results_data['ports']:
                    for port, state in port_results.items():
                        f.write(f"Port {port}: {state}\n")
                else:
                    f.write("No open or filtered ports found in the specified range.\n")
                f.write("---------------------------------\n")
            console.print(f"[bold green]Results successfully saved to[/bold green] [cyan]{output_file}[/cyan] [bold green]in TXT format.[/bold green]")
        else:
            console.print(f"[bold red]Error:[/bold red] Unsupported output format specified: '{output_format}'.")
    except IOError as e:
        console.print(f"[bold red]Error:[/bold red] Could not write to file '{output_file}': {e}")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred while saving results:[/bold red] {e}")
