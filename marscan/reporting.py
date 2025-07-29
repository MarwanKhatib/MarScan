import json
import csv
from rich.console import Console

console = Console()

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
