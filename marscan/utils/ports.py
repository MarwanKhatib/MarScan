from rich.console import Console

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
                if 0 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
                else:
                    console.print(f"[bold red]Warning:[/bold red] Invalid port range '{part}'. Ports must be between 0 and 65535.")
            else:
                port = int(part)
                if 0 <= port <= 65535:
                    ports.add(port)
                else:
                    console.print(f"[bold red]Warning:[/bold red] Invalid port '{part}'. Port must be between 0 and 65535.")
        except ValueError:
            console.print(f"[bold red]Warning:[/bold red] Skipping invalid port format: '{part}'.")
    return sorted(list(ports))
