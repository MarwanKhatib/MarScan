import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

console = Console()

def display_banner():
    """
    Displays a centered and professional banner for the MarScan tool.
    """
    # Generate ASCII banner
    ascii_banner = pyfiglet.figlet_format("MarScan", font="slant")  # better height-to-width ratio

    # Wrap ASCII banner in a Rich Text block
    ascii_text = Text(ascii_banner, style="bold blue")
    ascii_panel = Panel(
        Align.center(ascii_text),
        border_style="blue",
        padding=(1, 2),
    )

    # Build tool info panel with Rich markup
    info_text = Text.from_markup(
        "[bold white]A blazing-fast, lightweight Python port scanner.[/bold white]\n\n"
        "[dim]Author:[/dim] [cyan]Marwan ALkhatib[/cyan]\n"
        "[dim]GitHub:[/dim] [link=https://github.com/MarwanKhatib/MarScan]github.com/MarwanKhatib/MarScan[/link]\n"
        "[dim]LinkedIn:[/dim] [link=https://www.linkedin.com/in/marwan-alkhatib-426010323/]Marwan Alkhatib[/link]\n"
        "[dim]X:[/dim] [link=https://x.com/MarwanAl56ib]MarwanAl56ib[/link]"
    )
    info_panel = Panel(
        Align.center(info_text),
        border_style="cyan",
        padding=(1, 4),
    )

    # Display both panels
    console.print(ascii_panel)
    console.print(info_panel)

# Example usage
if __name__ == "__main__":
    display_banner()
