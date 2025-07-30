import pyfiglet
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from marscan import __version__

console = Console()

def display_banner():
    """
    Displays a modern, visually appealing banner for MarScan.
    """
    # Generate ASCII banner using a modern font
    ascii_banner = pyfiglet.figlet_format("MarScan", font="ansi_regular")
    
    # Create a Text object for the banner with a bold style
    banner_text = Text(ascii_banner, style="bold cyan", justify="center")

    # Create a tagline with the version number
    tagline = Rule(f"[bold white]v{__version__}[/] | [dim]Your Custom Red Team Port Scanner[/]", style="bold blue")

    # Create the author and links section
    info_text = Text.from_markup(
        "[dim]Author:[/dim] [cyan]Marwan ALkhatib[/cyan] | "
        "[dim]GitHub:[/dim] [link=https://github.com/MarwanKhatib/MarScan]MarScan Repo[/link] | "
        "[dim]X:[/dim] [link=https://x.com/MarwanAl56ib]MarwanAl56ib[/link]",
        justify="center"
    )

    # Group all elements for the panel
    panel_group = Group(
        banner_text,
        tagline,
        info_text
    )

    # Create a single, cohesive panel with a gradient border
    main_panel = Panel(
        panel_group,
        border_style="bold blue",
        padding=(2, 4),
        expand=True
    )

    # Display the final banner
    console.print(main_panel)

