import logging
from rich.logging import RichHandler

def get_logger(level: int = 0):
    """
    Create and configure a logger with RichHandler.
    
    Args:
        level (int): Verbosity level. 0 for WARNING, 1 for INFO, 2+ for DEBUG.
        
    Returns:
        logging.Logger: A configured logger instance.
    """
    if level == 1:
        log_level = "INFO"
    elif level >= 2:
        log_level = "DEBUG"
    else:
        log_level = "WARNING"

    # Get a specific logger instance
    logger = logging.getLogger("marscan")
    
    # Prevent messages from being passed to the root logger
    logger.propagate = False
    
    # Set the desired level
    logger.setLevel(log_level)

    # Clear existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()

    # Add a RichHandler for beautiful, console-friendly output
    handler = RichHandler(
        rich_tracebacks=True, 
        markup=True,
        show_time=False,  # We can turn this on for more detail if needed
        show_level=True,
        show_path=False
    )
    handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    logger.addHandler(handler)
    
    return logger
