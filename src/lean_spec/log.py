"""Console logging setup for the lean consensus node CLI."""

from __future__ import annotations

import logging


class ColoredFormatter(logging.Formatter):
    """Logging formatter with ANSI colors for better readability."""

    # ANSI color codes
    GREY = "\x1b[38;5;244m"
    BLUE = "\x1b[38;5;39m"
    GREEN = "\x1b[38;5;40m"
    YELLOW = "\x1b[38;5;220m"
    RED = "\x1b[38;5;196m"
    BOLD_RED = "\x1b[38;5;196;1m"
    CYAN = "\x1b[38;5;51m"
    RESET = "\x1b[0m"

    LEVEL_COLORS = {
        logging.DEBUG: GREY,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD_RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        # Get color for this level
        color = self.LEVEL_COLORS.get(record.levelno, self.RESET)

        # Format timestamp in cyan
        timestamp = self.formatTime(record, self.datefmt)
        colored_time = f"{self.CYAN}{timestamp}{self.RESET}"

        # Format level name with color
        levelname = f"{color}{record.levelname:8}{self.RESET}"

        # Format logger name in blue
        name = f"{self.BLUE}{record.name}{self.RESET}"

        # Format message
        message = record.getMessage()

        return f"{colored_time} {levelname} {name}: {message}"


def setup_logging(verbose: bool = False, no_color: bool = False) -> None:
    """Configure logging for the node with optional colors."""
    level = logging.DEBUG if verbose else logging.INFO

    # Create handler
    handler = logging.StreamHandler()
    handler.setLevel(level)

    # Use colored formatter unless disabled
    if no_color:
        formatter: logging.Formatter = logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        formatter = ColoredFormatter(datefmt="%Y-%m-%d %H:%M:%S")

    handler.setFormatter(formatter)

    # Configure root logger
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)
