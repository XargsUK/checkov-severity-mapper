"""
Simple logging configuration using standard library logging.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    verbose: bool = False,
    json_logs: bool = False,
    disable_existing_loggers: bool = False,
    no_color: bool = False,
) -> None:
    """
    Configure basic logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to write logs to
        verbose: Enable verbose output
        json_logs: Output logs in JSON format (ignored - simplified)
        disable_existing_loggers: Disable existing loggers
        no_color: Disable colored output (ignored - simplified)
    """
    # Set level based on verbose flag
    if verbose:
        level = "DEBUG"

    # Configure basic logging
    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    # File handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel("DEBUG")  # Always log everything to file
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=level, handlers=handlers, format="%(message)s", datefmt="[%X]", force=True
    )

    # Disable existing loggers if requested
    if disable_existing_loggers:
        logging.getLogger().handlers.clear()

    # Set third-party library log levels to reduce noise
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    # Log initial configuration
    logger = get_logger(__name__)
    logger.info(f"Logging configured - level: {level}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger
    """
    return logging.getLogger(name)


class LoggerMixin:
    """Mixin class to add logging capabilities to any class."""

    @property
    def logger(self) -> logging.Logger:
        """Get logger for this class."""
        if not hasattr(self, "_logger"):
            self._logger = get_logger(
                self.__class__.__module__ + "." + self.__class__.__name__
            )
        return self._logger

    def log_operation(self, operation: str, **kwargs) -> None:
        """Log an operation with context."""
        context = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        msg = f"Starting {operation}"
        if context:
            msg += f" ({context})"
        self.logger.info(msg)

    def log_success(self, operation: str, **kwargs) -> None:
        """Log successful operation completion."""
        context = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        msg = f"Completed {operation}"
        if context:
            msg += f" ({context})"
        self.logger.info(msg)

    def log_error(self, operation: str, error: Exception, **kwargs) -> None:
        """Log operation error."""
        context = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        msg = f"Failed {operation}: {error}"
        if context:
            msg += f" ({context})"
        self.logger.error(msg)

    def log_info(self, message: str, **kwargs) -> None:
        """Log an info message with context."""
        context = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        msg = message
        if context:
            msg += f" ({context})"
        self.logger.info(msg)

    def log_warning(self, message: str, **kwargs) -> None:
        """Log a warning with context."""
        context = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        msg = message
        if context:
            msg += f" ({context})"
        self.logger.warning(msg)
