"""Structured logging for emltriage."""

import logging
import sys
from typing import Optional

import structlog
from structlog.stdlib import LoggerFactory


def configure_logging(
    level: int = logging.INFO,
    json_format: bool = False,
    log_file: Optional[str] = None
) -> None:
    """Configure structured logging.
    
    Args:
        level: Logging level
        json_format: Use JSON formatting
        log_file: Optional file to log to
    """
    # Configure standard library logging
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        format="%(message)s",
        level=level,
        handlers=handlers,
    )
    
    # Configure structlog
    shared_processors = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.UnicodeDecoder(),
    ]
    
    if json_format:
        shared_processors.append(structlog.processors.JSONRenderer())
    else:
        shared_processors.append(structlog.dev.ConsoleRenderer())
    
    structlog.configure(
        processors=shared_processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=LoggerFactory(),
    )


def get_logger(name: str):
    """Get a structured logger.
    
    Args:
        name: Logger name
        
    Returns:
        Structlog logger instance
    """
    return structlog.get_logger(name)
