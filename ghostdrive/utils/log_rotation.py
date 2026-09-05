"""
log_rotation.py -- Maintenance utilities for log files and log rotation.
"""

import logging
import logging.handlers
from pathlib import Path

logger = logging.getLogger(__name__)
LOG_FILE = Path("ghostdrive.log")

def get_log_size() -> int:
    """Returns size of the active log file in bytes."""
    if LOG_FILE.exists():
        return LOG_FILE.stat().st_size
    return 0

def clear_logs() -> None:
    """Purges the active log file."""
    try:
        if LOG_FILE.exists():
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.truncate(0)
    except Exception as e:
        logger.error("Failed to clear log file: %s", e)

def force_rotation() -> None:
    """Manually triggers log rollover on all RotatingFileHandlers."""
    root_logger = logging.getLogger()
    for h in root_logger.handlers:
        if isinstance(h, logging.handlers.RotatingFileHandler):
            try:
                h.doRollover()
                logger.info("Log rotation rolled over successfully.")
            except Exception as e:
                logger.error("Failed to trigger log rollover: %s", e)

def set_max_log_size(max_bytes: int) -> None:
    """Configures maxBytes on any active RotatingFileHandler in the logging system."""
    root_logger = logging.getLogger()
    for h in root_logger.handlers:
        if isinstance(h, logging.handlers.RotatingFileHandler):
            h.maxBytes = max_bytes
            logger.info("Updated max bytes size of file logger to %d bytes.", max_bytes)
