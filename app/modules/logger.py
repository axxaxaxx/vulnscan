"""
Logging module for the vulnerability scanner application
"""

import logging
import sys
from datetime import datetime
from typing import Optional

def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        # Set log level
        logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Create file handler
        file_handler = logging.FileHandler('vuln_scanner.log')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        # Prevent duplicate logs
        logger.propagate = False
    
    return logger

def log_scan_event(scan_id: int, event: str, level: str = 'info', details: Optional[dict] = None):
    """
    Log a scan-related event
    
    Args:
        scan_id: Scan ID
        event: Event description
        level: Log level (info, warning, error, critical)
        details: Additional details dictionary
    """
    logger = get_logger('scan_events')
    
    message = f"Scan {scan_id}: {event}"
    if details:
        message += f" - Details: {details}"
    
    if level == 'info':
        logger.info(message)
    elif level == 'warning':
        logger.warning(message)
    elif level == 'error':
        logger.error(message)
    elif level == 'critical':
        logger.critical(message)
    else:
        logger.info(message)

def log_system_event(component: str, event: str, level: str = 'info', details: Optional[dict] = None):
    """
    Log a system-related event
    
    Args:
        component: Component name
        event: Event description
        level: Log level (info, warning, error, critical)
        details: Additional details dictionary
    """
    logger = get_logger('system_events')
    
    message = f"{component}: {event}"
    if details:
        message += f" - Details: {details}"
    
    if level == 'info':
        logger.info(message)
    elif level == 'warning':
        logger.warning(message)
    elif level == 'error':
        logger.error(message)
    elif level == 'critical':
        logger.critical(message)
    else:
        logger.info(message)
