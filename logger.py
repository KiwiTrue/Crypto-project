import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional
import os

class SecurityLogger:
    def __init__(self, name: str, log_dir: str = "logs"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Rotating file handler (10MB per file, max 5 files)
        log_file = os.path.join(log_dir, f'security_{name}_{datetime.now().strftime("%Y%m%d")}.log')
        fh = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        fh.setLevel(logging.INFO)
        
        # Format with more details
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(process)d] - %(message)s'
        )
        fh.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        
        # Log initialization
        self.log_security_event('logger_init', f'Logger initialized for {name}')

    def log_security_event(self, event_type: str, details: str, extra: Optional[dict] = None) -> None:
        try:
            msg = f"SECURITY_EVENT: {event_type} - {details}"
            if extra:
                msg += f" - {extra}"
            self.logger.info(msg)
        except Exception as e:
            # Fallback to basic logging if formatted logging fails
            self.logger.error(f"Logging failed: {str(e)}")
            self.logger.info(f"SECURITY_EVENT: {event_type}")

    def log_error(self, error_type: str, details: str, extra: Optional[dict] = None) -> None:
        try:
            msg = f"SECURITY_ERROR: {error_type} - {details}"
            if extra:
                msg += f" - {extra}"
            self.logger.error(msg)
        except Exception as e:
            # Fallback to basic logging
            self.logger.error(f"Logging failed: {str(e)}")
            self.logger.error(f"SECURITY_ERROR: {error_type}")
