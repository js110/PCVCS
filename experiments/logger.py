                      
                       

import logging
import sys
import io
from pathlib import Path
from typing import Optional
from datetime import datetime


class ExperimentLogger:
    
    def __init__(self, name: str = "experiment", log_file: Optional[Path] = None, 
                 level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
                  
        self.logger.handlers.clear()
        
                
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
                  
        if hasattr(sys.stdout, "buffer"):
            safe_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        else:
            safe_stdout = sys.stdout
        console_handler = logging.StreamHandler(safe_stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
                 
        if log_file is not None:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, message: str) -> None:
        self.logger.debug(message)
    
    def info(self, message: str) -> None:
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        self.logger.critical(message)
    
    def exception(self, message: str) -> None:
        self.logger.exception(message)
    
    def section(self, title: str) -> None:
        separator = "=" * 60
        self.logger.info(f"\n{separator}")
        self.logger.info(f"{title}")
        self.logger.info(separator)
    
    def subsection(self, title: str) -> None:
        separator = "-" * 60
        self.logger.info(f"\n{separator}")
        self.logger.info(f"{title}")
        self.logger.info(separator)


def setup_logger(name: str = "experiment", log_file: Optional[Path] = None,
                 level: str = "INFO") -> ExperimentLogger:
    return ExperimentLogger(name, log_file, level)
