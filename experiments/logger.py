                      
                       
"""
日志系统模块
提供统一的日志记录功能
"""

import logging
import sys
import io
from pathlib import Path
from typing import Optional
from datetime import datetime


class ExperimentLogger:
    """实验日志记录器"""
    
    def __init__(self, name: str = "experiment", log_file: Optional[Path] = None, 
                 level: str = "INFO"):
        """
        初始化日志记录器
        
        Args:
            name: 日志记录器名称
            log_file: 日志文件路径
            level: 日志级别 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
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
        """记录调试信息"""
        self.logger.debug(message)
    
    def info(self, message: str) -> None:
        """记录一般信息"""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """记录警告信息"""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """记录错误信息"""
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """记录严重错误信息"""
        self.logger.critical(message)
    
    def exception(self, message: str) -> None:
        """记录异常信息（包含堆栈跟踪）"""
        self.logger.exception(message)
    
    def section(self, title: str) -> None:
        """记录章节标题"""
        separator = "=" * 60
        self.logger.info(f"\n{separator}")
        self.logger.info(f"{title}")
        self.logger.info(separator)
    
    def subsection(self, title: str) -> None:
        """记录子章节标题"""
        separator = "-" * 60
        self.logger.info(f"\n{separator}")
        self.logger.info(f"{title}")
        self.logger.info(separator)


def setup_logger(name: str = "experiment", log_file: Optional[Path] = None,
                 level: str = "INFO") -> ExperimentLogger:
    """
    设置日志记录器
    
    Args:
        name: 日志记录器名称
        log_file: 日志文件路径
        level: 日志级别
    
    Returns:
        ExperimentLogger实例
    """
    return ExperimentLogger(name, log_file, level)
