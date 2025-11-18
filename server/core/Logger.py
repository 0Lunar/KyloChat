import logging
import logging.handlers
import os
import sys
from datetime import datetime
from colorama import init, Fore, Style

class Logger:
    def __init__(self, log_dir="logs", max_file_size=10*1024*1024, backup_count=5, 
                 console_output=True, use_colors=True):
        init()
        
        self.log_dir = log_dir
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        self.use_colors = use_colors and console_output
        self.console_output = console_output
        
        os.makedirs(log_dir, exist_ok=True)
        self.setup_logger()
        
    def setup_logger(self):
        self.logger = logging.getLogger('ChatServer')
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers = []
        
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        if self.use_colors:
            console_formatter = ColoredFormatter(
                '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
        else:
            console_formatter = file_formatter
        
        # Handler file
        log_file = os.path.join(self.log_dir, 'chatserver.log')
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.max_file_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)
        
        if self.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(console_formatter)
            console_handler.setLevel(logging.INFO)
            self.logger.addHandler(console_handler)
    
    def debug(self, message, use_colors=None):
        use_colors = self.use_colors if use_colors is None else use_colors
        
        if use_colors:
            colored_message = f"{Fore.CYAN}{message}{Style.RESET_ALL}"
            self.logger.debug(colored_message)
        
        else:
            self.logger.debug(message)
    
    def info(self, message, use_colors=None):        
        use_colors = self.use_colors if use_colors is None else use_colors
        
        if use_colors:
            colored_message = f"{Fore.GREEN}{message}{Style.RESET_ALL}"
            self.logger.info(colored_message)
        
        else:
            self.logger.info(message)
    
    def warning(self, message, use_colors=None):
        use_colors = self.use_colors if use_colors is None else use_colors
        
        if use_colors:
            colored_message = f"{Fore.YELLOW}{message}{Style.RESET_ALL}"
            self.logger.warning(colored_message)
        
        else:
            self.logger.warning(message)
    
    def error(self, message, use_colors=None):        
        use_colors = self.use_colors if use_colors is None else use_colors
        
        if use_colors:
            colored_message = f"{Fore.RED}{message}{Style.RESET_ALL}"
            self.logger.error(colored_message)
            
        else:
            self.logger.error(message)
    
    def critical(self, message, use_colors=None):
        use_colors = self.use_colors if use_colors is None else use_colors
        
        if use_colors:
            colored_message = f"{Fore.RED}{Style.BRIGHT}{message}{Style.RESET_ALL}"
            self.logger.critical(colored_message)
            
        else:
            self.logger.critical(message)
    
    def close(self):
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)


class ColoredFormatter(logging.Formatter):    
    def __init__(self, fmt=None, datefmt=None):
        super().__init__(fmt, datefmt)
        
        
    def format(self, record):
        return super().format(record)