import toml
import os
import re
from core.Exceptions import DecodingError, ParameterError, ConfigurationError


def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
        
    if ip.count('.') == 3 and not any([not i.isdigit() for i in ip.split('.')]):
        return bool(re.match(r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$', ip))
        
    if ip.split('.')[-1].isdigit():
        return False
        
    return bool(re.match(r'^((([A-Za-z0-9\-\_])+\.)+)?([A-Za-z0-9\-\_])+\.([A-Za-z0-9\-\_])+$', ip))
    


class SettingsParser(object):
    def __init__(self, config_file: str = 'config.toml') -> None:
        assert config_file.endswith('.toml'), "Invalid file extension; use .toml"
        assert os.path.isfile(config_file), "Configuration file not found"
        
        self.filename = config_file
        
        try:
            with open(self.filename, 'rt') as f:
                self.config = toml.load(f)
        except toml.TomlDecodeError:
            raise DecodingError('Invalid TOML encoding')
        
        
        try:
            self.ip = self.config['Address']['ip_address']
            
            if not validate_ip(self.ip):
                raise ConfigurationError("Invalid IP Address")
            
            self.port = self.config['Address']['port']
            
            if self.port < 0 or self.port > 65535:
                raise ConfigurationError("Invalid port")
            
            self.logging = bool(self.config['Logging']['logging'])
            self.save_logs = bool(self.config['Logging']['save_logs'])
            self.log_dir = self.config['Logging']['log_dir']
            self.log_file = self.config['Logging']['log_file']
            self.login_attempts = self.config['Authentication']['login_attempts']
            self.ban_on_fail = self.config['Authentication']['ban_on_fail']
            self.ban_time = self.config['Authentication']['ban_time']
            self.rate_limit = self.config['Security']['rate_limit']
            self.rate_limit_sleep = self.config['Security']['rate_limit_sleep'] / 1000
            self.max_message_size = self.config['Security']['max_message_size']
            
            if self.max_message_size > 0xFFFFFFFF or self.max_message_size < 0:
                raise ConfigurationError("Invalid max message size")
            
            self.max_image_size = self.config['Security']['max_image_size']
        
            if self.max_image_size > 0xFFFFFFFF or self.max_image_size < 0:
                raise ConfigurationError("Invalid max image size")
        
            self.slow_down = self.config['Security']['slow_down'] / 1000
            self.max_conns = self.config['Security']['max_conns']
            self.max_conn_errors = self.config['Security']['max_conn_errors']
            self.sleep_on_full_conns = self.config['Security']['sleep_on_full_conns'] / 1000
            self.certificate = self.config['Security']['certificate'] or 'cert.pem'
            self.white_list = set(self.config['Security']['whitelist'])
            self.black_list = set(self.config['Security']['blacklist'])
        except Exception:
            raise ParameterError("Missing parameter/s in toml config file")
    
    
    def get(self, key, default: None):
        return self.config.get(key, default)
    
    
    def update(self, m: dict):
        self.config.update(m)
    
    
    def __repr__(self) -> str:
        return f'IP: {self.ip}\nPORT: {self.port}\nLog dir: {self.log_dir}\nLog file: {self.log_file}\nLogin attempts: {self.login_attempts if self.login_attempts > 0 else "No limit"}\nRate limit: {f'{self.rate_limit} msg/s' if self.rate_limit > 0 else "No limit"}\nRate limit sleep: {f'{self.rate_limit_sleep} s' if self.rate_limit_sleep > 0 else "No limit"}\nMax message size: {f'{self.max_message_size} bytes' if self.max_message_size > 0 else "No limit"}\nMax Image size: {f'{self.max_image_size} bytes' if self.max_image_size > 0 else "No limit"}\nDelay: {f'{self.slow_down} s' if self.slow_down > 0 else "No limit"}\nMax conns: {self.max_conns if self.max_conns > 0 else "No limit"}\nMax conn errors: {self.max_conn_errors if self.max_conn_errors > 0 else "No limit"}\nSleep on full conns: {f'{self.sleep_on_full_conns} s' if self.sleep_on_full_conns > 0 else "No limit"}\nCertificate: {self.certificate}\nWhite List: {'Enabled' if self.white_list else 'Disabled'}\nBlack List: {'Enabled' if self.black_list else 'Disabled'}'
    
    
    def __str__(self) -> str:
        return self.__repr__()
    
    
    def __getitem__(self, key):
        return self.config[key]
    
    
    def __setitem__(self, key, value):
        self.config[key] = value