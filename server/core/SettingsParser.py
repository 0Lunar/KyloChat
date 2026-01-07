import toml
import os
from core.Exceptions import DecodingError, ParameterError


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
            self.port = self.config['Address']['port']
            self.log_dir = self.config['Logging']['log_dir']
            self.log_file = self.config['Logging']['log_file']
            self.login_attempts = self.config['Authentication']['login_attempts']
            self.rate_limit = self.config['Security']['rate_limit']
            self.rate_limit_sleep = self.config['Security']['rate_limit_sleep'] / 1000
            self.max_payload_size = self.config['Security']['max_payload_size']
            self.slow_down = self.config['Security']['slow_down'] / 1000
            self.max_conns = self.config['Security']['max_conns']
            self.max_conn_errors = self.config['Security']['max_conn_errors']
            self.sleep_on_full_conns = self.config['Security']['sleep_on_full_conns'] / 1000
        except Exception:
            raise ParameterError("Missing parameter/s in toml config file")
    
    
    def get(self, key, default: None):
        return self.config.get(key, default)
    
    
    def update(self, m: dict):
        self.config.update(m)
    
    
    def __getitem__(self, key):
        return self.config[key]
    
    
    def __setitem__(self, key, value):
        self.config[key] = value