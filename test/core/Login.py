from core.CryptoHandler import CryptoHandler
from core.HandleConnection import SocketHandler
from core.MessageTypes import MessageTypes
import os
import re


class Login(object):
    """ Class for managing client-server login """
    def __init__(self, connection: SocketHandler) -> None:
        self.crypto = CryptoHandler()
        self.conn = connection
        self.logged_user = ''
        
    
    @staticmethod
    def is_uuid4(data: str) -> bool:
        """
        Check if the token is UUID4
        
        Args:
            data: the data to check
        """
        return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', data))
    
    
    @staticmethod
    def validate_host(host: str) -> bool:
        """
        Validate IP address format
        
        Args:
            host: the address to validate
        """
        
        if host.count('.') == 3 and not any([not i.isdigit() for i in host.split('.')]):
            return bool(re.match(r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$', host))
        
        if host.split('.')[-1].isdigit():
            return False
        
        return bool(re.match(r'^((([A-Za-z0-9\-\_])+\.)+)?([A-Za-z0-9\-\_])+\.([A-Za-z0-9\-\_])+$', host))
    
    
    def checkCache(self, tokenFile: str = ".cache/token") -> bool:
        """
        Check that the cache exists and is valid
        
        Args:
            tokenFile: the file where tokens are saved (default: `.cache/token`)
        """
        if not os.path.isfile(tokenFile):
            return False
        
        with open(tokenFile, "rt") as f:
            while (token := f.readline()) != '':   
                host, username, token = token.split(" ")[:3]

                if not self.is_uuid4(token):
                    return False

                if not self.validate_host(host):
                    return False
        
        return True
    
    
    def getToken(self, host: str, tokenFile: str = ".cache/token") -> (tuple[str, str] | None):
        """
        Gets a token from the cache (if it exists)
        
        Args:
            host: the host associated with the token
            tokenFile: the file where tokens are saved (default: `.cache/token`)
        
        Returns:
        
        """
        if not self.checkCache(tokenFile):
            return None
        
        with open(tokenFile, 'rt') as f:
            while (token := f.readline().strip()) != '':
                token = token.split(" ")
                cache_host, username, token = token[:3]    

                if cache_host == host:
                    return (username, token)
        
        return None
    
    
    def removeToken(self, tokenFile: str = ".cache/token") -> None:
        """
        Removes the first token it finds with the currently connected host
        
        Args:
            tokenFile: the file where tokens are saved (default: `.cache/token`)
        """
        if not os.path.isfile(tokenFile):
            return
        
        with open(tokenFile, 'rt') as f:
            data = f.read().strip().split("\n")
        
        for line in data:
            host = line.split(" ")[0]
            
            if host == self.conn.addr[0]:
                data.remove(line)
                break
            
        lines = '\n'.join(data).strip()
        
        if not lines:
            open(tokenFile, "wt").close()
        
        else:
            with open(tokenFile, "wt") as f:
                f.write(lines)
    
    
    def saveToken(self, username: str, token: str, tokenFile: str = ".cache/token") -> None:
        """ 
        Cache the currently used token
        
        Args:
            username: the username associated with the token
            token: the token to save
            tokenFile: the file where tokens are saved (default: `.cache/token`)
        
        Returns:
        
        """
        if not bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', token)):
            return
        
        if tokenFile.count("/"):
            tokenFile_dir = os.path.abspath('/'.join(tokenFile.split("/")[:-1]))
        
            if not os.path.isdir(tokenFile_dir):
                os.mkdir(tokenFile_dir)
        
        if os.path.isfile(tokenFile):
            mode = "at"
        else:
            mode = "wt"
        
        with open(tokenFile, mode) as f:
            f.write(f'{self.conn.addr[0]} {username} {token}\n')
            
            
    def loging_cache(self) -> (tuple | None):
        """
        Attempt to log in with the cached token
        
        Returns:
            out: `(user, token)` on success, `None` on failure
        """
        if not (token := self.getToken(self.conn.addr[0])):
            return None
        
        user, token = token
        self.conn.send_char_bytes(MessageTypes.CACHED_LOGIN.value.to_bytes(1, 'little'))
        self.conn.send_short_bytes(token.encode(encoding='utf-8', errors='strict'))
        
        if self.conn.recv_code():
            return None
        
        return (user, token)
        
    
    def login(self, username: str, password: str) -> (str | None):
        """
        Login to the server with your credentials
        
        Args:
            username: The username
            password: The password
        
        Returns:
            Status: 'Token' if authenticated; Empity string otherwise
        """
        
        self.conn.send_char_bytes(MessageTypes.STD_LOGIN.value.to_bytes(1, 'little'))
        self.conn.send_short_bytes(username.encode(encoding='utf-8', errors='strict'))
        fail = self.conn.recv_code()
        
        if fail:
            return None
        
        self.conn.send_short_bytes(password.encode(encoding='utf-8', errors='strict'))
        fail = self.conn.recv_code()
        
        if fail:
            return None
        
        token = self.conn.recv_short_bytes().decode()
        
        if not token:
            raise RuntimeError("Invalid token")
        
        return token