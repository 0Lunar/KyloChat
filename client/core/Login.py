from core.CryptoHandler import CryptoHandler
from core.HandleConnection import SocketHandler
from core.MessageTypes import MessageTypes
import os
import re


class Login(object):
    def __init__(self, connection: SocketHandler) -> None:
        self.crypto = CryptoHandler()
        self.conn = connection
        self.logged_user = ''
        
    
    @staticmethod
    def is_uuid4(data: str) -> bool:
        return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', data))
    
    
    @staticmethod
    def validate_host(host: str) -> bool:
        """Validate IP address format"""
        
        if host.count('.') == 3 and not any([not i.isdigit() for i in host.split('.')]):
            return bool(re.match(r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$', host))
        
        if host.split('.')[-1].isdigit():
            return False
        
        return bool(re.match(r'^((([A-Za-z0-9\-\_])+\.)+)?([A-Za-z0-9\-\_])+\.([A-Za-z0-9\-\_])+$', host))
    
    
    def checkCache(self, tokenFile: str = ".cache/token") -> bool:
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
        
        return False
    
    
    def getToken(self, host: str, tokenFile: str = ".cache/token") -> (tuple[str, str] | None):
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
        if not bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', token)):
            return
        
        if tokenFile.count("/"):
            tokenFile_dir = os.path.abspath('/'.join(tokenFile.split("/")[:-1]))
        
            if not os.path.isdir(tokenFile_dir):
                os.mkdir(tokenFile_dir)
        
        with open(tokenFile, 'wt') as f:
            f.write(f'{self.conn.addr[0]} {username} {token}\n')
            
            
    def loging_cache(self) -> (tuple | None):
        if not (token := self.getToken(self.conn.addr[0])):
            return None
        
        user, token = token
        self.conn.unsafe_send(MessageTypes.CACHED_LOGIN.value.to_bytes(1, 'little'))
        self.conn.send_short_bytes(token.encode(encoding='utf-8', errors='strict'))
        
        if self.conn.recv_code():
            return None
        
        return (user, token)
        
    
    def login(self, username: str, password: str) -> (str | None):
        """
        Login in the server
        
        Args:
            username : The username
            password: The password
        
        Returns:
            Status : 'Token' if authenticated; Empity string otherwise
        """
        
        self.conn.unsafe_send(MessageTypes.STD_LOGIN.value.to_bytes(1, 'little'))
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