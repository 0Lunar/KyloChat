from core.CryptoHandler import CryptoHandler
from core.HandleConnection import SocketHandler


class Login(object):
    def __init__(self, connection: SocketHandler) -> None:
        self.crypto = CryptoHandler()
        self.conn = connection
        self.logged_user = ''
        
    
    def login(self, username: str, password: str) -> str:
        """
        Login in the server
        
        Args:
            username : The username
            password: The password
        
        Returns:
            Status : 'Token' if authenticated; Empity string otherwise
        """
        
        self.conn.send_short_bytes(username.encode('utf-8', errors='strict'))
        fail = self.conn.recv_code()
        
        if fail:
            return ''
        
        self.conn.send_short_bytes(password.encode('utf-8', errors='strict'))
        fail = self.conn.recv_code()
        
        if fail:
            return ''
        
        return self.conn.recv_short_bytes().decode()