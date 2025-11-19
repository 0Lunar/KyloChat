from core.CryptoHandler import CryptoHandler
from core.HandleConnection import SocketHandler
from core.dbHandler import DBHandler
from core.Logger import Logger


class Login(object):
    def __init__(self, connection: SocketHandler) -> None:
        self.crypto = CryptoHandler()
        self.conn = connection
        self.db = DBHandler()
        self.logger = Logger()
        self.logged_user = ''
    

    def login(self) -> bool:
        # Get Credentials
        # Username

        try:
            username = self.conn.recv_short_bytes()
            username = username.decode(encoding='utf-8', errors='ignore')
        except Exception as ex:
            self.logger.error(f"Connection error for {self.conn.addr}: {ex}")
            self.conn.fail_code()
            return False

    
        if not self.db.checkUser(username) or self.db.checkBan(username):
            self.logger.warning(f"Invalid username for {self.conn.addr}")
            self.conn.fail_code()
            return False
        
        self.conn.success_code()

        # Password

        try:
            password = self.conn.recv_short_bytes()
            password = password.decode(encoding='utf-8', errors='ignore')
        except Exception as ex:
            self.logger.error(f"Connection error for {self.conn.addr}: {ex}")
            self.conn.fail_code()
            return False
        
        # Compare Credentials With Database
        
        if self.db.checkPw(username, password):
            self.logger.info(f"Login success for {self.conn.addr}  ->  {username}")
            self.conn.success_code()
            
            UserID = self.db.userID(username)
            token = self.db.makeToken(UserID)
            
            self.logger.info(f"Token for {self.conn.addr}: {token[:14] + "*" * 22}")
            self.conn.send_short_bytes(token.encode())
            
            self.logged_user = username
            return True
        
        self.logger.warning(f"Invalid password for {self.conn.addr}; login failed for {username}")
        self.conn.fail_code()
        return False