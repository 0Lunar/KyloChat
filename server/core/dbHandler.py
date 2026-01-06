import mysql.connector as mysql
from core.CryptoHandler import CryptoHandler
import os
from uuid import uuid4
from datetime import datetime


class DBHandler(object):
    def __init__(self, host: str | None = None, username: str | None = None, password: str | None = None, database: str | None = None) -> None:
        """
        Class to manage users on the database
        """
        self.db = mysql.connect(
            host=host or os.environ.get("CHAT_DB_HOST", "localhost"),
            username=username or os.environ.get("CHAT_DB_USER", "root"),
            password=password or os.environ.get("CHAT_DB_PASSWD", "root"),
            database=database or os.environ.get("CHAT_DB_NAME", "KyloChatDB"),
            autocommit=True
        )
        
        self.crypto = CryptoHandler()
        
    
    def isConnected(self) -> bool:
        """
        Check if the connection with the database is open
        
        Returns:
            bool : `True` if connected, otherwise `False`
        """
        return self.db.is_connected()
        

    def checkUser(self, username: str | int) -> bool:
        """
        Check if the user exists
        
        Args:
            username : `string` for username; `int` for UserID
        
        Returns:
            bool : `True` if the username exists, otherwise `False`
        """
        cursor = self.db.cursor()
        
        if type(username) is str:
            cursor.execute(
                "SELECT 1 FROM users WHERE users.username=%s LIMIT 1",
                (username, )
            )
        else:
            cursor.execute(
                "SELECT 1 FROM users WHERE users.UserID=%s LIMIT 1",
                (username, )
            )
        
        res = cursor.fetchone()
        
        cursor.close()

        if res is None:
            return False
        
        return len(res) == 1 and res[0]
    
    
    def userID(self, username: str) -> int:
        """
        Return the userid of a user
        
        Args:
            username : `string` representing the username
        
        Returns:
            user_id : An `int` representing the user's ID in the database
        """
        cursor = self.db.cursor()
        
        cursor.execute(
            "SELECT users.UserID FROM users WHERE users.username=%s LIMIT 1",
            (username,)
        )
        res = cursor.fetchone()
        
        cursor.close()
        
        if res is None:
            return -1
        
        return res[0]

        
    def checkPw(self, username: str | int, password: str, silent: bool = False) -> bool:
        """
        Check the credentials
        
        Args:
            username : `string` for username
            password : `string` for password
            silent : If set to `True` does not raise exceptions
        
        Returns:
            bool : `True` if username and password are correct, otherwise `False`
        """
        if not self.checkUser(username):
            return False
        
        cursor = self.db.cursor()
        
        if type(username) is str:
            cursor.execute(
                "SELECT credentials.password FROM credentials INNER JOIN (users) ON (users.UserID) = (credentials.user) WHERE users.username=%s LIMIT 1",
                (username,)
            )
        else:
            cursor.execute(
                "SELECT credentials.password FROM credentials INNER JOIN (users) ON (users.UserID) = (credentials.user) WHERE users.UserID=%s LIMIT 1",
                (username, )
            )
        
        hs_passwd = cursor.fetchone()
        
        cursor.close()
        
        if hs_passwd is None or len(hs_passwd) == 0:
            if silent:
                return False
            raise RuntimeError("Database Response is NULL")
                
        return self.crypto.Bcrypt_Check(password.encode(), hs_passwd[0].encode())


    def checkBan(self, username: str | int, silent: bool = False) -> bool:
        """
        Check if a user is banned
        
        Args:
            username : `string` for username; `int` for UserID
            silent : If set to `True` does not raise exceptions
        
        Returns:
            bool : `True` if user is banned, otherwise `False`
        """
        if not self.checkUser(username):
            return False
        
        cursor = self.db.cursor()
        
        if type(username) is str:
            cursor.execute(
                "SELECT users.banned FROM users WHERE users.username=%s LIMIT 1",
                (username, )
            )
        else:
            cursor.execute(
                "SELECT users.banned FROM users WHERE users.UserID=%s LIMIT 1",
                (username, )
            )
        
        res = cursor.fetchone()
        
        cursor.close()
        
        if res is None or len(res) == 0:
            if silent:
                return False
            raise RuntimeError("Database response is NULL")
        
        return res[0]


    def isAdmin(self, user: str | int) -> bool:
        if not self.checkUser(user):
            return False
        
        cursor = self.db.cursor()
        
        if type(user) is str:
            cursor.execute(
                "SELECT users.admin FROM users WHERE users.username=%s LIMIT 1",
                (user, )
            )
        else:
            cursor.execute(
                "SELECT users.admin FROM users WHERE users.UserID=%s LIMIT 1",
                (user, )
            )
        
        res = cursor.fetchone()
        
        cursor.close()
        
        if res is None:
            return False
        
        return res[0]
    

    def existToken(self, token: str) -> bool:
        """
        Check if the token exists in the database
        
        Params:
            token : `string` for the token
        
        Returns:
            bool : `True` if the token exists, otherwise `False`
        """
        cursor = self.db.cursor()
        cursor.execute(
            "SELECT 1 FROM tokens WHERE tokens.token=%s LIMIT 1",
            (token, )
        )
                
        res = cursor.fetchone()
        cursor.close()
                        
        if res is None:
            return False
    
        return res[0]
    
    
    def isExpiredToken(self, token: str) -> (bool | None):
        """
        Check if a token is expired
        
        Args:
            token : `string` for token
        
        Returns:
            bool : `True` if the token is expired, otherwise `False`
        """
        cursor = self.db.cursor()
        
        cursor.execute(
            "SELECT tokens.expire FROM tokens WHERE tokens.token=%s LIMIT 1",
            (token, )
        )
        expire = cursor.fetchone()
        
        if expire is None:
            cursor.close()
            return None
        
        expire = expire[0]  # type: datetime
        
        if expire.timestamp() < datetime.now().timestamp():
            cursor.close()
            return True
        
        cursor.execute(
            "SELECT tokens.revoked FROM tokens WHERE tokens.token=%s LIMIT 1",
            (token, )
        )
        
        revoked = cursor.fetchone()[0]
        
        cursor.close()
        
        return revoked


    def checkTokenBan(self, token: str) -> bool:
        """
        Check if a user is banned with the token
        
        Args:
            token : `string` for token
        
        Returns:
            bool : `True` if the user is banned, otherwise `False`
        """
        cursor = self.db.cursor()
        
        cursor.execute(
            "SELECT users.banned FROM (users INNER JOIN tokens ON tokens.user = users.UserID) WHERE tokens.token=%s LIMIT 1",
            (token, )
        )
        
        ban = cursor.fetchone()
        cursor.close()
        
        if ban is None:
            return False
        
        return ban[0]
    

    def isAdminToken(self, token: str) -> bool:
        """
        Check if a token belongs to an admin
        
        Params:
            tokens : `string` for token
            
        Returns:
            `True` if the token is admin, otherwise `False`
        """
        
        if not self.existToken(token):
            return False
    
        cursor = self.db.cursor()
        
        cursor.execute(
            "SELECT users.admin FROM (users INNER JOIN tokens ON users.UserID=tokens.user) WHERE tokens.token=%s LIMIT 1",
            (token, )
        )
        
        res = cursor.fetchone()
        cursor.close()
        
        if res is None:
            return False
        
        return res[0]
    
    
    def TokenToUsername(self, token: str) -> str:
        if not self.existToken(token):
            return ""
        
        cursor = self.db.cursor()
        
        cursor.execute(
            "SELECT users.username FROM (users INNER JOIN tokens ON tokens.user=users.UserID) WHERE tokens.token=%s LIMIT 1",
            (token, )
        )
        
        res = cursor.fetchone()
        
        if res is None:
            return ""
        
        return res[0]
    
    
    def makeToken(self, user: int) -> str:
        """
        Create a token
        
        Args:
            user : An `int` representing the user's ID in the database
        
        Returns:
            token : A `string` representing the token
        """
        
        if not self.checkUser(user):
            return ""
        
        token = str(uuid4())
        expire = datetime.now().timestamp() + 604800.0  # 1 week
        expire = datetime.fromtimestamp(expire).strftime("%Y-%m-%d %H:%M:%S")
        
        cursor = self.db.cursor()
        cursor.execute(
            "INSERT INTO tokens(token, user, expire) VALUES (%s, %s, %s)",
            (token, user, expire, )
        )
        
        cursor.close()
                
        return token


    def banUser(self, user_id: int) -> bool:
        """
        Ban a user
        
        Args:
            user_id : An `int` representing the user's ID in the database
        
        Returns:
            bool : `True` if the user is banned, otherwise `False`
        """
        
        if not self.checkUser(user_id):
            return False
        
        if self.checkBan(user_id):
            return False
        
        if self.isAdmin(user_id):
            return False
        
        cursor = self.db.cursor()
        
        cursor.execute(
            "UPDATE users SET banned=true WHERE users.UserID=%s",
            (user_id, )
        )
        
        cursor.close()
        
        return True


    def unbanUser(self, user_id: int) -> bool:
        """
        Unban a user
        
        Args:
            user_id : An `int` representing the user's ID in the database
        
        Returns:
            bool : `True` if the user is unbanned, otherwise `False`
        """
        
        if not self.checkUser(user_id):
            return False
    
        if not self.checkBan(user_id, True):
            return False
        
        if self.isAdmin(user_id):
            return False
    
        cursor = self.db.cursor()
        
        cursor.execute(
            "UPDATE users SET banned=false WHERE users.UserID=%s",
            (user_id, )
        )
        
        cursor.close()
        
        return True


    def changePasswd(self, user_id: int, newPasswd: str) -> bool:
        if not self.checkUser(user_id):
            return False
        
        if self.isAdmin(user_id):
            return False
        
        passwd = self.crypto.Bcrypt_Hash(
            newPasswd.encode(),
            self.crypto.Generate_Bcrypt_Salt()
        ).decode(encoding='utf-8', errors='ignore')
        
        cursor = self.db.cursor()
        
        cursor.execute(
            "UPDATE credentials SET password=%s WHERE credentials.user=%s",
            (passwd, user_id, )
        )
        
        cursor.close()
        
        return True
    
    
    def makeUser(self, username: str, password: str, email: str | None = None, admin: bool = False, silent: bool = False) -> bool:
        """
        Create a user on the database
        
        Args:
            username : username for login
            password : user password
            email : email for the account (optional for non admin)
            admin : `True` if the user is admin, otherwise `False`
            
        Returns:
            out : `True` on success, `False` on failure
        """
        
        if not username:
            if silent:
                return False
            raise RuntimeError("Missing username")
        
        if not password:
            if silent:
                return False
            raise RuntimeError("Missing password")
        
        if admin and not email:
            if silent:
                return False
            raise RuntimeError("Admin need an email")
        
        if self.checkUser(username):
            if silent:
                return False
            raise RuntimeError("User already exists")
        
        email = email or 'None'
        hashed_password = self.crypto.Bcrypt_Hash(
            password.encode(),
            self.crypto.Generate_Bcrypt_Salt()
        )
        
        cursor = self.db.cursor()
        
        cursor.execute(
            "INSERT INTO users(username, email, admin) VALUES (%s, %s, %s)",
            (username, email, admin, )
        )
        
        user_id = self.userID(username)
        
        cursor.execute(
            "INSERT INTO credentials(user, password) VALUES (%s, %s)",
            (user_id, hashed_password, )
        )
        
        cursor.close()
        
        return True
    
    
    def showTokens(self, limit: int = 100) -> (list | None):
        """
        Return the first N tokens in the database
        
        Args:
            limit : The maximum number of tokens to return
        
        Returns:
            out : list[Tokens] on success, None on failure
        """
        
        if limit < 1:
            return None
        
        cursor = self.db.cursor()
        
        cursor.execute(
            "SELECT tokens.token, users.username, users.UserID FROM (tokens INNER JOIN users ON users.UserID = tokens.user) LIMIT %s",
            (limit, )
        )
        
        tokens = cursor.fetchall()
        
        return tokens
    
    
    def removeToken(self, token: str) -> bool:
        """
        Remove a token from the database
        
        Args:
            token : The token to remove
        
        Returns:
            out : `True` on success, `False` on failure
        """
        
        if not token or len(token) != 36:
            return False
        
        if not self.existToken(token):
            return False
        
        cursor = self.db.cursor()
        
        cursor.execute(
            "DELETE FROM tokens WHERE tokens.token=%s",
            (token, )
        )
        
        cursor.close()
        
        return True
    
    
    def revokeToken(self, token: str) -> bool:
        """
        Revoke a token from the database
        
        Args:
            token : The token to remove
        
        Returns:
            out : `True` on success, `False` on failure
        """
        
        if not token or len(token) != 36:
            return False
        
        if not self.existToken(token):
            return False
        
        cursor = self.db.cursor()
        
        cursor.execute(
            "UPDATE tokens SET revoked=True WHERE tokens.token=%s",
            (token, )
        )
        
        cursor.close()
        
        return True