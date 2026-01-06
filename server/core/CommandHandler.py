from core.dbHandler import DBHandler
from core.ConnectionsHandler import ConnHandler

class CommandHandler(object):
    def __init__(self, dbHandler: DBHandler, connHandler: ConnHandler) -> None:
        self.commands = {
            "help":     (0, self.helpCommand),
            "user_id":  (1, self.user_id),       # print user id : /user_id <username : str>
            "ban":      (1, self.banUser),       # Ban a user : /ban <usr_id : int>
            "unban":    (1, self.unbanUser),     # Unban a user : /unban <usr_id : int>
            "isAdmin":  (1, self.isAdmin),       # Check if a user is admin : /isAdmin <usr_id: int>
            "isBanned": (1, self.isBanned),      # Check if a user is banned : /isBanned <usr_id : int>
            "usrpw":    (2, self.changePasswd),  # Change a password for a user : /usrpw <usr_id : int> <new_pwd : str>
            "lsip":     (0, self.lsip),          # List all the connected ip's : /lsusr
            "mkusr":    (4, self.makeUser),      # Create a user on the database : /mkusr <username : str> <password : str> <email : str> <isadmin : bool>
            "rvktk":    (1, self.revokeToken),   # Revoke a token : /rvktk <token : str>
            "rmtk":     (1, self.removeToken),   # Remove permanently the token : /rmtk <token : str>
            "showtk":   (1, self.showTokens),    # Show the tokens in the database : /showtk <limit : int>
        }
        
        self._db = dbHandler
        self._cn = connHandler
        
        if not self._db.isConnected():
            raise RuntimeError("Database not connected")
        
        
    def helpCommand(self) -> bytes:
        return \
b'''
/help           Display this message
/user_id        print user id : /user_id <username : str>
/ban            Ban a user : /ban <usr_id : int>
/unban          Unban a user : /unban <usr_id : int>
/isAdmin        Check if a user is admin : /isAdmin <usr_id : int>
/isBanned       Check if a user is banned : /isBanned <usr_id : int>
/usrpw          Change a password for a user : /usrpw <usr_id : int> <new_pwd : str>
/lsip           List all the connected ip's : /lsusr
/mkusr          Create a user on the database : /mkusr <username : str> <password : str> <email : str> <isadmin : bool>
/rvktk          Revoke a token:  /rvktk <token : str>
/rmtk           Remove permanently the token : /rmtk <token : str>
/showtk         Show the tokens in the database : /showtk <limit : int>
'''
    

    def isCommand(self, msg: str) -> bool:
        if not msg:
            return False
        
        if not msg.startswith("/"):
            return False
                
        return msg.split(" ")[0][1:] in self.commands.keys()
    
    
    def parseCommand(self, command: str) -> bytes:
        if not self.isCommand(command):
            return b''

        cmd = command.split(" ")
        command, args = cmd[0][1:], cmd[1:]
        
        if len(args) != self.commands[command][0]:
            return self.helpCommand()
        
        out = self.commands[command][1](*args)
        
        if type(out) != bytes:
            try:
                return str(out).encode()
            except Exception as ex:
                return b"Error"
        
        return out
    
    
    def user_id(self, username: str) -> bytes:
        if not self._db.isConnected():
            return b'User not found'
        
        return f'UserID: {self._db.userID(username)}'.encode('utf-8')
    
    
    def banUser(self, user_id: int) -> bytes:
        if not self._db.isConnected():
            return b'Database not connected'
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
    
        if self._db.banUser(user_id):
            return b'User Banned'
        
        return f'Error banning {user_id}'.encode('utf-8')
    
    
    def unbanUser(self, user_id: int) -> bytes:
        if not self._db.isConnected():
            return b'Database not connected'
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
        
        if self._db.unbanUser(user_id):
            return b'User Unbanned'
        
        return f'Error unbanning {user_id}'.encode('utf_8')
    
    
    def isAdmin(self, user_id: int) -> (bool | bytes):
        if not self._db.isConnected():
            return b'Database not connected'
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
        
        return self._db.isAdmin(user_id)
    
    
    def isBanned(self, user_id: int) -> (bool | bytes):
        if not self._db.isConnected():
            return b'Database not connected'
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
        
        return self._db.checkBan(user_id)
    
    
    def changePasswd(self, user_id: int, passwd: str) -> bytes:
        if not self._db.isConnected():
            return b'Database not connected'
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
        
        if self._db.changePasswd(user_id, passwd):
            return b'Password Changed'
    
        return f'Error changing password for {user_id}'.encode('utf-8')
    
    
    def lsip(self) -> tuple:
        return tuple(self._cn.get_all_hosts())
    
    
    def makeUser(self, username: str, password: str, email: str | None = None, admin: bool = False) -> (bool | bytes):
        if not self._db.isConnected():
            return b'Database not connected'
        
        if not email or email.lower() == 'none':
            email = None
        
        if not username or not password or (admin and not email):
            return b'Missing parameters'
        
        if type(admin) is not bool:
            if type(admin) is str:
                admin = True if admin.lower() == 'true' else False
            
            elif type(admin) is int:
                admin = bool(admin)
            
            else:
                admin = False
        
        if self._db.makeUser(username, password, email, admin, True):
            return b'User created successfully'
        
        return f'Error creating: ({username}, {'*' * len(password)}, {email}, Admin={admin})'.encode('utf-8')
    
    
    def revokeToken(self, token: str) -> bytes:
        if not self._db.isConnected():
            return b'Database not connected'
        
        if not self._db.existToken(token):
            return b'Token not found'
        
        if self._db.revokeToken(token):
            return b'Token revoked'
        
        return b'Error revoking the token'
    
    
    def removeToken(self, token: str) -> bytes:
        if not self._db.isConnected():
            return b'Database not connected'
        
        if not self._db.existToken(token):
            return b'Token not found'
        
        if self._db.removeToken(token):
            return b'Token permanently removed'
        
        return b'Error removing the token'
    
    
    def showTokens(self, limit: int) -> bytes:
        if not self._db.isConnected():
            return b'Database not connected'
        
        if type(limit) is not int:
            try:
                limit = int(limit)
            except:
                return b'Invalid limit'
        
        if limit < 1:
            return b'Invalid limit'
        
        tokens = self._db.showTokens(limit)
        
        if tokens:
            output = b'\n'
            
            for token in tokens:
                tk, user, userid = token[0], token[1], token[2]
                output += f'Token: {tk}\nUser: {user}\nUserID: {userid}\n\n'.encode('utf-8')
                
            return output[:-2]
        
        return b'No token found'