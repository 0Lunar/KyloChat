from core.dbHandler import DBHandler
from core.ConnectionsHandler import ConnHandler

class CommandHandler(object):
    def __init__(self, dbHandler: DBHandler, connHandler: ConnHandler) -> None:
        self.commands = {
            "help": (0, self.helpCommand),
            "user_id":  (1, self.user_id),       # print user id : /user_id <username : str>
            "ban":      (1, self.banUser),       # Ban a user : /ban <usr_id : int>
            "unban":    (1, self.unbanUser),     # Unban a user : /unban <usr_id : int>
            "isAdmin":  (1, self.isAdmin),       # Check if a user is admin : /isAdmin <usr_id: int>
            "isBanned": (1, self.isBanned),      # Check if a user is banned : /isBanned <usr_id : int>
            "usrpw":    (2, self.changePasswd),  # Change a password for a user : /usrpw <usr_id : int> <new_pwd : str>
            "lsip":     (0, self.lsip),          # List all the connected ip's : /lsusr
            "mkusr":    (4, self.makeUser),      # Create a user on the database : /mkusr <username : str> <password : str> <email : str> <isadmin : bool>
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
'''
    

    def isCommand(self, msg: str) -> bool:
        if not msg:
            return False
        
        msg = msg.split(" ")[0]
        
        return msg.startswith("/") and msg[1:] in self.commands.keys()
    
    
    def parseCommand(self, command: str):
        if not self.isCommand(command):
            return

        cmd = command.split(" ")
        command, args = cmd[0][1:], cmd[1:]
        
        if len(args) != self.commands[command][0]:
            return
        
        out = self.commands[command][1](*args)
        
        if type(out) != bytes:
            try:
                return str(out).encode()
            except Exception as ex:
                return "Error"
        
        return out
    
    
    def user_id(self, username: str) -> int:
        if not self._db.isConnected():
            return -1
        
        return self._db.userID(username)
    
    
    def banUser(self, user_id: int) -> bool:
        if not self._db.isConnected():
            return False
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return False
    
        return self._db.banUser(user_id)
    
    
    def unbanUser(self, user_id: int) -> bool:
        if not self._db.isConnected():
            return False
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return False
        
        return self._db.unbanUser(user_id)
    
    
    def isAdmin(self, user_id: int) -> bool:
        if not self._db.isConnected():
            return False
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return False
        
        return self._db.isAdmin(user_id)
    
    
    def isBanned(self, user_id: int) -> bool:
        if not self._db.isConnected():
            return False
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return False
        
        return self._db.checkBan(user_id)
    
    
    def changePasswd(self, user_id: int, passwd: str) -> bool:
        if not self._db.isConnected():
            return False
        
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return False
        
        return self._db.changePasswd(user_id, passwd)
    
    
    def lsip(self) -> tuple[str]:
        return self._cn.get_all_ip()
    
    
    def makeUser(self, username: str, password: str, email: str | None = None, admin: bool = False) -> bool:
        if not username or not password or (admin and not email):
            return False
        
        return self._db.makeUser(username, password, email, admin, True)