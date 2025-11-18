from core.dbHandler import DBHandler
from core.ConnectionsHandler import ConnHandler

class CommandHandler(object):
    def __init__(self, dbHandler: DBHandler, connHandler: ConnHandler) -> None:
        self.commands = {
            "help": (0, self.helpCommand),
            "user_id":  (1, self.user_id),       # print user id : /user_id <username>
            "ban":      (1, self.banUser),       # Ban a user : /ban <usr_id>
            "unban":    (1, self.unbanUser),     # Unban a user : /unban <usr_id>
            "isAdmin":  (1, self.isAdmin),       # Check if a user is admin : /isAdmin <usr_id>
            "isBanned": (1, self.isBanned),      # Check if a user is banned : /isBanned <usr_id>
            "usrpw":    (2, self.changePasswd),  # Change a password for a user : /usrpw <usr_id> <new_pwd>
            "lsip":     (0, self.lsip),          # List all the connected ip's : /lsusr
        }
        
        self._db = dbHandler
        self._cn = connHandler
        
        if not self._db.isConnected():
            raise RuntimeError("Database not connected")
        
        
    def helpCommand(self) -> bytes:
        return \
b'''
/help           Display this message
/user_id        print user id : /user_id <username>
/ban            Ban a user : /ban <usr_id>
/unban          Unban a user : /unban <usr_id>
/isAdmin        Check if a user is admin : /isAdmin <usr_id>
/isBanned       Check if a user is banned : /isBanned <usr_id>
/usrpw          Change a password for a user : /usrpw <usr_id> <new_pwd>
/lsip           List all the connected ip's : /lsusr
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