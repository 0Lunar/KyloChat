from core.dbHandler import DBHandler
from core.ConnectionsHandler import ConnHandler

class CommandHandler(object):
    """ Command parsing class """
    def __init__(self, dbHandler: DBHandler, connHandler: ConnHandler) -> None:
        self.commands = {
            "help":     (0, self.helpCommand),
            "user_id":  (1, self.user_id),       # print user id : /user_id <username : str>
            "ban":      (1, self.banUser),       # Ban a user : /ban <usr_id : int>
            "unban":    (1, self.unbanUser),     # Unban a user : /unban <usr_id : int>
            "isAdmin":  (1, self.isAdmin),       # Check if a user is admin : /isAdmin <usr_id: int>
            "isBanned": (1, self.isBanned),      # Check if a user is banned : /isBanned <usr_id : int>
            "chpw":     (2, self.changePasswd),  # Change a password for a user : /usrpw <usr_id : int> <new_pwd : str>
            "lsip":     (0, self.lsip),          # List all the connected ip's : /lsusr
            "mkusr":    (4, self.makeUser),      # Create a user on the database : /mkusr <username : str> <password : str> <email : str> <isadmin : bool>
            "rvktk":    (1, self.revokeToken),   # Revoke a token : /rvktk <token : str>
            "rmtk":     (1, self.removeToken),   # Remove permanently the token : /rmtk <token : str>
            "showtk":   (1, self.showTokens),    # Show the tokens in the database : /showtk <limit : int>
            "lsusers":  (0, self.list_users),    # Show all the users in the database : /lsusers
        }
        
        self._db = dbHandler
        self._cn = connHandler
        
        if not self._db.isConnected():
            raise RuntimeError("Database not connected")
        
        
    def helpCommand(self) -> bytes:
        """ Returns the help command """
        return \
b'''
/help           Display this message
/user_id        print user id : /user_id <username : str>
/ban            Ban a user : /ban <usr_id : int>
/unban          Unban a user : /unban <usr_id : int>
/isAdmin        Check if a user is admin : /isAdmin <usr_id : int>
/isBanned       Check if a user is banned : /isBanned <usr_id : int>
/chpw           Change a password for a user : /usrpw <usr_id : int> <new_pwd : str>
/lsip           List all the connected ip's : /lsusr
/mkusr          Create a user on the database : /mkusr <username : str> <password : str> <email : str> <isadmin : bool>
/rvktk          Revoke a token:  /rvktk <token : str>
/rmtk           Remove permanently the token : /rmtk <token : str>
/showtk         Show the tokens in the database : /showtk <limit : int>
/lsusers        Show all the users in the database : /lsusers
'''
    

    def isCommand(self, msg: str) -> bool:
        """
        Checks whether a string is a valid command
        
        Args:
            msg: the message to check
        
        Returns:
            check: `True` if it's a command, `False` otherwise
        """
        if not msg:
            return False
        
        if not msg.startswith("/"):
            return False
                
        return msg.split(" ")[0][1:] in self.commands.keys()
    
    
    def parseCommand(self, command: str) -> bytes:
        """
        Parse a command and executes it
        
        Args:
            command: the command to execute
        
        Returns:
            data: the output of the command
        """
        if not self.isCommand(command):
            return b''

        cmd = command.split(" ")
        command, args = cmd[0][1:], cmd[1:]
        
        if len(args) != self.commands[command][0]:
            return self.helpCommand()
        
        out = self.commands[command][1](*args)
        
        if type(out) != bytes:
            try:
                return str(out).encode(encoding='utf-8', errors='strict')
            except Exception as ex:
                return b"Error"
        
        return out
    
    
    def user_id(self, username: str) -> bytes:
        """
        Convert username to userID
        
        Args:
            username: the username
        
        Returns:
            userid: the database userID
        """
        try:
            return f'UserID: {self._db.userID(username)}'.encode(encoding='utf-8', errors='strict')
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def banUser(self, user_id: int) -> bytes:
        """
        Ban a user
        
        Args:
            user_id: the database userID
        
        Returns:
            status: command output
        """       
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
    
        try:
            if self._db.banUser(user_id):
                return b'User Banned'

            return f'Error banning {user_id}'.encode(encoding='utf-8', errors='strict')
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def unbanUser(self, user_id: int) -> bytes:
        """
        Unban a user
        
        Args:
            user_id: the database userID
        
        Returns:
            status: command output
        """     
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
        
        try:
            if self._db.unbanUser(user_id):
                return b'User Unbanned'

            return f'Error unbanning {user_id}'.encode(encoding='utf_8', errors='strict')
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def isAdmin(self, user_id: int) -> bytes:
        """
        Check if a user is admin
        
        Args:
            user_id: the database userID
        
        Returns:
            out: `True` if the user is admin, `False` otherwise
        """       
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
        
        try:
            return b'True' if self._db.isAdmin(user_id) else b'False'
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def isBanned(self, user_id: int) -> (bool | bytes):
        """
        Check if a user is banned
        
        Args:
            user_id: the database userID
        
        Returns:
            banStatus: `True` if banned, `False` otherwise
        """     
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
        
        try:
            return b'True' if self._db.checkBan(user_id, silent=True) else b'False'
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    

    def changePasswd(self, user_id: int, passwd: str) -> bytes:
        """
        Change a user's password
        
        Args:
            user_id: the database userID
            passwd: the new user password
        
        Returns:
            status: command output
        """
        if type(user_id) is not int:
            try:
                user_id = int(user_id)
            except:
                return b'Invalid UserID'
        
        try:
            if self._db.changePasswd(user_id, passwd):
                return b'Password Changed'

            return f'Error changing password for {user_id}'.encode(encoding='utf-8', errors='strict')
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def lsip(self) -> tuple:
        """
        Show all connected IPs
        
        Returns:
            hosts: all the connected hosts
        """
        return tuple(self._cn.get_all_hosts())
    
    
    def makeUser(self, username: str, password: str, email: str | None = None, admin: bool = False) -> bytes:
        """
        Create a new user
        
        Args:
            username: the username
            password: the password for authentication
            email: the email for account recovery (optional)
            admin: set `True` if the account have admin permissions, `False` otherwise (default: `False`)
        
        Returns:
            status: command output
        """
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
        
        try:
            return b'User created successfully' if self._db.makeUser(username, password, email, admin, True) \
                else f'Error creating: ({username}, {'*' * len(password)}, {email}, Admin={admin})'.encode(encoding='utf-8', errors='strict')
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def revokeToken(self, token: str) -> bytes:
        """
        Revoke a token
        
        Args:
            token: the token to revoke
        
        Returns:
            status: command output
        """
        try:
            if not self._db.existToken(token):
                return b'Token not found'

            if self._db.revokeToken(token):
                return b'Token revoked'

            return b'Error revoking the token'
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def removeToken(self, token: str) -> bytes:
        """
        Removes a token from the database
        
        Args:
            token: the token to remove
        
        Returns:
            status: command output
        """
        try:
            if not self._db.existToken(token):
                return b'Token not found'

            if self._db.removeToken(token):
                return b'Token permanently removed'

            return b'Error removing the token'
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def showTokens(self, limit: int) -> bytes:
        """
        Show all tokens in the database
        
        Args:
            limit: max number of tokens to show
            
        Returns:
            status: command output
        """
        if type(limit) is not int:
            try:
                limit = int(limit)
            except:
                return b'Invalid limit'
        
        if limit < 1:
            return b'Invalid limit'
        
        try:
            tokens = self._db.showTokens(limit)

            if tokens:
                output = b'\n'

                for token in tokens:
                    tk, user, userid = token[0], token[1], token[2]
                    output += f'Token: {tk}\nUser: {user}\nUserID: {userid}\n\n'.encode(encoding='utf-8', errors='strict')

                return output[:-2]

            return b'No token found'
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
    
    
    def list_users(self) -> bytes:
        """
        Show all users in the database
        
        Returns:
            users: all the users registered in the database
        """
        try:
            users = self._db.showUsers()
            
            if not users:
                return b'Users not found'
            
            out = b'\n'
            
            for user in users:
                out += f'ID: {user[0]}\nUsername: {user[1]}\nBanned: {user[2]}\n\n'.encode(encoding='utf-8', errors='strict')
            
            return out
        except Exception as ex:
            return f'Database error: {ex}'.encode(encoding='utf-8', errors='strict')
