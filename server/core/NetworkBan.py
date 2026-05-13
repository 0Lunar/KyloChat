from core.SettingsParser import SettingsParser
import time


class NetworkBan(object):
    """ IPS against bruteforce attacks """
    def __init__(self) -> None:
        self.settings = SettingsParser()
        
        self.networks = dict()
        self.logins = dict()
    
    
    def addLogin(self, host: str, count: int) -> None:
        """
        Adds a login attempt
        
        Args:
            host: the host address
            count: the number of attempts made
        """
        if not self.logins.get(host, None):
            self.logins[host] = count
        
        else:
            self.logins[host] += count
            
    
    def countLogin(self, host: str) -> int:
        """
        Returns the number of login attempts
        
        Args:
            host: the host address
            
        Returns:
            attepts: The number of host attempts
        """
        return self.logins.get(host, 0)
    
    
    def removeLogin(self, host: str) -> None:
        """
        Removes a host from the login attempts list
        
        Args:
            host: the host address
        """
        if host in self.logins:
            self.logins.pop(host)
            
            
    def cleanLogin(self) -> None:
        """ Removes all login attempts made """
        self.logins.clear()
    
    
    def newBan(self, host: str) -> None:
        """
        Ban a host from the network
        
        Args:
            host: the host address
        """
        if not self.settings.ban_on_fail:
            raise RuntimeError("Ban disabled")
        
        self.networks[host] = time.time() + self.settings.ban_time
    
    
    def isBanned(self, host: str) -> bool:
        """
        Check if a host is banned from the network
        
        Args:
            host: the host address
        """
        if not self.settings.ban_on_fail:
            return False
        
        if self.networks.get(host, None) and self.networks[host] >= time.time():
            return True
                    
        return False