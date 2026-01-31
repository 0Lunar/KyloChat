from core.SettingsParser import SettingsParser
import time
import re


class NetworkBan(object):
    def __init__(self) -> None:
        self.settings = SettingsParser()
        
        self.networks = dict()
        self.logins = dict()
    
    
    def addLogin(self, host: str, count: int) -> None:
        if not self.logins.get(host, None):
            self.logins[host] = count
        
        else:
            self.logins[host] += count
            
    
    def countLogin(self, host: str) -> int:
        return self.logins.get(host, 0)
    
    
    def removeLogin(self, host: str) -> None:
        if host in self.logins:
            self.logins.pop(host)
            
            
    def cleanLogin(self) -> None:
        self.logins.clear()
    
    
    def newBan(self, host: str) -> None:
        if not self.settings.ban_on_fail:
            raise RuntimeError("Ban disabled")
        
        self.networks[host] = time.time() + self.settings.ban_time
    
    
    def isBanned(self, host: str) -> bool:
        if not self.settings.ban_on_fail:
            return False
        
        if self.networks.get(host, None) and self.networks[host] >= time.time():
            return True
                    
        return False