"""
Script to test KyloChat login
"""

import argparse
import re
import sys

sys.path.append("../")

from core.MessageTypes import MessageTypes
from core.HandleConnection import SocketHandler
from core.Login import Login


parser = argparse.ArgumentParser('KyloChat Login Script', description='A fast script to verify the KyloChat Authentication')
parser.add_argument('-a', '--host', type=str, help='The IP Address / Domain', required=True)
parser.add_argument('-p', '--port', type=int, help='The port', required=True)
parser.add_argument('-usr', '--username', type=str, help='Username for the authentication', required=True)
parser.add_argument('-psw', '--password', type=str, help='Password fot the authentication', required=True)
parser.add_argument('-t', '--timeout', type=int, help='Connection timeout', default=10)
parsed = parser.parse_args()


def check_host(host: str) -> bool:
    if host.count('.') == 3 and not any([not i.isdigit() for i in host.split('.')]):
        return bool(re.match(r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$', host))
        
    if host.split('.')[-1].isdigit():
        return False
        
    return bool(re.match(r'^((([A-Za-z0-9\-\_])+\.)+)?([A-Za-z0-9\-\_])+\.([A-Za-z0-9\-\_])+$', host))


def check_port(port: int) -> bool:
    return 0 < port < 65536


if __name__ == '__main__':
    if not check_host(parsed.host) or not check_port(parsed.port):
        parser.print_help()
        sys.exit(1)

        
    print(f'IP: {parsed.host}')
    print(f'PORT: {parsed.port}')
    print(f'Username: {parsed.username}')
    print(f'Password: {parsed.password[:-len(parsed.password) // 2] + '*' * (len(parsed.password) // 2)}')
    print(f'Timeout: {parsed.timeout}')
    
    try:
        conn = SocketHandler()
        login = Login(conn)
        
        conn.settimeout(parsed.timeout)
        
        print("Connecting...")
        conn.connect((parsed.host, parsed.port))
        
        print("Authenticating...")
        token = login.login(parsed.username, parsed.password)
        
        if token:
            print("Authenticated!")
            print(f"Token: {token}")
            
            conn.unsafe_send(MessageTypes.MESSAGE.value.to_bytes(1, 'little'))
            conn.send_int_bytes(token.encode(encoding='utf-8', errors='strict') + b'/exit')
            conn.close()
            
            print("Exited")
        else:
            print("Authentication failed")
            conn.close()
    
    except Exception as ex:
        print(f'Unexpected error: {ex}')
