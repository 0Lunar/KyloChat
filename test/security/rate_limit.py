import argparse
import re
import sys
import time

sys.path.append("../")

from libs.CryptoHandler import CryptoHandler
from libs.HandleConnection import SocketHandler
from libs.Login import Login

parser = argparse.ArgumentParser('KyloChat Rate Limit Testing Script', description='A fast script to verify if the KyloChat rate limit is working')
parser.add_argument('-a', '--host', type=str, help='The IP Address / Domain', required=True)
parser.add_argument('-p', '--port', type=int, help='The port', required=True)
parser.add_argument('-usr', '--username', type=str, help='Username for the authentication', required=True)
parser.add_argument('-psw', '--password', type=str, help='Password fot the authentication', required=True)
parser.add_argument('-r', '--rate-limit', type=int, help='Rate limit', default=10)
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
    print(f'Rate limit {parsed.rate_limit}')
    print(f'Timeout: {parsed.timeout}')
    
    try:
        conn = SocketHandler()
        login = Login(conn)
        
        conn.settimeout(parsed.timeout + 5)
        
        print("Connecting...")
        conn.connect((parsed.host, parsed.port))
        
        print("Authenticating...")
        token = login.login(parsed.username, parsed.password)
            
        if not token:
            print("Authentication failed")
            conn.close()
            sys.exit(1)
            
        print("Authenticated!")
        print(f"Token: {token}")
        
        print(f"Flooding {parsed.host}:{parsed.port}...")
        
        for idx in range(parsed.rate_limit + 1):
            conn.send_int_bytes(token.encode() + f'{idx + 1} Flooding...'.encode())
            msg_type = int.from_bytes(conn.unsafe_recv(1), 'little')
            code = int.from_bytes(conn.unsafe_recv(2), 'little')
            
            if code != 200:
                print(f"{idx} Message rejected")
                
            if parsed.rate_limit == idx:
                last_code = code
            
        try:
            start_tm = time.time()
            conn.send_int_bytes(token.encode() + b'Flooding...')
            msg_type = int.from_bytes(conn.unsafe_recv(1), 'little')
            code = int.from_bytes(conn.unsafe_recv(2), 'little')
            end_tm = time.time()
            
            print(f'Delay: {end_tm - start_tm:.02f}')
            print(f'Status code before delay: {last_code}')
            
            if end_tm - start_tm >= parsed.timeout and last_code == 401:
                print("✅ Rate limit working")
                
            else:
                print("❌Rate limit not working")
            
        except TimeoutError:
            print("Timeout exeeded, possible cause: rate limit")
    except Exception as ex:
        print(f'Unexpected error: {ex}')