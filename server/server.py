from core import SocketHandler, Login, DBHandler, CommandHandler, Logger, MessageTypes
from core import ConnHandler
from core import SettingsParser
from core import Decompressor
from core import NetworkBan
import threading
import socket
from colorama import Fore
from time import sleep
from time import time as timestamp
from typing import Optional


# Global handlers
settings = SettingsParser()
netBan = NetworkBan()
hConn = ConnHandler()
hDb = DBHandler()
hCommand = CommandHandler(hDb, hConn)
logger = Logger(log_dir=settings.log_dir, log_file=settings.log_file, use_colors=True)


# Server Configuration
IP = settings.ip
PORT = settings.port


def send_status_code(conn: SocketHandler, code: int) -> None:
    """Send status code to client"""
    assert code > 0 and code < 65536, "Invalid status code"
    
    try:
        conn.unsafe_send(MessageTypes.STATUS_CODE.value.to_bytes(1, 'little'))
        conn.unsafe_send(int.to_bytes(code, 2, 'little'))
    except Exception as e:
        logger.error(f"Failed to send status code {code}: {e}")


def broadcast_system_message(message: bytes, exclude_session: Optional[str] = None) -> None:
    """Broadcast a system message to all connected clients"""
    exclude_set = {exclude_session} if exclude_session else set()
    
    for session_id, client in hConn.get_all_sessions().items():
        if session_id in exclude_set:
            continue
        
        try:
            client.conn.unsafe_send(MessageTypes.MESSAGE.value.to_bytes(1, 'little'))
            client.conn.send_short_bytes(b'SERVER')
            client.conn.send_int_bytes(message)
        except Exception as e:
            logger.error(f"Failed to broadcast to {client.username}: {e}")


def broadcast_user_message(username: str, message: bytes, exclude_session: Optional[str] = None) -> None:
    """Broadcast a user message to all connected clients"""
    exclude_set = {exclude_session} if exclude_session else set()
    
    for session_id, client in hConn.get_all_sessions().items():
        if session_id in exclude_set:
            continue
        
        try:
            client.conn.unsafe_send(MessageTypes.MESSAGE.value.to_bytes(1, 'little'))
            client.conn.send_short_bytes(username.encode(encoding='utf-8', errors='strict'))
            client.conn.send_int_bytes(message)
        except Exception as e:
            logger.error(f"Failed to send message to {client.username}: {e}")


def handle_exit_command(session_id: str, token: str) -> None:
    """Handle client exit/disconnect"""
    client = hConn.get(session_id)
    
    if not client:
        return
    
    username = hDb.TokenToUsername(token) if hDb.existToken(token) else "Unknown"
    
    logger.info(f"Connection closed: {username} ({client.addr})")
        
    # System notification
    if hDb.existToken(token):
        system_msg = Fore.RED.encode(encoding='utf-8', errors='strict') + username.encode(encoding='utf-8', errors='strict') + b' disconnected'
        broadcast_system_message(system_msg, exclude_session=session_id)
    
    # Close connection and remove from handler
    try:
        client.conn.close()
    except:
        pass
    
    hConn.remove(session_id)


def validate_token(conn: SocketHandler, token: str, addr: tuple) -> bool:
    """
    Validate token and send appropriate status code
    
    Returns:
        True if token is valid, False otherwise
    """
    if not hDb.existToken(token):
        logger.warning(f"Invalid token from {addr}")
        send_status_code(conn, 403)
        return False
    
    if hDb.checkTokenBan(token):
        logger.warning(f"Banned token from {addr}")
        send_status_code(conn, 403)
        return False
    
    if hDb.isExpiredToken(token):
        logger.warning(f"Expired token from {addr}")
        send_status_code(conn, 401)
        return False
    
    return True


def handle_command(conn: SocketHandler, token: str, command: str, session_id: str) -> None:
    """Handle command execution"""
    send_status_code(conn, 100)
    
    if hDb.isAdminToken(token):
        logger.info(f"Executing command: {command}")
        output = hCommand.parseCommand(command)
        
        conn.unsafe_send(MessageTypes.MESSAGE.value.to_bytes(1, 'little'))
        conn.send_short_bytes(b'SERVER')
        conn.send_int_bytes(output)
    else:
        username = hDb.TokenToUsername(token)
        logger.warning(f"Command denied for {username} ({conn.addr})")
        
        conn.unsafe_send(MessageTypes.MESSAGE.value.to_bytes(1, 'little'))
        conn.send_short_bytes(b'SERVER')
        conn.send_int_bytes(b'ACCESS DENIED: Admin privileges required')


def handle_message(token: str, message: bytes, session_id: str) -> None:
    """Handle regular message broadcast"""
    username = hDb.TokenToUsername(token)
    broadcast_user_message(username, message, exclude_session=session_id)


def handle_connection(session_id: str) -> None:
    """Main connection handler for an authenticated client"""
    client = hConn.get(session_id)
    
    if not client:
        logger.error(f"Session {session_id} not found")
        return
    
    conn = client.conn
    addr = client.addr
    errors = 0
    msg_cnt = 0
    start_tm = timestamp()
    
    logger.info(f"Starting message handler for {client.username} ({addr})")
    
    while True:
        try:
            msg_type = int.from_bytes(conn.unsafe_recv(1), 'little')
            payload = conn.recv_int_bytes()
            msg_cnt += 1
            
            logger.info(f"Received {len(payload)} bytes from {client.username} ({addr})")
                              
            if msg_cnt > settings.rate_limit:
                logger.warning(f'Rate Limit exceeded from {addr}: {msg_cnt} msg/s')
                send_status_code(conn, 401)
                sleep(settings.rate_limit_sleep)
                msg_cnt = 0
                
                continue
                
            if (timestamp() - start_tm) >= 1:
                msg_cnt = 0
                start_tm = timestamp()
                
            if msg_type == MessageTypes.COMPRESSED_MSG.value:
                decomporessor = Decompressor()
                payload = decomporessor.decompress(payload)
            
            if len(payload) > settings.max_payload_size:
                logger.warning(f'Payload size exceeded from {addr}: {len(payload)} bytes')
                send_status_code(conn, 400)
                
                if settings.slow_down > 0:
                    sleep(settings.slow_down)
                
                continue
            
            if len(payload) < 36:
                logger.warning(f"Invalid payload size from {addr}: {len(payload)} bytes")
                send_status_code(conn, 400)
                
                if settings.slow_down > 0:
                    sleep(settings.slow_down)
                
                continue
            
            token = payload[:36].decode(encoding='utf-8', errors='ignore')
            data = payload[36:]
            
            if data == b"/exit":
                handle_exit_command(session_id, token)
                break
            
            if not validate_token(conn, token, addr):
                if settings.slow_down > 0:
                    sleep(settings.slow_down)
                    
                continue
            
            logger.info(f"Received {len(data)} bytes from {client.username} ({addr})")
            
            message = data.decode(encoding='utf-8', errors='ignore')
            
            if hCommand.isCommand(message):
                handle_command(conn, token, message, session_id)
            else:
                send_status_code(conn, 200)
                handle_message(token, data, session_id)
            
            errors = 0
                        
        except ConnectionResetError:
            logger.warning(f"Connection reset by {client.username} ({addr})")
            handle_exit_command(session_id, token)
            break
        
        except BrokenPipeError:
            logger.warning(f"Broken pipe for {client.username} ({addr})")
            handle_exit_command(session_id, token)
            break
        
        except Exception as ex:
            errors += 1
            logger.error(f"Error handling message from {client.username} ({addr}): {ex}")
            
            if errors >= settings.max_conn_errors:
                logger.critical(f"Maximum error limit ({settings.max_conn_errors}) exceeded for {client.username} ({addr})")
                handle_exit_command(session_id, token)
                break
            
        if settings.slow_down > 0:
            sleep(settings.slow_down)
    
    logger.info(f"Connection handler terminated for {client.username} ({addr})")


def handle_handshake(conn: SocketHandler, addr: tuple[str, int]) -> None:
    """Handle initial handshake and authentication"""
    session_id = None
    
    try:
        logger.info(f"Starting handshake with {addr}")
        conn.handshake()
        logger.info(f"Handshake completed with {addr}")
        
        # Authentication
        logger.info(f"Requiring credentials from {addr}")
        login_handler = Login(conn)
        
        token = None
        
        if settings.login_attempts > 0:
            for attempt in range(1, settings.login_attempts + 1):
                try:
                    token = login_handler.get_login()
                except:
                    logger.warning(f'Connection closed from {addr[0]}')
                    conn.close()
                    return
                    
                if token:
                    logger.info(f"Authentication successful for {login_handler.logged_user} from {addr}")
                    netBan.removeLogin(addr[0])
                    break
                
                logger.warning(f"Login attempt {attempt}/{settings.login_attempts} failed for {addr}")
                netBan.addLogin(addr[0], attempt)
                
                if netBan.countLogin(addr[0]) >= settings.login_attempts:
                    netBan.newBan(addr[0])
                    netBan.removeLogin(addr[0])
                    logger.warning(f"Maximum login attempts exceeded for {addr}")
                    conn.close()
                    return

            else:
                logger.warning(f"Maximum login attempts exceeded for {addr}")
                
                if settings.ban_on_fail:
                    netBan.newBan(addr[0])
                
                conn.close()
                return
        
        else:
            attempt = 1
            
            while True:
                try:
                    token = login_handler.get_login()
                except RuntimeError:
                    logger.warning(f'Connection closed from {addr[0]}')
                    conn.close()
                    return
                
                if token:
                    logger.info(f"Authentication successful for {login_handler.logged_user} from {addr}")
                    break
                
                logger.warning(f"Login attempt {attempt} failed for {addr}")
                attempt += 1

        
        try:
            session_id = hConn.add(conn, addr, login_handler.logged_user)
            logger.info(f"Session {session_id} created for {login_handler.logged_user}")
        except ValueError as e:
            logger.error(f"Failed to add connection: {e}")
            conn.send_short_bytes(b'SERVER')
            conn.send_int_bytes(b'Username already connected')
            conn.close()
            return
        

        # Login notification
        login_message = f"{Fore.GREEN}{login_handler.logged_user}{Fore.RESET} logged in 👋".encode(encoding='utf-8', errors='strict')
        broadcast_system_message(login_message, exclude_session=session_id)
        handle_connection(session_id)
        
    except ConnectionResetError:
        logger.warning(f"Connection reset during handshake from {addr}")
    
    except Exception as ex:
        logger.critical(f"Handshake error from {addr}: {ex}")
    
    finally:
        # Cleanup
        if session_id and hConn.exists(session_id):
            hConn.remove(session_id)
        
        try:
            conn.close()
        except:
            pass


def shutdown_server() -> None:
    """Shutdown the server"""
    logger.info("Shutting down server...")
    
    # Notify all clients
    shutdown_msg = b"Server is shutting down. Goodbye!"
    broadcast_system_message(shutdown_msg)
    
    # Close all connections
    for client in hConn.get_all_sessions().values():
        try:
            client.conn.close()
        except:
            pass
    
    hConn.clear()
    logger.info("Server shutdown complete")


def main() -> None:
    """Main server entry point"""
    logger.info(f"Server settings: \n{settings}")
    logger.info(f"Starting KyloChat Server on {IP}:{PORT}...")
    
    try:
    # Create server socket
        server_socket = SocketHandler(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((IP, PORT))
        server_socket.listen()
    except Exception as ex:
        logger.critical(f"Error starting KyloChat: {ex}")
        return
    
    logger.info(f"Server listening on {IP}:{PORT}")
    logger.info("Press Ctrl+C to stop the server")
    
    try:
        while True:
            try:
                # If the server is full
                if settings.max_conns > 0 and hConn.count() >= settings.max_conns:
                    if settings.sleep_on_full_conns > 0:
                        sleep(settings.sleep_on_full_conns)
                    continue
                
                # Accept new connection
                conn, addr = server_socket.accept()
                
                if settings.white_list and addr[0] not in settings.white_list:
                    logger.warning(f'Connection rejected from {addr}: not in whitelist')
                    conn.close()
                    continue
                
                elif settings.black_list and addr[0] in settings.black_list:
                    logger.warning(f'Connection rejected from {addr}: blacklist')
                    conn.close()
                    continue
                
                elif netBan.isBanned(addr[0]):
                    logger.warning(f'Connection rejected from {addr}: network banned')
                    conn.close()
                    continue
                
                logger.info(f"New connection from {addr}")
                                
                # Handle in new thread
                thread = threading.Thread(
                    target=handle_handshake,
                    args=(conn, addr),
                    daemon=True,
                    name=f"Client-{addr[0]}:{addr[1]}"
                )
                thread.start()
                
            except socket.timeout:
                logger.error("Timeout")
                continue
            
            except Exception as ex:
                logger.error(f"Error accepting connection: {ex}")
    
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    
    finally:
        shutdown_server()
        server_socket.close()
        logger.info("Server stopped")


if __name__ == "__main__":
    main()