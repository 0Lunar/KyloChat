from core import SocketHandler, Login, ConnHandler, DBHandler, CommandHandler, Logger
import threading
import socket


IP = "0.0.0.0"
PORT = 5000

hConn = ConnHandler()
hDb = DBHandler()
hCommand = CommandHandler(hDb, hConn)
logger = Logger(use_colors=True)


def HandleConn(conn: SocketHandler) -> None:
    errors = 0
    
    while True:
        try:
            if len((payload := conn.recv_int_bytes())) < 33:
                conn.unsafe_send(int.to_bytes(400, 2, 'little'))
                continue
            
            token, data = payload[:36].decode(encoding='utf-8', errors='ignore'), payload[36:]
                        
            if data == b"/exit":
                logger.info(f"Connection closed from {conn.addr}")
                conn.close()
                break
            
            if not hDb.existToken(token):
                logger.warning(f"Invalid token from {conn.addr}")
                conn.unsafe_send(int.to_bytes(403, 2, 'little'))
                continue
            
            if hDb.checkTokenBan(token):
                logger.warning(f"Banned token from {conn.addr}")
                conn.unsafe_send(int.to_bytes(403, 2, 'little'))
                continue
                
            if hDb.isExpiredToken(token):
                logger.warning(f"Expired token for {conn.addr}")
                conn.unsafe_send(int.to_bytes(401, 2, 'little'))
                continue
            
            logger.info(f"{len(data)} bytes received from {conn.addr}")
            
            _data = data.decode(encoding='utf-8', errors='ignore')
                        
            if hCommand.isCommand(_data):
                conn.unsafe_send(int.to_bytes(100, 2, 'little'))
                
                if hDb.isAdminToken(token):
                    logger.info(f"Executing command: {_data}")
                    out = hCommand.parseCommand(_data)
                    conn.send_int_bytes(out)
                
                else:
                    logger.warning(f"Command denied for {conn.addr}")
                    conn.send_int_bytes(b'[SERVER] [ACCESS DENIED]')
            
            else:
                conn.unsafe_send(int.to_bytes(200, 2, 'little'))
                
                for cn in hConn.get_all_conns():
                    if conn is not cn:
                        cn.send_int_bytes(b'[' + hDb.TokenToUsername(token).encode() + b'] ' + data)

        except Exception as ex:
            logger.error(f"Exception in connection handling for {conn.addr} : {ex}")
            
            if errors == 5:
                logger.critical(f"The maximum error limit has been exceeded for {conn.addr}; exiting")
                break
            
            errors += 1


def HandleHandshake(conn: SocketHandler, addr: tuple[str, int]) -> None:
    try:
        logger.info(f"Starting handshake to {conn.addr}")
        conn.handshake()
        logger.info(f"Handshake completed to {conn.addr}")

        logger.info(f"Requiring credentials for: {conn.addr}")
        log = Login(conn)

        for _ in range(4):
            if log.login():
                break
        else:
            conn.close()
            return

        hConn.add(conn, addr)
        HandleConn(conn)
        
    except Exception as ex:
        conn.close()
        logger.critical(f"HandleHandshake Error: {ex}")


if __name__ == "__main__":
    logger.info("Starting server...")
    
    sh = SocketHandler(socket.AF_INET, socket.SOCK_STREAM)
    sh.bind((IP, PORT))
    
    logger.info("Server started")
    while True:
        try:
            conn, addr = sh.listen()
            t = threading.Thread(target=(HandleHandshake), args=(conn, addr, ))
            t.start()
            logger.info(f"New connection: {addr}")
        except KeyboardInterrupt:
            break
        except:
            logger.error("Error, Connection aborted")