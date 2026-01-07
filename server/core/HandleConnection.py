from core.CryptoHandler import CryptoHandler
import socket


class SocketHandler(socket.socket):
    def __init__(self, family: socket.AddressFamily | int = -1, type: socket.SocketKind | int = -1, proto: int = -1, fileno: int | None = None) -> None:
        super().__init__(family, type, proto, fileno)
        self.crypto = CryptoHandler()
        self.MIN_ENC_PAYLOAD = 48
        self.addr = None

        if fileno:
            self.connected = True
        else:
            self.connected = False
    

    def listen(self) -> tuple["SocketHandler", tuple[str, int]]:
        if self.connected:
            raise RuntimeError("Socket already connected")

        super().listen()
        conn, remote = super().accept()
        conn = SocketHandler(socket.AF_INET, socket.SOCK_STREAM, 0, conn.detach())
        conn.addr = remote

        return (conn, remote )
        
    
    def handshake(self) -> None:
        """
        Start the handshake with the client
        
        Public Key: RSA-2048
        Cipher:     AES-256
        Sign:       HMAC-SHA256
        """
        
        if not self.connected:
            raise RuntimeError("Connection closed")

        conn = super()
        key_size = 2048

        try:
            # Public Key RSA
            self.crypto.New_RSA(key_size=key_size)

            pub = self.crypto.RSA_export_pub_key()

            if pub is None:
                raise RuntimeError("Error exporting RSA public key")

            pub_len = len(pub).to_bytes(length=2, byteorder='little')
            payload = pub_len + pub

            conn.send(payload)

            # Get Encrypted AES Key
            enc = conn.recv(key_size // 8)      #   2048 bit -> 256 bytes

            while len(enc) < (key_size // 8):
                chunk = conn.recv((key_size // 8) - len(enc))
                if not chunk:
                    raise RuntimeError("Failed to receive complete AES key")
                enc += chunk

            aes_key = self.crypto.RSA_decrypt(enc)

            if aes_key is None or len(aes_key) not in (16, 24, 32):
                raise ValueError("Invalid AES key")

            self.crypto.New_AES(key=aes_key)

            # Get HMAC
            enc = conn.recv(64)

            while len(enc) < 64:
                chunk = conn.recv(64 - len(enc))
                if not chunk:
                    raise RuntimeError("Failed to receive complete HMAC key")
                enc += chunk

            if len(enc) != 64:
                raise ValueError(f"Invalid HMAC key length: {len(enc)} != 64")

            iv, encrypted_hmac_key = enc[:16], enc[16:]

            self.crypto.AES_Update_Iv(iv)
            hmac_key = self.crypto.AES_Decrypt(encrypted_hmac_key)

            if hmac_key is None or len(hmac_key) != 32:
                raise ValueError("Invalid HMAC key decrypted")

            self.crypto.New_HMAC(key=hmac_key)

            self.hs = True

        except Exception as ex:
            conn.close()
            raise Exception(ex)
        
    
    def recv(self, size: int) -> bytes:
        """
        Receive N bytes
        
        Args:
            size : number of bytes to receive
        
        Returns:
            out : The payload received
        """
        
        data = b''
        while len(data) < self.MIN_ENC_PAYLOAD + (size + (-size % 16)):
            chunk = super().recv(self.MIN_ENC_PAYLOAD + (size + (-size % 16)) - len(data))
            
            if not chunk:
                raise RuntimeError("Connection closed")
            
            data += chunk

        if len(data) < self.MIN_ENC_PAYLOAD:
            raise RuntimeError("Payload too short")

        iv, data, sig = data[:16], data[16:-32], data[-32:]

        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")

        self.crypto.AES_Update_Iv(iv)
        if not (data := self.crypto.AES_Decrypt(data)):
            raise RuntimeError("Error decrypting msg with AES")

        return data


    def send(self, msg: bytes) -> None:
        """
        Send the message encrypted
        
        Args:
            msg : the message to send
        """
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if not self.hs:
            raise RuntimeError("Missing handshake")
        
        if not msg:
            raise RuntimeError("Invalid Message")
        
        iv = self.crypto.Generate_iv()
        
        self.crypto.AES_Update_Iv(iv)
        data = self.crypto.AES_Encrypt(msg)
        
        sig = self.crypto.Sign_HMAC(data)
        
        payload = iv + data + sig
        
        super().send(payload)
        
    
    def _sendNbytes(self, msg: bytes, n: int) -> None:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if not self.hs:
            raise RuntimeError("Missing handshake")
        
        if not msg:
            raise RuntimeError("Invalid Message")
        
        if len(msg) > ((1 << (8 * n)) - 1) - 0x30:
            raise RuntimeError("Payload too big")
        
        iv = self.crypto.Generate_iv()
        
        self.crypto.AES_Update_Iv(iv)
        data = self.crypto.AES_Encrypt(msg)
        
        if data is None:
            raise RuntimeError("Data encryption error (AES)")
        
        sig = self.crypto.Sign_HMAC(data)
        
        payload = iv + data + sig
        payload_len = len(payload).to_bytes(n, 'little')
        
        super().send(payload_len)
        super().send(payload)
        
        
    def _recvNbytes(self, n: int) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = b''
        
        while len(payload_len) < n:
            chunk = super().recv(n - len(payload_len))
            
            if not chunk:
                raise RuntimeError("Connection Error")
            
            payload_len += chunk
        
        payload_len = int.from_bytes(payload_len, 'little')

        data = super().recv(payload_len)
                
        while len(data) < payload_len:
            chunk = super().recv(payload_len - len(data))
            
            if not chunk:
                raise RuntimeError("Connection Error")
            
            data += chunk
        
        iv, data, sig = data[:16], data[16:-32], data[-32:]        
        
        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")
        
        self.crypto.AES_Update_Iv(iv)
        if not (data := self.crypto.AES_Decrypt(data)):
            raise RuntimeError("Error decrypting msg with AES")
        
        return data
        
        
    def send_char_bytes(self, msg: bytes) -> None:
        """
        Sends a payload of maximum length 255 bytes
        """
        
        self._sendNbytes(msg, 1)
        
    
    def send_short_bytes(self, msg: bytes) -> None:
        """
        Sends a payload of maximum length 65_535 bytes
        """
        
        self._sendNbytes(msg, 2)
        
        
    def send_int_bytes(self, msg: bytes) -> None:
        """
        Sends a payload of maximum length 4_294_967_296 bytes
        """
        
        self._sendNbytes(msg, 4)
        
        
    def send_long_bytes(self, msg: bytes) -> None:
        """
        Sends a payload of maximum length 18_446_744_073_709_551_616 bytes
        """
        
        self._sendNbytes(msg, 8)
    
    
    def recv_char_bytes(self) -> bytes:
        """
        Receives a payload of maximum length 255 bytes
        """
        
        return self._recvNbytes(1)


    def recv_short_bytes(self) -> bytes:
        """
        Receives a payload of maximum length 65_535 bytes
        """
        
        return self._recvNbytes(2)
    

    def recv_int_bytes(self) -> bytes:
        """
        Receives a payload of maximum length 4_294_967_296 bytes
        """
        
        return self._recvNbytes(4)
    

    def recv_long_bytes(self) -> bytes:
        """
        Receives a payload of maximum length 18_446_744_073_709_551_616 bytes
        """
        
        return self._recvNbytes(8)


    def unsafe_send(self, msg: bytes) -> int:
        """
        Send a message without encryption
        
        Args:
            msg : payload to send
            
        Returns:
            out : the number of bytes sent
        """
        
        return super().send(msg)
    
    
    def unsafe_recv(self, bufsize: int) -> bytes:
        """
        Receive a message without encryption
        
        Args:
            bufsize : Number of byte to receive
            
        Returns:
            buffer : the buffere received
        """
        
        return super().recv(bufsize)
    
    
    def success_code(self) -> None:
        """
        Send the success code (not encrypted) b'\x00'
        """
        
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if super().send(b'\x00') <= 0:
            raise RuntimeError("Connection error")
    

    def fail_code(self) -> None:
        """
        Send the fail code (not encrypted) b'\x01'
        """
        
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if super().send(b'\x01') <= 0:
            raise RuntimeError("Connection error")