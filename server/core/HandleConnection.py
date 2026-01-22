from core.CryptoHandler import CryptoHandler
from core.MessageTypes import MessageTypes
from core.SettingsParser import SettingsParser
import socket


class SocketHandler(socket.socket):
    def __init__(self, family: socket.AddressFamily | int = -1, type: socket.SocketKind | int = -1, proto: int = -1, fileno: int | None = None) -> None:
        super().__init__(family, type, proto, fileno)
        self.crypto = CryptoHandler()
        self.MIN_ENC_PAYLOAD = 48
        self.addr = None
        self.settings = SettingsParser()

        if fileno:
            self.connected = True
        else:
            self.connected = False
    

    def accept(self) -> tuple["SocketHandler", tuple[str, int]]:
        if self.connected:
            raise RuntimeError("Socket already connected")

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
        _timeout = conn.timeout
        conn.settimeout(10)

        try:
            # Certificate
            
            self.crypto.Load_CERT(self.settings.certificate)
            cert = self.crypto.Export_CERT_public_key()
            cert_len = len(cert).to_bytes(2, 'little')
                        
            conn.send(cert_len + cert)
            
            # X25519
            
            self.crypto.New_ECC()
            pub = self.crypto.ECC_export_pub_key()
            sign = self.crypto.CERT_Sign(pub)

            if pub is None:
                raise RuntimeError("Error exporting X25519 public key")
            
            payload = pub + sign
            payload_len = len(payload).to_bytes(2, 'little')
            conn.send(payload_len + payload)
            
            payload = conn.recv(32)
            
            self.crypto.ECC_import_pub_bytes(payload)
            aes_key = self.crypto.ECC_calc_key()
            
            self.crypto.New_AES(aes_key)

            # Get HMAC
            enc = conn.recv(92)

            while len(enc) < 92:
                chunk = conn.recv(92 - len(enc))
                if not chunk:
                    raise RuntimeError("Failed to receive complete HMAC key")
                enc += chunk

            if len(enc) != 92:
                raise ValueError(f"Invalid HMAC key length: {len(enc)} != 64")

            nonce, aad, encrypted_hmac_key = enc[:12], enc[12:28], enc[28:]

            self.crypto.AES_set_AAD(aad)
            hmac_key = self.crypto.AES_Decrypt(nonce, encrypted_hmac_key, aad)

            if hmac_key is None or len(hmac_key) != 32:
                raise ValueError("Invalid HMAC key decrypted")

            self.crypto.New_HMAC(key=hmac_key)

            conn.settimeout(None)
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

        nonce, data, sig = data[:12], data[12:-32], data[-32:]

        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")

        if not (data := self.crypto.AES_Decrypt(nonce, data, None)):
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
        
        nonce = self.crypto.Generate_nonce()
        
        data = self.crypto.AES_Encrypt(nonce, msg, None)
        
        sig = self.crypto.Sign_HMAC(data)
        
        payload = nonce + data + sig
        
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
        
        nonce = self.crypto.Generate_nonce()
        
        data = self.crypto.AES_Encrypt(nonce, msg, None)
        
        if data is None:
            raise RuntimeError("Data encryption error (AES)")
        
        sig = self.crypto.Sign_HMAC(data)
        
        payload = nonce + data + sig
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
        
        nonce, data, sig = data[:12], data[12:-32], data[-32:]        
        
        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")
        
        if not (data := self.crypto.AES_Decrypt(nonce, data, None)):
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
        
        if super().send(MessageTypes.SUCCESS.value.to_bytes(1, 'little')) <= 0:
            raise RuntimeError("Connection error")
    

    def fail_code(self) -> None:
        """
        Send the fail code (not encrypted) 0x01
        """
        
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if super().send(MessageTypes.FAILURE.value.to_bytes(1, 'little')) <= 0:
            raise RuntimeError("Connection error")