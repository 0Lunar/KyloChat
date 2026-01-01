from cryptography.hazmat.primitives.asymmetric import rsa as RSA
from cryptography.hazmat.primitives.asymmetric import padding as asmpadding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.padding import PKCS7
import bcrypt
from secrets import token_bytes
import socket
import sys
import getpass
import warnings


class CryptoHandler(object):
    def __init__(self) -> None:
        self.AES_BLOCK_SIZE = 16
        self.AES_BLOCK_SIZE_BITS = 128
        self.priv_key = None
        self.pub_key = None
        self.remote_pub = None
        self.aes_key = None
        self.aes_iv = None
        self.hmac_key = None
        pass


    def Generate_AES256_key(self) -> bytes:
        return token_bytes(32)


    def Generate_HMAC_key(self) -> bytes:
        return token_bytes(32)
    

    def Generate_iv(self) -> bytes:
        return token_bytes(16)
    

    def Generate_Bcrypt_Salt(self) -> bytes:
        return bcrypt.gensalt()
    

    def random_bytes(self, length: int) -> bytes:
        return token_bytes(length)


    def New_RSA(self, key_size: int = 2048, exponent: int = 65537):
        self.priv_key = RSA.generate_private_key(exponent, key_size)
        self.pub_key = self.priv_key.public_key()

    
    def RSA_export_pub_key(self) -> (bytes | None):
        if self.pub_key:
            return self.pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
        return None


    def RSA_import_pub_key(self, pub_key: bytes) -> None:
        self.remote_pub = serialization.load_pem_public_key(pub_key)
    

    def RSA_encrypt(self, msg: bytes) -> (bytes | None):
        if self.remote_pub:
            return self.remote_pub.encrypt(
                plaintext=msg,
                padding=asmpadding.OAEP(
                    mgf=asmpadding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )

        elif self.pub_key:
            return self.pub_key.encrypt(
                plaintext=msg,
                padding=asmpadding.OAEP(
                    mgf=asmpadding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
    
        return None


    def RSA_decrypt(self, encrypted: bytes) -> (bytes | None):
        if self.priv_key:
            return self.priv_key.decrypt(
                ciphertext=encrypted,
                padding=asmpadding.OAEP(
                    mgf=asmpadding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )

        return None


    def New_AES(self, key: bytes | None = None, iv: bytes | None = None) -> None:
        self.aes_key = key or self.Generate_AES256_key()
        self.aes_iv = iv or self.Generate_iv()
        self.aes = Cipher(
            algorithm=algorithms.AES256(self.aes_key),
            mode=modes.CBC(initialization_vector=self.aes_iv)
        )
    

    def AES_Update_Iv(self, iv: bytes) -> None:
        if not self.aes_key:
            raise RuntimeError("AES not initialized")

        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes long")
        
        self.aes_iv = iv

        self.aes = Cipher(
            algorithm=algorithms.AES256(self.aes_key),
            mode=modes.CBC(initialization_vector=iv)
        )

    
    def AES_Encrypt(self, msg: bytes) -> (bytes | None):
        try:
            encryptor = self.aes.encryptor()
            pad = PKCS7(block_size=self.AES_BLOCK_SIZE_BITS).padder()
            padded_msg = pad.update(msg) + pad.finalize()
            encrypted_msg = encryptor.update(padded_msg) + encryptor.finalize()

            return encrypted_msg
        except:
            return None
    

    def AES_Decrypt(self, encrypted_msg: bytes) -> (bytes | None):
        try:
            decryptor = self.aes.decryptor()
            unpad = PKCS7(block_size=self.AES_BLOCK_SIZE_BITS).unpadder()
            decrypted_msg = decryptor.update(encrypted_msg) + decryptor.finalize()
            unpadded_msg = unpad.update(decrypted_msg) + unpad.finalize()

            return unpadded_msg
        except:
            return None
    

    def New_HMAC(self, key: bytes | None = None) -> None:
        self.hmac_key = key or self.Generate_HMAC_key()
    

    def Sign_HMAC(self, msg: bytes) -> bytes:
        if not self.hmac_key:
            raise RuntimeError("HMAC not initialized")
        
        hmac = HMAC(
            key=self.hmac_key,
            algorithm=SHA256(),
            backend=None
        )

        hmac.update(msg)
        return hmac.finalize()


    def check_HMAC(self, msg: bytes, signature: bytes) -> bool:
        if not self.hmac_key:
            raise RuntimeError("HMAC not initialized")

        hmac = HMAC(
            key=self.hmac_key,
            algorithm=SHA256(),
            backend=None
        )

        hmac.update(msg)

        try:
            hmac.verify(signature)
            return True
        except:
            return False

    
    def Bcrypt_Hash(self, password: bytes, salt: bytes | None = None) -> bytes:
        salt = salt or bcrypt.gensalt()
        return bcrypt.hashpw(password, salt)


    def Bcrypt_Check(self, password, hashed_password) -> bool:
        return bcrypt.checkpw(password, hashed_password)
    

class SocketHandler(socket.socket):
    def __init__(self, family: socket.AddressFamily | int = -1, type: socket.SocketKind | int = -1, proto: int = -1, fileno: int | None = None) -> None:
        super().__init__(family, type, proto, fileno)
        self.crypto = CryptoHandler()

        if fileno:
            self.connected = True
        else:
            self.connected = False
    

    def listen(self) -> tuple["SocketHandler", tuple[str, int]]:
        if self.connected:
            raise RuntimeError("Socket already connected")

        super().listen()
        conn, remote = super().accept()

        return ( SocketHandler(socket.AF_INET, socket.SOCK_STREAM, 0, conn.detach()), remote )
    

    def connect(self, address) -> None:
        if self.connected:
            raise RuntimeError("Already connected")

        try:
            super().connect(address)
            self.connected = True
        except:
            pass
        
    
    def handshake(self) -> None:
        conn = super()

        try:
            # Public Key RSA
            size = int.from_bytes(conn.recv(2), 'little')
            pub = conn.recv(size)
                        
            self.crypto.RSA_import_pub_key(pub)
            
            print("RSA Key received")
            print(f"RSA Key: \n{pub.decode()}")
            
            aes_key = self.crypto.Generate_AES256_key()
            aes_iv = self.crypto.Generate_iv()
            hmac_key = self.crypto.Generate_HMAC_key()
            
            print(f"Generated AES-256 Key: {aes_key.hex()}")
            print(f"Generated AES IV: {aes_iv.hex()}")
            print(f"Generated HMAC-SHA256 Key: {hmac_key.hex()}")
            
            sys.stdout.flush()
            
            self.crypto.New_AES(aes_key, aes_iv)
            self.crypto.New_HMAC(hmac_key)
            
            encrypted_aes_key = self.crypto.RSA_encrypt(aes_key) or b''
            encrypted_hmac_key = self.crypto.AES_Encrypt(hmac_key) or b''
                        
            conn.send(encrypted_aes_key)
            print("AES key Sent")
            
            conn.send(aes_iv + encrypted_hmac_key)
            print("HMAC key sent")
            
            self.hs = True
            
        except Exception as ex:
            print(f"Handshake server error: {ex}")
            conn.close()
            raise Exception(ex)
        
    
    def recv(self, size: int) -> bytes:
        data = b''
        while len(data) < (size + (-size % 16)):
            chunk = super().recv((size + (-size % 16)) - len(data))
            if not chunk:
                raise RuntimeError("Connection closed")
            data += chunk

        if len(data) < (16 + 32):
            raise RuntimeError("Payload too short")

        iv, data, sig = data[:16], data[16:-32], data[-32:]

        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")

        self.crypto.AES_Update_Iv(iv)
        if not (data := self.crypto.AES_Decrypt(data)):
            raise RuntimeError("Error decrypting msg with AES")

        return data


    def send(self, msg: bytes) -> None:
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
        
        
    def send_short_bytes(self, msg: bytes) -> None:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if not self.hs:
            raise RuntimeError("Missing handshake")
        
        if not msg:
            raise RuntimeError("Invalid Message")
        
        if len(msg) > 0xFFFF:
            raise RuntimeError("PAyload too big")
        
        iv = self.crypto.Generate_iv()
        
        self.crypto.AES_Update_Iv(iv)
        data = self.crypto.AES_Encrypt(msg)
        
        sig = self.crypto.Sign_HMAC(data)
        
        payload = iv + data + sig
        payload_len = len(payload).to_bytes(2, 'little')
        
        super().send(payload_len)        
        super().send(payload)
        
        
    def send_int_bytes(self, msg: bytes) -> None:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if not self.hs:
            raise RuntimeError("Missing handshake")
        
        if not msg:
            raise RuntimeError("Invalid Message")
        
        if len(msg) > 0xFFFFFFFF:
            raise RuntimeError("PAyload too big")
        
        iv = self.crypto.Generate_iv()
        
        self.crypto.AES_Update_Iv(iv)
        data = self.crypto.AES_Encrypt(msg)
        
        sig = self.crypto.Sign_HMAC(data)
        
        payload = iv + data + sig
        
        payload_len = len(payload).to_bytes(4, 'little')
        
        super().send(payload_len)
        super().send(payload)


    def success_code(self) -> None:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if super().send(b'\x00') <= 0:
            raise RuntimeError("Connection error")
    

    def fail_code(self) -> None:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if super().send(b'\x01') <= 0:
            raise RuntimeError("Connection error")
    

    def recv_byte(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        return super().recv(1)
    
    
    def recv_char_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(1)
        payload_len = int.from_bytes(payload_len, 'little')

        data = super().recv(payload_len)
        
        iv, data, sig = data[:16], data[16:-32], data[-32:]
        
        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")
        
        self.crypto.AES_Update_Iv(iv)
        if not (data := self.crypto.AES_Decrypt(data)):
            raise RuntimeError("Error decrypting msg with AES")
        
        return data


    def recv_short_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(2)
        payload_len = int.from_bytes(payload_len, 'little')

        data = super().recv(payload_len)
        
        iv, data, sig = data[:16], data[16:-32], data[-32:]
                
        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")
        
        self.crypto.AES_Update_Iv(iv)
        if not (data := self.crypto.AES_Decrypt(data)):
            raise RuntimeError("Error decrypting msg with AES")
        
        return data
    

    def recv_int_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(4)
        payload_len = int.from_bytes(payload_len, 'little')

        data = super().recv(payload_len)
        
        iv, data, sig = data[:16], data[16:-32], data[-32:]
        
        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")
        
        self.crypto.AES_Update_Iv(iv)
        if not (data := self.crypto.AES_Decrypt(data)):
            raise RuntimeError("Error decrypting msg with AES")
        
        return data
    

    def recv_long_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(8)
        payload_len = int.from_bytes(payload_len, 'little')

        data = super().recv(payload_len)
        
        iv, data, sig = data[:16], data[16:-32], data[-32:]
        
        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")
        
        self.crypto.AES_Update_Iv(iv)
        if not (data := self.crypto.AES_Decrypt(data)):
            raise RuntimeError("Error decrypting msg with AES")
        
        return data


    def unsafe_send(self, msg: bytes) -> int:
        return super().send(msg)
    
    
    def unsafe_recv(self, bufsize: int) -> bytes:
        return super().recv(bufsize)
    

if __name__ == "__main__":
    warnings.warn('Deprecated script', DeprecationWarning)
    
    conn = SocketHandler(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(("127.0.0.1", 5000))
    
    print("Inizio handshake...")
    conn.handshake()
    print("Handshake completata")
    
    print("Login in corso...")
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    print("Invio credenziali...")
    
    conn.send_short_bytes(username.encode())
    status = conn.unsafe_recv(1)
    
    if status != b'\x00':
        print("Errore, username non valido")
        conn.close()
        exit(0)
    
    conn.send_short_bytes(password.encode())
    status = conn.unsafe_recv(1)
    
    if status != b'\x00':
        print("Errore, password non valida")
        conn.close()
        exit(0)
        
    print("Autenticazione eseguita con successo")
    print("Recezione token...")
    
    token = conn.recv_short_bytes().decode(encoding='utf-8', errors='replace')
    
    print(f"Token: {token}")
    
    print("Permi CTRL+C per disconnetterti o digita /exit")
    
    while True:
        try:
            msg = input(" => ")
            
            conn.send_int_bytes(token.encode() + msg.encode())
            
            if msg == "/exit":
                
                break
            
            status = int.from_bytes(conn.unsafe_recv(2), 'little')
            
            print(f"Status code: {status}")
            
            if status == 100:
                resp = conn.recv_int_bytes()
                print(resp.decode(encoding='utf-8', errors='ignore'))
            
        except KeyboardInterrupt:
            conn.send_int_bytes(token.encode() + b'/exit')
            break
        except Exception as ex:
            conn.send_int_bytes(token.encode() + b'/exit')
            print(f"Eccezione: {ex}")
            break
    
    conn.close()
    print("Connessione chiusa")