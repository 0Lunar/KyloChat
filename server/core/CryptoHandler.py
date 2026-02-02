from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
import bcrypt
from secrets import token_bytes
import os


class CryptoHandler(object):
    def __init__(self) -> None:
        self.cert_passwd = os.environ.get("CERT_PASSWD", None)
        self.AES_BLOCK_SIZE = 16
        self.AES_BLOCK_SIZE_BITS = 128
        self.priv_key = None
        self.pub_key = None
        self.remote_pub = None
        self.aes_key = None
        self.aes_aad = None
        self.hmac_key = None
        self.cert = None


    @staticmethod
    def Generate_AES256_key() -> bytes:
        return token_bytes(32)

    @staticmethod
    def Generate_HMAC_key() -> bytes:
        return token_bytes(32)
    
    @staticmethod
    def Generate_nonce() -> bytes:
        return token_bytes(12)
        
    @staticmethod
    def Generate_AAD() -> bytes:
        return token_bytes(16)
        
    @staticmethod
    def random_bytes(length: int) -> bytes:
        return token_bytes(length)
    
    @staticmethod
    def Generate_Bcrypt_Salt() -> bytes:
        return bcrypt.gensalt()


    def New_ECC(self) -> None:
        self.priv_key = X25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        
    
    def ECC_export_pub_key(self) -> (bytes | None):
        if self.pub_key:
            return self.pub_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        
        return None
    
    
    def ECC_import_pub_bytes(self, pub_key: bytes) -> None:
        self.remote_pub = X25519PublicKey.from_public_bytes(pub_key)
        
        
    def ECC_calc_key(self) -> (bytes | None):
        if self.priv_key and self.remote_pub:
            shared_key = self.priv_key.exchange(self.remote_pub)
            
            return HKDF(
                algorithm=SHA256(),
                length=32,
                salt=None,
                info=b'Key Derivation for X25519'
            ).derive(shared_key)
        return None
    
    
    def Load_CERT(self, cert_path: str = 'cert.pem') -> None:
        if not os.path.isfile(cert_path):
            crt = ec.generate_private_key(
                curve=ec.SECP256R1()
            )
            
            self.cert = crt
            
            priv_key = crt.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.cert_passwd.encode()) if self.cert_passwd else serialization.NoEncryption()
            )
            
            with open(cert_path, 'wb') as f:
                f.write(priv_key)
        
        else:
            with open(cert_path, 'rb') as f:
                cert = f.read()
                
            crt = serialization.load_pem_private_key(cert, self.cert_passwd.encode() if self.cert_passwd else None)
            self.cert = crt
            
    
    def Export_CERT_public_key(self) -> bytes:
        if self.cert is None:
            raise RuntimeError("Invalid Certificate")
        
        return self.cert.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        
    
    def CERT_Sign(self, data: bytes) -> bytes:
        if self.cert is None:
            raise RuntimeError("Invalid Certificate")
        
        return self.cert.sign(
            data=data,
            signature_algorithm=ec.ECDSA(SHA256())
        )
        
        
    def CERT_Close(self) -> None:
        self.cert = None


    def New_AES(self, key: bytes | None = None) -> None:
        self.aes_key = key or self.Generate_AES256_key()
        self.aes = AESGCM(self.aes_key)
    
    
    def AES_set_AAD(self, aad: bytes) -> None:
        self.aes_aad = aad 
    
    
    def AES_Encrypt(self, nonce: bytes, msg: bytes, aad: bytes | None) -> (bytes | None):
        aad = aad or self.aes_aad
        
        try:
            pad = PKCS7(block_size=self.AES_BLOCK_SIZE_BITS).padder()
            padded_msg = pad.update(msg) + pad.finalize()
            encrypted_msg = self.aes.encrypt(nonce, padded_msg, aad)

            return encrypted_msg
        except:
            return None
    

    def AES_Decrypt(self, nonce: bytes, encrypted_msg: bytes, aad: bytes | None) -> (bytes | None):        
        aad = aad or self.aes_aad
        
        try:
            unpad = PKCS7(block_size=self.AES_BLOCK_SIZE_BITS).unpadder()
            decrypted_msg = self.aes.decrypt(nonce, encrypted_msg, aad)
            unpadded_msg = unpad.update(decrypted_msg) + unpad.finalize()

            return unpadded_msg
        except Exception as ex:
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