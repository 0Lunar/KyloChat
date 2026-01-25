from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from secrets import token_bytes
import os


class CryptoHandler(object):
    def __init__(self) -> None:
        self.AES_BLOCK_SIZE = 16
        self.AES_BLOCK_SIZE_BITS = 128
        self.priv_key = None
        self.pub_key = None
        self.remote_pub = None
        self.aes_key = None
        self.aes_aad = None
        self.hmac_key = None
        self.cert = None
        pass


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
    
    
    def CERT_Import(self, cert: bytes) -> None:
        self.cert = serialization.load_ssh_public_key(
            data=cert
        )
        
    
    def CERT_Verify(self, data: bytes, sign: bytes) -> bool:
        if self.cert is None:
            raise RuntimeError("Invalid Certificate")
        
        try:
            self.cert.verify(
                signature=sign,
                data=data,
                signature_algorithm=ec.ECDSA(SHA256())
            )
            
            return True
        except:
            return False
        
        
    def CERT_Save(self, hostname: str, fingerprint_file: str = ".cache/fingers.pub") -> None:
        if self.cert is None:
            raise RuntimeError("Invalid Certificate")
        
        if fingerprint_file.count("/"):
            fingerprint_dir = os.path.abspath('/'.join(fingerprint_file.split("/")[:-1]))
        
            if not os.path.isdir(fingerprint_dir):
                os.mkdir(fingerprint_dir)
            
        
        crt = self.cert.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode()
        
        with open(fingerprint_file, 'a') as f:
            f.write(f'{hostname} {crt}\n')
    
    
    def CERT_Check(self, hostname: str, fingerprint_file: str = ".cache/fingers.pub") -> bool:
        if self.cert is None:
            raise RuntimeError("Invalid Certificate")
        
        hostname = hostname.strip()
        
        if not os.path.isfile(fingerprint_file):
            self.CERT_Save(hostname, fingerprint_file)
            return True
        
        with open(fingerprint_file, 'rt') as f:
            while (fingerprint := f.readline()) != '':
                host = fingerprint.split(" ")[0].strip()
                
                if host == hostname:
                    break
        
        if not fingerprint:
            self.CERT_Save(hostname, fingerprint_file)
            return True
        
        local_cert = fingerprint[len(host) + 1 : ].strip()
        
        cert = self.cert.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode().strip()
        
        if cert != local_cert:
            return False
    
        return True


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