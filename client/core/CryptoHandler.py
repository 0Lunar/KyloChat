from cryptography.hazmat.primitives.asymmetric import rsa as RSA
from cryptography.hazmat.primitives.asymmetric import padding as asmpadding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.padding import PKCS7
from secrets import token_bytes


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
        pass


    def Generate_AES256_key(self) -> bytes:
        return token_bytes(32)


    def Generate_HMAC_key(self) -> bytes:
        return token_bytes(32)
    

    def Generate_nonce(self) -> bytes:
        return token_bytes(12)
        
        
    def Generate_AAD(self) -> bytes:
        return token_bytes(16)
        

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