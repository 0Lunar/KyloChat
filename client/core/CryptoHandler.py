from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend
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
    """ Wrapper to handle encryption during connection """    
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
        """
        Generate a 256-bit AES key
        
        Returns:
            key: the AES key
        """
        return token_bytes(32)

    @staticmethod
    def Generate_HMAC_key() -> bytes:
        """
        Generate a 256-bit HMAC key
        
        Returns:
            key: the HMAC key
        """
        return token_bytes(32)
    
    @staticmethod
    def Generate_nonce() -> bytes:
        """
        Generates a 128-bit nonce
        
        Returns:
            nonce: the random generated nonce
        """
        return token_bytes(16)

    @staticmethod
    def random_bytes(length: int) -> bytes:
        """
        Wrapper for `secrets.token_bytes`, allows for cryptographically secure random bytes
        
        Args:
            length: the length of the payload
        
        Returns:
            data: the payload generated with the CSPRNG
        """
        return token_bytes(length)
    
    
    def New_ECC(self) -> None:
        """ Generate a new x25519 key for key exchange """
        self.priv_key = X25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        
    
    def ECC_export_pub_key(self) -> (bytes | None):
        """
        Export the local public x25519 key
        
        Returns:
            pub_key: `None` if not generater, `bytes` if exported successfully
        """
        if self.pub_key:
            return self.pub_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        
        return None
    
    
    def ECC_import_pub_bytes(self, pub_key: bytes) -> None:
        """
        Import a remote public x25519 key
        
        Args:
            pub_key: the pubblic key to import
        """
        self.remote_pub = X25519PublicKey.from_public_bytes(pub_key)
        
        
    def ECC_calc_key(self) -> (bytes | None):
        """
        Calculate the shared x25519 key
        
        Returns:
            shared_key: The x25519 key derived with HKDF
        """
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
        """
        Import the server certificate
        
        Args:
            cert: the certificate in `bytes`
        """
        self.cert = serialization.load_ssh_public_key(
            data=cert
        )
        
    
    def CERT_Verify(self, data: bytes, sign: bytes) -> bool:
        """ 
        Verify data signed with the server's certificate
        
        Args:
            data: the data to verify
            sign: the data signature
        
        Returns:
            result: `True` on valid signature, `False` on invalid signature
        """
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
        """
        Save the server certificate to a file (default: `.cache/fingers.pub`)
        
        Args:
            hostname: the host to which to associate the certificate
            fingerprint_file: the file in which to save the certificate (default: `.cache/fingers.pub`)
        """
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
        """
        Verify the certificate with the one saved in the cache file (default: .cache/fingers.pub)
        
        Args:
            hostname: the hostname to check
            fingerprint_file: the file to search for certificates (default: `.cache/fingers.pub`)
        
        Returns:
            result: `True` if the certificate does not exist or is valid, `False` if the certificate does not match
        """
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
        """
        Create a new AES session
        
        Args:
            key: the AES key, if set to `None`, is generated automatically
        """
        self.aes_key = key or self.Generate_AES256_key()
    
    
    def AES_Encrypt(self, nonce: bytes, msg: bytes) -> (bytes | None):
        """
        Encrypt data with AES-CTR
        
        Args:
            nonce: sequence of random bytes to initialize the encryption
            msg: the message to encrypted
        
        Returns:
            encrypted: `bytes` if successfully encrypted, `None` if an error has occurred
        """
        if not self.aes_key:
            raise RuntimeError("Missing AES key")
                
        try:
            aes = Cipher(
                algorithm=AES256(self.aes_key),
                mode=CTR(nonce),
                backend=default_backend()
            )

            encryptor = aes.encryptor()
            encrypted_msg = encryptor.update(msg) + encryptor.finalize()

            return encrypted_msg
        except Exception as ex:
            return None
    

    def AES_Decrypt(self, nonce: bytes, encrypted_msg: bytes) -> (bytes | None):
        """
        Decrypt data with AES-CTR
        
        Args:
            nonce: sequence of random bytes to initialize the decryption
            encrypted_msg: the message to decrypt
        
        Returns:
            encrypted: `bytes` if successfully decrypted, `None` if an error has occurred
        """
        if not self.aes_key:
            raise RuntimeError("Missing AES key")
        
        try:
            aes = Cipher(
                algorithm=AES256(self.aes_key),
                mode=CTR(nonce),
                backend=default_backend()
            )
            
            decryptor = aes.decryptor()
            decrypted_msg = decryptor.update(encrypted_msg) + decryptor.finalize()

            return decrypted_msg
        except Exception as ex:
            return None
    

    def New_HMAC(self, key: bytes | None = None) -> None:
        """
        Create a new HMAC session
        
        Args:
            key: the HMAC key, if set to `None`, is generated automatically
        """
        self.hmac_key = key or self.Generate_HMAC_key()
    

    def Sign_HMAC(self, msg: bytes) -> bytes:
        """
        Sign data with HMAC (Encrypt-than-Mac)
        
        Args:
            msg: the data to sign
        
        Returns:
            sign: the signature of the message
        """
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
        """
        Verify signed data with HMAC
        
        Args:
            msg: the message to verify
            signature: the message signature
        
        Returns:
            result: `True` on valid signature, `False` on invalid signature
        """
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