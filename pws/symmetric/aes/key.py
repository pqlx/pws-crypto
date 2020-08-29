from pws.symmetric.aes.aes import encrypt_raw, decrypt_raw
from pws.symmetric.aes.error import AESKeyException, AESEncryptionException
from pws.symmetric.aes.modes import ECB_encrypt, ECB_decrypt, CBC_encrypt, CBC_decrypt

class AESKey:
    

    MODES = ("CBC", "ECB")

    @staticmethod
    def _check_key(key: bytes) -> bool:
        return len(key) in (16, 24, 32)
    
    @classmethod
    def _check_mode(cls, mode: str) -> bool:
        return mode in cls.MODES

    def __init__(self, key: bytes):
        if not self._check_key(key):
            raise AESKeyException(f"Invalid AES key length. Should be 128-, 192-, or 256 bits (16-, 24-, or 32 bytes) in length.")

        self.key = key


    def encrypt(self, plaintext: bytes, mode: str="cbc", padding_mode: str="pkcs7"):
        
        mode = mode.upper()

        if not self._check_mode(mode):
            raise AESEncryptionException(f"Invalid encryption mode. Supported modes: {self.MODES}")
        
        mode_routine = {
            "CBC": CBC_encrypt,
            "ECB": ECB_encrypt
        }[mode]

        return mode_routine(
                plaintext=plaintext,
                key=self.key,
                padding_mode=padding_mode)

    def decrypt(self, ciphertext: bytes, mode: str="cbc", padding_mode: str="pkcs7"):

        mode = mode.upper()

        if not self._check_mode(mode):
            raise AESEncryptionException(f"Invalid decryption mode. Supported modes: {self.MODES}")

        mode_routine = {
            "CBC": CBC_decrypt,
            "ECB": ECB_decrypt

        }[mode]

        return mode_routine(
                ciphertext=ciphertext,
                key=self.key,
                padding_mode=padding_mode) 
