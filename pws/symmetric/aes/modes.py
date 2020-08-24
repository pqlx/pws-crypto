from typing import Optional, Callable
import secrets

from pws.symmetric.aes.aes import encrypt_raw, decrypt_raw
from pws.symmetric.aes.padding import encoders, decoders
from pws.symmetric.aes.error import AESPaddingException, AESEncryptionException, AESDecryptionException

from pws.helpers import xor_bytes as _xorb

def _get_padding_mode(mode: str, type_: str="encode") -> Callable[[bytes], bytes]:
    """
    Get the correct padding routine given a `mode` and `type_`.
    for `mode`s see ./padding.py
    `type_` can be either "encode" or "decode", for padding encoding / decoding functions.
    """
    assert type_ in ("encode", "decode")

    dict_ = encoders if type_ == "encode" else decoders

    if mode not in dict_.keys():
        raise AESPaddingException(f"Bad padding mode '{mode}'. Choose from: {dict_.keys()}")

    return dict_[mode]


def _iterate_blocks(blocks: bytes, block_size: int = 0x10, forward: bool=True):
    """
    Yield blocks of size `block_size`. Assumes len(bocks) % blocksize == 0
    
    if `forward`, iterate forward, else iterate backward
    """
    
    if forward:
        range_ = range(0, len(blocks), block_size)
    else:
        range_ = range(len(blocks) - block_size, -1, -block_size)

    for i in range(0, len(blocks), block_size):
        yield blocks[i:(i+block_size)]


def ECB_encrypt(plaintext: bytes, key: bytes, padding_mode: str="pkcs7"):
    """
    Using ECB mode, encrypt a variable length `plaintext` using key `key`, with padding mode `padding_mode`

    ECB mode is a mode which encrypt every plaintext block seperately.
    """

    padding_routine = _get_padding_mode(padding_mode, "encode")
    plaintext = padding_routine(plaintext)

    return b''.join([encrypt_raw(block, key) for block in _iterate_blocks(plaintext) ])

def ECB_decrypt(ciphertext: bytes, key: bytes, padding_mode: str="pkcs7"):
    """
    Using ECB mode, decrypt a `ciphertext` using key `key`, with padding mode `padding_mode`

    ECB mode is a mode which decrypts every plaintext block seperately.
    """

    if len(ciphertext) % 0x10 != 0:
        raise AESDecryptionException(f"Ciphertext length was '{len(ciphertext)}', should be integer multiple of 16.")

    plaintext = b''.join([decrypt_raw(block, key) for block in _iterate_blocks(ciphertext)])

    unpadding_routine = _get_padding_mode(padding_mode, "decode")

    return unpadding_routine(plaintext)

def CBC_encrypt(plaintext: bytes, key: bytes, padding_mode: str="pkcs7", iv: Optional[bytes]=None) -> bytes:
    """
    Using CBC mode, encrypt a variable length `plaintext` using key `key`, with padding mode `padding_mode` and IV `iv`.

    If `iv` is None, a random IV will be generated.
    The IV is prepended to the resulting ciphertext transparently.

    CBC is a mode for which every block depends on the previous block. 
    """

    if not iv:
        iv = secrets.token_bytes(0x10)

    if len(iv) != 0x10:
        raise AESEncryptionException(f"IV length was '{len(iv)}', should be 16.")

    padding_routine = _get_padding_mode(padding_mode, "encode")
    plaintext = padding_routine(plaintext)
        
    result = b""

    xor_block = iv

    for block in _iterate_blocks(plaintext):
        
        new_block = _xorb(block, xor_block)
        encrypted_block = xor_block = encrypt_raw(new_block, key)

        result += encrypted_block

    result = iv + result

    return result

def CBC_decrypt(ciphertext: bytes, key: bytes, padding_mode: str="pkcs7") -> bytes:
    """
    Using CBC mode, decrypt a `ciphertext` using key `key`, with padding mode `padding_mode`.
    The IV is assumed to be prepended to the `ciphertext`.

    CBC is a mode for which each block depends on the previous block.
    """

    if len(ciphertext) % 0x10 != 0:
        raise AESDecryptionException(f"Ciphertext length was '{len(ciphertext)}', should be integer multiple of 16.")
    
    plaintext = b""

    iv, ciphertext = ciphertext[:0x10], ciphertext[0x10:]

    xor_block = iv

    for block in _iterate_blocks(ciphertext):

        decrypted_block = decrypt_raw(block, key)
        
        plaintext += _xorb(decrypted_block, xor_block)
        xor_block = block
    
    unpadding_routine = _get_padding_mode(padding_mode, "decode")
    return unpadding_routine(plaintext)
