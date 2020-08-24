from pws.symmetric.aes.aes import encrypt_raw, decrypt_raw
from pws.symmetric.aes.padding import encoders, decoders
from pws.symmetric.aes.error import AESPaddingException

def _get_padding_mode(mode: str, type_: str="encode"):
    
    assert type_ in ("encode", "decode")

    dict_ = encoders if type_ == "encode" else decoders

    if mode not in dict_.keys():
        raise AESPaddingException(f"Bad padding mode '{mode}'. Choose from: {dict_.keys()}")

    return dict_[mode]


def _iterate_blocks(blocks: bytes, block_size: int = 0x10):
    """Yield blocks of size `block_size`. Assumes len(bocks) % blocksize == 0"""
    
    for i in range(0, len(blocks), block_size):
        yield blocks[i:(i+block_size)]


def ECB_encrypt(plaintext: bytes, key: bytes, padding_mode: str="pkcs7"):

    padding_routine = _get_padding_mode(padding_mode, "encode")

    plaintext = padding_routine(plaintext)

    return b''.join([encrypt_raw(block, key) for block in _iterate_blocks(plaintext) ])

def ECB_decrypt(ciphertext: bytes, key: bytes, padding_mode: str="pkcs7"):
    
    plaintext = b''.join([decrypt_raw(block, key) for block in _iterate_blocks(ciphertext)])

    unpadding_routine = _get_padding_mode(padding_mode, "decode")

    return unpadding_routine(plaintext)


