from pws.symmetric.aes.error import AESPKCS7PaddingException


def pkcs7_pad(plaintext: bytes, block_size: int=0x10) -> bytes:
    """
    Pad a message using the byte padding algorithm described in PKCS#7
    This padding scheme appends n bytes with value n, with n the amount of padding bytes.
    
    The specification describing the padding algorithm can be found here:
    https://tools.ietf.org/html/rfc2315#section-10.3
    """

    assert 0 < block_size < 0x100
    
    # If the plaintext is an exact multiple of block_size, 
    # we need to append a whole block.
    remainder = block_size - (len(plaintext) % block_size)

    return plaintext + bytes([remainder] * remainder)


def pkcs7_unpad(padded: bytes, block_size=0x10):
    """
    Unpad a message encoded using the byte padding algorithm described in PKCS#7
    
    Be VERY careful about disclosing the padding decoding routine result to an adversary.
    A padding oracle WILL render your encryption scheme useless.

    The specification describing the padding algorithm can be found here:
    https://tools.ietf.org/html/rfc2315#section-10.3
    """ 
    assert 0 < block_size < 0x100
    
    n_to_truncate = padded[-1]

    if n_to_truncate == 0 or n_to_truncate > block_size:
        raise AESPKCS7PaddingException(f"Last byte of PKCS#7 padded message '{n_to_truncate:02x}' not in range 01-{block_size:02x} (inclusive)")

    if n_to_truncate > len(padded):
        raise AESPKCS7PaddingException(f"Claimed padding length '{n_to_truncate:02x}' larger that message size '{len(padded):02x}'")

    return padded[:-n_to_truncate]

encoders = {
    "pkcs7": pkcs7_pad
}

decoders = {
    "pkcs7": pkcs7_unpad
}


