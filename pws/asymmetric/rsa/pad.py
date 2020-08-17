import secrets
from pws.asymmetric.rsa.helpers import AbstractText, int_to_bytes, bytes_to_int

from pws.asymmetric.rsa.error import BadPKCS1PaddingException 

def pad_pkcs1_v1_5(m_: AbstractText) -> AbstractText:
    """
    Pad a message using the PKCS#1 v1.5 padding scheme
    This involves a few metadata padding bytes as well as
    eight pseudorandomly generated filler bytes
    """ 
    if isinstance(m_, int):
        m = int_to_bytes(m_)
    else:
        m = m_

    # secrets.token_bytes cannot be used here, since there are no guarantees that bytes generated
    # by this function are not equal to zero.
    padded = (b"\x00\x02" + bytes([secrets.choice(range(1, 0x100)) for _ in range(8)]) + b"\x00" + m)

    if isinstance(m_, int):
        return bytes_to_int(padded)
    else:
        return padded


def unpad_pkcs1_v1_5(m_: AbstractText) -> AbstractText:
    """Unpad a message padded with the PKCS#1 v1.5 padding scheme"""
    if isinstance(m_, int):
        # we need to account for the automatically stripped 0 byte at the beginning
        m = b"\x00" + int_to_bytes(m_)
    else:
        m = m_
    
    
    if m[0] != 0x00 or m[1] != 0x02 or m[10] != 0x00:
        raise BadPKCS1PaddingException("Invalid PKCS#1 v1.5 padding metadata byte(s)!")

    if any(x == 0 for x in m[2:10]):
        raise BadPKCS1PaddingException("Invalid PKCS#1 v1.5 padding byte(s) 00")

    unpadded = m[11:]


    if isinstance(m_, int):
        return bytes_to_int(unpadded)
    else:
        return unpadded

def pad_oeap(m: AbstractText) -> AbstractText:
    raise NotImplementedError()

def unpad_oeap(m: AbstractText) -> AbstractText:
    raise NotImplementedError()
