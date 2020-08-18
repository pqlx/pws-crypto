from typing import Callable
import struct
import secrets

from pws.hash import SHA1 as sha1

from pws.asymmetric.rsa.helpers import AbstractText, int_to_bytes, bytes_to_int
from pws.asymmetric.rsa.error import BadPKCS1PaddingException, BadOAEPPaddingException


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

HashFunc = Callable[[bytes], bytes]

def _oaep_mgf(message: bytes, size: int, hash_func: HashFunc):
    cnt  = 0
    result = b""
    while len(result) < size:
        c = message + struct.pack(">I", cnt)
        result += hash_func(c)

    return result[:size]

def _oaep_xor(a: bytes, b: bytes):
    assert len(a) == len(b)

    return bytes([x ^ y for x,y in zip(a, b)])

def pad_oaep(
        m_: AbstractText,
        n_size: int,
        label: bytes=b"",
        hash_func: HashFunc=lambda x: sha1(x).digest) -> AbstractText:
    
    if isinstance(m_, int):
        m = int_to_bytes(m_)
    else:
        m = m_
    
    message_len = len(m)
    l_hash = hash_func(label)
    hash_len = len(l_hash) 
    
    ps = b"\x00" * (n_size - message_len - 2 * hash_len - 2)

    db = l_hash + ps + b"\x01" + m
    
    assert len(db) == n_size - hash_len - 1

    seed = secrets.token_bytes(hash_len)
    
    db_mask = _oaep_mgf(seed, n_size - hash_len - 1, hash_func=hash_func)
    masked_db = _oaep_xor(db, db_mask)
    
    seed_mask = _oaep_mgf(masked_db, hash_len, hash_func=hash_func)
    masked_seed = _oaep_xor(seed, seed_mask)

    em = b"\x00" + masked_seed + masked_db

    if isinstance(m_, int):
        return bytes_to_int(em)
    else:
        return em

def unpad_oaep(
        m_: AbstractText,
        n_size: int,
        label: bytes=b"",
        hash_func: HashFunc=lambda x: sha1(x).digest) -> AbstractText:
    
    if isinstance(m_, int):
        # We need to account for the automatically stripped 00 byte
        m = b"\x00" + int_to_bytes(m_)
    else:
        m = m_

    l_hash = hash_func(label)
    hash_len = len(l_hash)

    y, masked_seed, masked_db = m[0:1], m[1:(1 + hash_len)], m[(1+hash_len):]

    if not ( len(y) == 1 and len(masked_seed) == hash_len and len(masked_db) == (n_size - hash_len - 1)):
        raise BadOAEPPaddingException("Failed decomposition of padded plaintext into components.")
    
    if y != b"\x00":
        raise BadOAEPPaddingException("Failed first byte check: Y byte nonzero")

    seed_mask = _oaep_mgf(masked_db, hash_len, hash_func=hash_func)
    seed = _oaep_xor(masked_seed, seed_mask)

    db_mask = _oaep_mgf(seed, n_size - hash_len - 1, hash_func=hash_func)
    db = _oaep_xor(masked_db, db_mask)

    l_hash_prime, remainder = db[:hash_len], db[hash_len:]
    
    if len(l_hash_prime) != hash_len:
        raise BadOAEPPaddingException("Failed decomposition of label hash")
    
    if l_hash_prime != l_hash:
        raise BadOAEPPaddingException(f"Failed label hash check: {l_hash_prime}, expected {l_hash}")
    
    try:
        delimiter_idx = remainder.index(b"\x01") 
    except ValueError: # subsection not found
        raise BadOAEPPaddingException("Delimiter byte 01 not found in padded plaintext")

    if sum(remainder[:delimiter_idx]) != 0:
        raise BadOAEPPaddingException(f"Padding bytes not all 00: {remainder[:delimiter_idx]}, expected{bytes(delimiter_idx)}")

    unpadded = remainder[delimiter_idx+1:]
    
    if isinstance(m_, int):
        return bytes_to_int(unpadded)
    else:
        return unpadded
    
