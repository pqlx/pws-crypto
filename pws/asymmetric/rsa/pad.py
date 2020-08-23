from typing import Callable
import struct
import secrets

from math import ceil

from pws.hash import SHA1 as sha1

from pws.helpers import xor_bytes as _xor

from pws.asymmetric.rsa.helpers import AbstractText, int_to_bytes, bytes_to_int
from pws.asymmetric.rsa.error import RSAPKCS1PaddingException, RSAOAEPPaddingException, RSAPSSPaddingException


# PKCS #1 v1.5 implementations

def pad_pkcs1_v1_5(m_: AbstractText) -> AbstractText:
    """
    Pad a message using the PKCS#1 v1.5 padding scheme
    
    The PKCS#1 v1.5 padding encoding specification can be found here:
    https://tools.ietf.org/html/rfc2313#section-8 

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
    """
    Unpad a message padded with the PKCS#1 v1.5 padding scheme
    
    The PKCS#1 v1.5 padding decoding specification can be found here:
    https://tools.ietf.org/html/rfc2313#section-9

    """

    if isinstance(m_, int):
        # we need to account for the automatically stripped 0 byte at the beginning
        m = b"\x00" + int_to_bytes(m_)
    else:
        m = m_
    
    
    if m[0] != 0x00 or m[1] != 0x02 or m[10] != 0x00:
        raise RSAPKCS1PaddingException("Invalid PKCS#1 v1.5 padding metadata byte(s)!")

    if any(x == 0 for x in m[2:10]):
        raise RSAPKCS1PaddingException("Invalid PKCS#1 v1.5 padding byte(s) 00")

    unpadded = m[11:]


    if isinstance(m_, int):
        return bytes_to_int(unpadded)
    else:
        return unpadded

HashFunc = Callable[[bytes], bytes]

# OAEP implementations

def _mgf(message: bytes, size: int, hash_func: HashFunc):
    """
    Mask generation function, used for OAEP and PSS padding.
    The mask generation function is similar to a cryptograhpic 
    hash function, except that it supports output of arbitrary lengths.
    """
    
    cnt  = 0
    result = b""
    while len(result) < size:
        c = message + struct.pack(">I", cnt)
        result += hash_func(c)
        cnt += 1

    return result[:size]

_sha1digest = lambda x: sha1(x).digest

def pad_oaep(
        m_: AbstractText,
        n_size: int,
        label: bytes=b"",
        hash_func: HashFunc=_sha1digest
        ) -> AbstractText:
    """
    Pad a message using the OAEP padding scheme
    
    `label` and `hash_func` should be agreed upon between public and private key holder(s).

    The OAEP padding encoding specification can be found here:
    https://tools.ietf.org/html/rfc8017#section-7.1.1
    """

    if isinstance(m_, int):
        m = int_to_bytes(m_)
    else:
        m = m_
    
    message_len = len(m)
    l_hash = hash_func(label)
    hash_len = len(l_hash) 
    
    # the message length is longer than supported (that is: the padded result will be bigger than `n`), bail out.
    if message_len > n_size - 2 * hash_len - 2:
        raise RSAOAEPPaddingException(f"Message too long. Expected value <= {n_size - 2 * hash_len - 2}, got {message_len}")
    
    # generate a padding string ps to fill up all available space with 00 bytes
    # ps may have a length of zero.
    ps = b"\x00" * (n_size - message_len - 2 * hash_len - 2)
    
    # form a data block db using our padding, label hash, delimiter, and message
    db = l_hash + ps + b"\x01" + m
    
    # sanity check: the length of the data block should be equal to the length of n minus the hash length minus 1 (for a null byte)
    assert len(db) == n_size - hash_len - 1
    
    # generate a seed using a cryptographically secure source, with length of hash_len
    seed = secrets.token_bytes(hash_len)
    
    # create a random mask using our mask generation and said seed.
    db_mask = _mgf(seed, n_size - hash_len - 1, hash_func=hash_func)
    
    # xor the data block with the mask
    masked_db = _xor(db, db_mask)
    
    # create a mask for the seed using our masked data block
    seed_mask = _mgf(masked_db, hash_len, hash_func=hash_func)
    masked_seed = _xor(seed, seed_mask)
    
    # make a final encoded message using a null byte, our masked seed, and our masked db.
    # the null byte is prepended to make sure 0 <= m < n
    em = b"\x00" + masked_seed + masked_db
    
    if isinstance(m_, int):
        return bytes_to_int(em)
    else:
        return em

def unpad_oaep(
        m_: AbstractText,
        n_size: int,
        label: bytes=b"",
        hash_func: HashFunc=_sha1digest
        ) -> AbstractText:
    """
    Unpad a message encoded with the OAEP padding scheme
    
    `label` and `hash_func` should be agreed upon between public and private key holder(s).

    The OAEP padding decoding specficiation can be found here:
    https://tools.ietf.org/html/rfc8017#section-7.1.2
    """

    if isinstance(m_, int):
        # we need to account for the automatically stripped 00 byte
        # gotcha: Simply appending a "00" will fail in certain edge cases where the leftmost byte of masked_seed is 00 as well. (approx. 1/256)
        m = int_to_bytes(m_, n_size)
    else:
        m = m_

    l_hash = hash_func(label)
    hash_len = len(l_hash)

    # decompose the padded plaintext into its components
    y, masked_seed, masked_db = m[0:1], m[1:(1 + hash_len)], m[(1+hash_len):]
    
    # simple length checks
    if not ( len(y) == 1 and len(masked_seed) == hash_len and len(masked_db) == (n_size - hash_len - 1)):
        raise RSAOAEPPaddingException("Failed decomposition of padded plaintext into components.")
    
    # if the first byte is not zero, bail out
    if y != b"\x00":
        raise RSAOAEPPaddingException("Failed first byte check: Y byte nonzero")
    
    # recover our seed by generating a seed mask from masked_db
    seed_mask = _mgf(masked_db, hash_len, hash_func=hash_func)
    seed = _xor(masked_seed, seed_mask)
    
    # then recover our data block by generating a data block mask from seed
    db_mask = _mgf(seed, n_size - hash_len - 1, hash_func=hash_func)
    db = _xor(masked_db, db_mask)
    
    # split the stored label hash and the rest of the message
    l_hash_prime, remainder = db[:hash_len], db[hash_len:]
    
    # simple length check
    if len(l_hash_prime) != hash_len:
        raise RSAOAEPPaddingException("Failed decomposition of label hash")
    
    # label integrity check failed.
    if l_hash_prime != l_hash:
        raise RSAOAEPPaddingException(f"Failed label hash check: {l_hash_prime}, expected {l_hash}")
    
    # try getting the delimiter
    try:
        delimiter_idx = remainder.index(b"\x01") 
    
    # if no delimiter is found, bail out.
    except ValueError: # subsection not found
        raise RSAOAEPPaddingException("Delimiter byte 01 not found in padded plaintext")
    
    # if not all bytes before the delimiter are 00, bail out as well.
    if any(remainder[:delimiter_idx]):
        raise RSAOAEPPaddingException(f"Padding bytes not all 00: {remainder[:delimiter_idx]}, expected{bytes(delimiter_idx)}")
    # get the unpadded message
    unpadded = remainder[delimiter_idx+1:]
    
    if isinstance(m_, int):
        return bytes_to_int(unpadded)
    else:
        return unpadded

# PSS implementations

def pad_pss(
        m_: AbstractText,
        n_size_bits: int,
        salt_len: int = 20,
        hash_func: HashFunc=_sha1digest
        ) -> AbstractText:
    """
    Hash, then pad a message using the PSS signature scheme.
    Notice how this differs from encryption padding schemes, where
    the whole message `m` is padded, instead of its hash.
    
    `salt_len` and `hash_func` should be agreed upon between public and private key holder(s).
    `n_size_bits` should be ONE LESS than the minimum amount of bits needed to represent `n`,
    so that 0 <= m < n can be guaranteed at all times (if barely).

    The PSS hashing and padding encoding specification can be found here:
    https://tools.ietf.org/html/rfc8017#section-9.1.1

    """
   
    # salt length should be non-negative.
    assert salt_len >= 0
    
    # the length in bytes needed.
    n_size = ceil( n_size_bits / 8)
    
    if isinstance(m_, int):
        m = int_to_bytes(m_)
    else:
        m = m_

    # start by taking the message hash, and its length.
    m_hash = hash_func(m)
    hash_len = len(m_hash)
    
    # if the padded length is bigger than supported (that is, the padded result will be bigger than n), bail out.
    # this should rarely, if never, occur, because a salt length of i.e 20 is more than enough, and hash functions
    # do not tend to give terribly large outputs. An RSA key modulus should be AT LEAST 512 bits = 64 bytes.
    if n_size < hash_len + salt_len + 2:
        raise RSAPSSPaddingException(f"Total size {hash_len + salt_len + 2} too large for key size {n_size} bytes. Consider using a smaller salt.")
    
    # generate a salt of length `salt_len`. it is possible for salt_len to be 0, in which case a deterministic
    # signature is generated (which is not advised).
    salt = secrets.token_bytes(salt_len)
    
    # generate a message M' composed of eight null bytes, the message hash, and the salt.
    m_prime = b"\x00" * 8 + m_hash + salt
    
    # take its hash, H ( = m_prime_hash )
    m_prime_hash = hash_func(m_prime)
    
    # create a padding string ps to fill up the remaining bytes. the length of ps may be zero.
    ps = b"\x00" * (n_size - salt_len - hash_len - 2)
    
    # create a data bock, consisting of the padding string ps, a delimiter byte 01, and the salt.
    db = ps + b"\x01" + salt
    
    # sanity check. db should be just large enough to be able to add a hash and byte 0xbc
    assert len(db) == n_size - hash_len - 1
    
    # generate a mask for the data block, using H ( = m_prime_hash), and mask the data block with it.
    db_mask = _mgf(m_prime_hash, n_size - hash_len - 1, hash_func=hash_func)
    masked_db = bytearray(_xor(db, db_mask))
    
    # to make sure 0 <= m < n, we need to zero the leftmost n_size * 8 - n_size_bits bits
    # that is: the amount of bits n_size is too big.
    # we need to do this because PSS makes maximum use of the size provided, instead of lazily
    # prepending 00, like other padding schemes.

    to_zero = 8 * n_size - n_size_bits
    
    if to_zero:
        # bit magic: clear the leftmost `to_zero` bits of masked_db[0].
        masked_db[0] &= ((1 << (8 - to_zero)) - 1)
    
    masked_db = bytes(masked_db)
    
    # generate a final encoded message em, using our masked_db, our H ( = m_prime_hash) and an identification byte 0xbc
    em = masked_db + m_prime_hash + b"\xbc"

    if isinstance(m_, int):
        return bytes_to_int(em)
    else:
        return em

def unpad_verify_pss(
        m_hash: bytes, # original message hash
        em_: AbstractText, # signature
        n_size_bits: int,
        salt_len: int = 20,
        hash_func: HashFunc=_sha1digest
        ) -> bool:
    """
    Unpad and verify a message (hash) encoded with the PSS padding scheme.
    Notice that again, this differs from the decryption padding schemes.
    
    A message digest `m_hash` of the message to be verified
    should be provided, which is compared to the unpadded message.
    
    `salt_len` and `hash_func` should be agreed upon between public and private key holder(s).
    `n_size_bits` should be ONE LESS than the minimum amount of bits needed to represent `n`,
    so that 0 <= m < n can be guaranteed at all times (if barely).
    
    The PSS verification and padding decoding specification can be found here:
    https://tools.ietf.org/html/rfc8017#section-9.1.2
    """

    # salt length should be non-negative
    assert salt_len > 0
    
    # the length in bytes needed.
    n_size = ceil(n_size_bits / 8)
    
    if isinstance(em_, int):
        em = int_to_bytes(em_, n_size)
    else:
        em = em_
    
    # compute the length of m_hash to aid message decomposition
    hash_len = len(m_hash)
    
    # make sure the encoded message is not too big for the parameters supplied.
    if len(em) < hash_len + salt_len + 2:
        raise RSAPSSPaddingException(f"Total size needed ({hash_len + salt_len + 2}) too big for message em of length {len(em)}")
    
    # Verify the identification byte.
    if em[-1] != 0xbc:
        raise RSAPSSPaddingException(f"Last byte of padded plaintext not 0xbc: rather {hex(em[-1])}")
    
    # decompose the encoded message into the masked data block and hash
    masked_db, h = bytearray(em[:-(hash_len+1)]), em[-(hash_len+1):-1]
    
    to_be_zero = 8 * n_size - n_size_bits
     
    # Make sure the bit remainder is zero, as should be done by the pss encoding routine.
    if to_be_zero:
        
        # bit magic: check if the leftmost to_be_zero bits are zero, and if not, bail
        # notice how this mask is just the inverse of the mask used in the `pad_pss` routine.

        if masked_db[0] & (~((1 << (8 - to_be_zero)) - 1) & 0xff) != 0:
            raise RSAPSSPaddingException("Bit remainder of first masked db byte not zero!")
    
    masked_db = bytes(masked_db)
    
    # generate the data block mask, and recover the original data block.
    db_mask = _mgf(h, len(em) - hash_len - 1, hash_func=hash_func)
    db = bytearray(_xor(masked_db, db_mask))
    
    # be sure to clear the leftmost to_be_zero bits again, similar to the encoding routine.
    if to_be_zero:
        db[0] &= ((1 << (8 - to_be_zero)) - 1)
    
    # calculate the length of the padding.
    n_padding = len(em) - hash_len - salt_len - 2
    
    # If there's any non-zero bytes in the padding, bail out.
    if any(db[:n_padding]):
        raise RSAPSSPaddingException(f"Non-zero padding byte encounter: expected {bytes(n_padding)}, got {db[:n_padding]}")
    
    # If there's no delimiter byte 01, bail out.
    if db[n_padding] != 0x01:
        raise RSAPSSPaddingException(f"Delimiter byte does not match: expected 0x01, got {hex(db[n_padding + 1])}")
    
    # fetch the salt from the data block.
    salt = db[-hash_len:]
    if len(salt) != hash_len:
        raise RSAPSSPaddingException(f"Failed decomposition into components of DB")
    
    # Construct the hash again by appending 8 null bytes, the message hash, and the salt.
    m_prime = 8 * b"\x00" + m_hash + salt
    m_prime_hash = hash_func(m_prime)
    
    # Compare the two hashes, if they match the verification has succeeded, else it has failed.
    return m_prime_hash == h
