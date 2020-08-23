from typing import List

from pws.helpers import xor_bytes as _xorb, lcs32

from pws.symmetric.aes.state import AESState


def generate_round_keys(key: bytes) -> List[bytes]:
    """
    Generate round keys from a supplied AES key.

    AES operates on a 128-bit state, and needs a 128 byte key each round.
    Because the number of rounds `n_rounds` ranges from 11 to 15 inclusive, the key has
    to be expanded to `n_rounds` round keys, and in a determinstic manner.
    
    The AES (rijndael) key scheduling algorithm can be found here:
    https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
    """
    assert len(key) in (16, 24, 32)
    
    round_constants = [
            x.to_bytes(4, 'little') for x in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    ]
    
    # length of key in 32-bit words.
    N = len(key) // 4

    # 32-bit words of the orginal key
    K = lambda x: key[4*x:4*(x+1)]
    
    # number of round keys needed, depending on the key size.
    R = {16: 11, 24: 13, 32: 15}[len(key)]

    # left circular shift for single byte.
    rot_word = lambda x: lcs32(x, 1) 
    
    # substitute word with s-box values.
    sub_word = lambda x: bytes([AESState.sbox[y] for y in x]) 
    
    # expanded keys
    W = []

    for i in range(4 * R):
        
        if i < N:
            v = K(i)
        
        elif i >= N and i % N == 0:
            v = _xorb( _xorb(W[i - N], sub_word(rot_word( W[i - 1] ))), round_constants[(i // N) - 1] )
        
        elif i >= N and N > 6 and i % N == 4:
            v = _xorb(W[i - N], sub_word(W[i - 1]))
        
        else:
            v = _xorb(W[i - N], W[i - 1])
        
        W.append(v)
    
    keys = [b''.join(W[4 * i:4 * (i + 1)]) for i in range(R)]

    return keys


