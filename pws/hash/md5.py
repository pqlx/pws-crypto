from typing import Optional
import struct
from math import sin, floor

from pws.hash.abstracthash import Hash


class MD5(Hash):
    """
    Class for managing and computing MD5 digests.

    MD5 is a widely used cryptographic hash function, producing a 128-bit hash value.
    It has been found to suffer from extensive vulnerabilities, and its only valid use
    is as a checksum algorithm to verify data integrity.
    """

    per_round_shifts = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    ]

    constants = None

    # Inherit __init__

    @staticmethod
    def pad(data: bytes) -> bytes:
        """MD5 padding routine.."""
        
        # The padding routine as follows:
        # Start by appending a `1` bit to the message
        # Proceed by appending `0` bits to the message until length in bits congruent to 448 (mod 512)
        # Append 8 bytes of original length to message

        bit_length = 8 * len(data)
        
        # We add the 1 to the bit length because of the extra `1` bit appended in step 1
        # we simply reverse the order of operations and then set the bit because it's easier to do so.
        pad_length_bits = (448 - (bit_length + 1)) % 512 + 1
        
        # The value should be divisible by eight
        assert (pad_length_bits & 0b111) == 0

        pad_length_bytes = pad_length_bits // 8 
        
        
        padded = data + b"\x80" + b"\x00" * (pad_length_bytes - 1)
        
        # append eight bytes of length
        padded += struct.pack("<Q", bit_length)
        
        # Padded data should be divisible by 512 bits ( = 64 bytes)
        assert len(padded) % 64 == 0

        return padded
        
    def compute_digest(self) -> bytes:
        
        if not MD5.constants:
            self.generate_constants()

        a_0, b_0, c_0, d_0 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        padded = self.pad(self._plaintext)
        
        # Left rotate x by c bits.            
        lr = lambda x, c: ((x << c) | (x >> (32-c)))
        u32 = lambda x: x & 0xffffffff

        # Iterate over 512 bit (= 64 byte) blocks
        for n in range(0, len(padded), 64):
            
            block = padded[n:n+64]
            
            def M(idx: int):
                # Fetch little-endian 32-bit unsigned integer at index `idx` in block.
                return struct.unpack("<I", block[4*idx:4*(idx+1)])[0]
            
            # Initialize hash values for this chunk
            A, B, C, D = a_0, b_0, c_0, d_0

            for i in range(64):
            
                # 48 - 63
                if i >= 48:
                    F = C ^ (B | ~D)
                    g = (7 * i) % 16
                
                # 32 - 47
                elif i >= 32: 
                    F = B ^ C ^ D
                    g = (3 * i + 5) % 16
                
                # 16 - 31
                elif i >= 16:
                    F = (B & D) | (~D & C)
                    g = (5 * i + 1) % 16
                
                # 0 - 15
                else:
                    F = (B & C) | (~B & D)
                    g = i
                
                F = u32(F + A + MD5.constants[i] + M(g))
                A = D
                D = C
                C = B

                B += u32(lr(F, MD5.per_round_shifts[i]))
            
            # Add chunk's hash to result so far
            a_0 += A
            b_0 += B
            c_0 += C
            d_0 += D
        
        a_0, b_0, c_0, d_0 = (u32(x) for x in (a_0, b_0, c_0, d_0))
        
        # Produce the final hash value
        return struct.pack("<I", a_0) + struct.pack("<I", b_0) + struct.pack("<I", c_0) + struct.pack("<I", d_0)
    

    @classmethod
    def generate_constants(cls):
        """
        Generate constants needed for md5 digest computation.
        These constants are the integer part of the sines of integers.
        """

        ## precompute 2**32 so that we don't calculate it every iteration.
        e = 2**32
        
        # fill the constants
        cls.constants = [floor(e * abs( sin(i + 1) )) for i in range(64)]

if __name__ == "__main__":
    
    from pws.hash.hash_test import run_test
    from hashlib import md5

    run_test("MD5", MD5, md5)

