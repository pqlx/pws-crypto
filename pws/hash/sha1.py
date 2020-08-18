import struct
from pws.hash.abstracthash import Hash


class SHA1(Hash):


    @staticmethod
    def pad(data: bytes) -> bytes:
        
        # Padding routine as follows
        # Start by appending a `1` bit to the message
        # Proceed by appending `0` bits to the message until the length in bits is congruent to 448 (mod 512).
        # append 8 bytes of original length to message
        
        # Note that this padding routine is virtually the same as the one from MD5.
        # a difference that should be noted is that for sha-1 every value is big-endian

        bit_length = 8 * len(data)
        pad_length_bits = (448 - (bit_length + 1)) % 512 + 1

        assert (pad_length_bits & 0b111) == 0

        pad_length_bytes = pad_length_bits // 8
        
        padded = data + b"\x80" + b"\x00" * (pad_length_bytes - 1)

        # append eight bytes of length, big-endian
        padded += struct.pack(">Q", bit_length)

        # Padded data should be divisible by 512 bits ( = 64 bytes)

        return padded

    
    def compute_digest(self) -> bytes:
        
        # Computing the hash is indeed very similar to MD5.
        # These two hash algorithms both use the Merkle–Damgård construction

        h_0, h_1, h_2, h_3, h_4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
        padded = self.pad(self._plaintext) 

        # Left rotate x by c bits.
        lr = lambda x, c: ((x << c) | (x >> (32-c)))
        u32 = lambda x: x & 0xffffffff
        
        # For every 512 bit block..
        for n in range(0, len(padded), 64):
            
            block = bytearray(padded[n:n+64])
            

            def w_get(idx: int) -> int:
                # Fetch big-endian 32-bit unsigned integer at index `idx` in block.
                return struct.unpack(">I", block[4*idx:4*(idx+1)])[0]
            
            def w_set(idx: int, value: int) -> None:
                # Set big-endian 32-bit unsigned integer at index `idx` to `value` in block
                block[4*idx:4*(idx+1)] = struct.pack(">I", u32(value))

            # Extend the sixteen 32-bit words into eighty ones.
            block.extend(b"\x00" * ((80 - 16) * 4))
            
            for i in range(16, 80):
                w_set(i, lr( (w_get(i - 3) ^ w_get(i - 8) ^ w_get(i - 14) ^ w_get(i - 16)), 1)) 
            
            # Initialize hash values for chunk.
            a, b, c, d, e = h_0, h_1, h_2, h_3, h_4 

            for i in range(0, 80):

                # 60-79
                if i >= 60:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                # 40 - 59
                elif i >= 40:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                
                # 20 - 39
                elif i >= 20:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                
                # 0 - 19
                else:
                    f = (b & c) | (~b & d)
                    k = 0x5A827999
                
                f = u32(f)

                temp = u32(lr(a, 5) + f + e + k + w_get(i))
                e = d
                d = c
                c = u32(lr(b, 30))
                b = a
                a = temp
            
            # Add this chunk's hash to result so far
            h_0 = u32(h_0 + a)
            h_1 = u32(h_1 + b)
            h_2 = u32(h_2 + c)
            h_3 = u32(h_3 + d)
            h_4 = u32(h_4 + e)
        
        # Add it all together in a 160-bit number
        result = (h_0 << 128) | (h_1 << 96) | (h_2 << 64) | (h_3 << 32) | h_4
        
        # Convert it to a sequence of bytes and return.
        return result.to_bytes(160 // 8, "big")

if __name__ == "__main__":

    from pws.hash.hash_test import run_test
    from hashlib import sha1

    run_test("SHA-1", SHA1, sha1)
