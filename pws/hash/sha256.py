import struct
from pws.hash.abstracthash import Hash

class SHA256(Hash):

    constants = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

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
        
        # initialize the results to the initialization vector.
        h = [
            0x6a09e667, 0xbb67ae85, 
            0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
        ]

        padded = self.pad(self._plaintext)
        

        u32 = lambda x: x & ((1 << 32) - 1)
        # right rotate 32-bit integer `x` by `c` bits.
        rr = lambda x, c: u32((x >> c) | (x << (32 - c)))

        for n in range(0, len(padded), 64):
            block = bytearray(padded[n:n+64])

            def w_get(idx: int):
                return struct.unpack(">I", block[4*idx:4*(idx+1)])[0]

            def w_set(idx: int, value: int) -> None:
                block[4*idx:4*(idx+1)] = struct.pack(">I", u32(value))

            block.extend(b"\x00" * ((64 - 16) * 4))

            for i in range(16, 64):
                s = (
                    rr(w_get(i - 15), 7) ^ rr(w_get(i - 15), 18) ^ (w_get(i - 15) >> 3),
                    rr(w_get(i - 2), 17) ^ rr(w_get(i - 2), 19) ^  (w_get(i - 2) >> 10)
                )
                w_set(i, w_get(i - 16) + s[0] + w_get(i - 7) + s[1])
            
            a = h.copy()
            
            for i in range(64):
                S1 = rr(a[4], 6) ^ rr(a[4], 11) ^ rr(a[4], 25)
                ch = (a[4] & a[5]) ^ (~a[4] & a[6])
                t1 = u32(a[7] + S1 + ch + self.constants[i] + w_get(i))
                S0 = rr(a[0], 2) ^ rr(a[0], 13) ^ rr(a[0], 22)
                maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2])
                t2 = u32(S0 + maj)

                for i in range(7, 0, -1):
                    a[i] = a[i - 1]
                
                a[0] = u32(t1 + t2)

                a[4] = u32(a[4] + t1)

            for i in range(8):
                h[i] = u32(h[i] + a[i])

        hash_: bytes = b''.join([struct.pack(">I", h[i]) for i in range(8)])
        return hash_

