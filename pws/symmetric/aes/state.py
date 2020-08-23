from typing import Union, Tuple

from pws.math.gf2 import GF2, GF2Element

class AESState:
    """
    Class to represent an AES state.

    AES operates on a 4x4 (= 16) column-major array of bytes (elements of GF(2^8)). 
    Given a block b_0, b_1, ..., b_15, the state is as follows:

    [ b_0  b_4  b_8  b_12 ]
    [ b_1  b_5  b_9  b_13 ]
    [ b_2  b_6  b_10 b_14 ]
    [ b_3  b_7  b_11 b_15 ]
    
    """

    # the rijndael s-box, found by inversion in GF(2^8) with polynomial 0b100011011
    # followed by transformation using an affine matrix multiplication transformation,
    # followed by a constant addition
    sbox =  (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16          
    )


    def __init__(self, block: bytes):
        assert len(block) == 16
        
        self._block = bytearray(block)
    

    def print(self):
        print(str(self))
        print()    


    # Encryption routines

    def add_round_key(self, round_key: bytes):
        assert len(round_key) == 16
        
        for i, b in enumerate(round_key):
            self._block[i] ^= b
    
    def sub_bytes(self):
        
        for i, b in enumerate(self._block):
            self._block[i] = self.sbox[b]
    
    def mix_columns(self):
        
        # GF(2^8) defined by polynomial x^8 + x^4 + x^3 + x + 1
        field = GF2(8, 0b100011011)

        def mix_column(column: bytes):
            
            # multiply the column by matrix:

            # 2 3 1 1
            # 1 2 3 1
            # 1 1 2 3
            # 3 1 1 2

            
            g_1, g_2, g_3 = field.element(1), field.element(2), field.element(3)
            
            c_0, c_1, c_2, c_3 = (field.element(x) for x in column)
            
            
            compute_element = lambda a, b, c, d: (a * c_0 + b * c_1 + c * c_2 + d * c_3).value

            new_column = bytes([
                    compute_element(g_2, g_3, g_1, g_1),
                    compute_element(g_1, g_2, g_3, g_1),
                    compute_element(g_1, g_1, g_2, g_3),
                    compute_element(g_3, g_1, g_1, g_2)
                ])
            
            return new_column
        
        for i in range(4):
            column = mix_column(bytes([self[i, 0], self[i, 1], self[i, 2], self[i, 3]] ))
            self[i, 0], self[i, 1], self[i, 2], self[i, 3] = column


    def shift_rows(self):
        """
        Shifts rows one to three one, two, or three places to the left respectively.

        [ b_0  b_4  b_8  b_12 ]  -------->  [ b_0  b_4  b_5   b_6  ]
        [ b_1  b_5  b_9  b_13 ]  -------->  [ b_5  b_9  b_13  b_1  ]
        [ b_2  b_6  b_10 b_14 ]  -------->  [ b_10 b_14 b_2   b_6  ]
        [ b_3  b_7  b_11 b_15 ]  -------->  [ b_15 b_3  b_7   b_11 ]
        

        """


        # not very efficient, though idiomatic

        for i in range(1, 4):
            
            self[0, i], self[1, i], \
            self[2, i], self[3, i] = (
                    self[((0 + i) % 4), i], self[((1 + i) % 4), i],
                    self[((2 + i) % 4), i], self[((3 + i) % 4), i]
                    )

    

    @staticmethod
    def _resolve_2d_idx(index: Tuple[int, int]):
        result = index[0] * 4 + index[1]
        
        return result
    
    @property
    def block(self):
        return self._block

    # dunder methods

    def __getitem__(self, index: Union[int, Tuple[int, int]]) -> int:

        if isinstance(index, tuple):
            index = self._resolve_2d_idx(index)
        
        assert 0 <= index < 16

        return self._block[index]
    
    def __setitem__(self, index: Union[int, Tuple[int, int]], value: int) -> None:

        if isinstance(index, tuple):
            index = self._resolve_2d_idx(index)

        assert 0 <= index < 16

        self._block[index] = value

    def __str__(self):
        
        h = "{:02x} "
        return f"{h*4}\n{h*4}\n{h*4}\n{h*4}".format(*[self[i % 4, i // 4] for i in range(16)] )
    

    def __repr__(self):
        return f"AESState(block={self._block})"
