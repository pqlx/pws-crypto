from typing import List
from pws.math import GF2, GF2Element

from pws.helpers import lcs8_bit as lcs
"""
This file does not serve any practical purpose, as the AES s-box should be hardcoded
for performance (see: ./state.py).

It only serves as a proof of concept.
"""


def construct_sbox() -> List[int]:

    field = GF2(8, 0b100011011)
    
    lcs_gf2 = lambda b, s: field.element(lcs(b.value, s)) 
    constant_addition = field.element(0x63)

    sbox = []
    
    # since 0's inverse does not exist, but is assumed to 0 for our purpose.
    sbox.append(constant_addition.value)

    for i in range(1, 0x100):
        i = field.element(i)
        
        # we have the matrix:
        # 1 0 0 0 1 1 1 1
        # 1 1 0 0 0 1 1 1
        # 1 1 1 0 0 0 1 1
        # 1 1 1 1 0 0 0 1
        # 1 1 1 1 1 0 0 0
        # 0 1 1 1 1 1 0 0
        # 0 0 1 1 1 1 1 0
        # 0 0 0 1 1 1 1 1
        #
        # which should be multiplied by the inverse
        
        inverse = i.inverse
        
        # this matrix multiplication can be expressed as:
        s = inverse + lcs_gf2(inverse, 1) + lcs_gf2(inverse, 2) + lcs_gf2(inverse, 3) + lcs_gf2(inverse, 4)

        s += constant_addition

        sbox.append(s.value)

    return sbox

