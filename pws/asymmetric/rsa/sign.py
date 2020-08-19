from typing import Optional

from pws.asymmetric.rsa.helpers import AbstractText, int_to_bytes, bytes_to_int, byte_length, bit_length
from pws.asymmetric.rsa.pad import pad_pss

from pws.asymmetric.rsa.error import RSASignException

from pws.math import int_pow

def sign(m_: AbstractText, d: int, n: int, pad_type: Optional[str]="pss", **kwrags) -> AbstractText:
    
    if pad_type and not pad_type in ["pss", "none"]:
        raise RSASignException("Invalid padding mode \"{pad_type}\" selected. Valid choices are \"pss\", \"none\"")

    
    pad_function = {
            "pss": lambda x: pad_pss(x, n_size_bits=(bit_length(n) - 1)),
            "none": lambda x: x,
            None: lambda x: x
            }[pad_type]

    m = pad_function(m_)

    if isinstance(m, bytes):
        m = bytes_to_int(m)

    if not (0 <= m <= n):
        raise RSASignException("m too big. Assertion 0 <= m < n should hold at all times")

    sigma = int_pow(m, d, n)

    if isinstance(m_, bytes):
        return int_to_bytes(sigma)
    else:
        return sigma
