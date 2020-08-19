from typing import Optional

from pws.asymmetric.rsa.helpers import AbstractText, int_to_bytes, bytes_to_int, byte_length
from pws.asymmetric.rsa.pad import pad_pkcs1_v1_5, pad_oaep

from pws.math import int_pow

def encrypt(m_: AbstractText, e: int, n: int, pad_type: Optional[str]="pkcs1", **kwargs) -> AbstractText:
    
    if pad_type and not pad_type in ["pkcs1", "oaep", "none"]:
        raise ValueError(f"Invalid padding mode \"{pad_type}\" selected. Valid choices are \"pkcs1\", \"oaep\", \"none\"") 
    
    pad_function = {
        "pkcs1": pad_pkcs1_v1_5,
        "oaep":  lambda x: pad_oaep(x, n_size=byte_length(n), label=kwargs.get("oaep_label", b"")),
        "none":  lambda x: x,
        None  :  lambda x: x
    }[pad_type]
    
    # pad our plaintext accordingly
    m = pad_function(m_)

    if isinstance(m, bytes):
        m = bytes_to_int(m)
    
    if not (0 <= m < n):
        raise ValueError("m too big. Assertion 0 <= m < n should hold at all times")

    c =  int_pow(m, e, n)
    
    if isinstance(m_, bytes):
        return int_to_bytes(c)
    else:
        return c
    
