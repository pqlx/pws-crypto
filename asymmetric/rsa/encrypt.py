from typing import Optional
import pad as RSAPad

from helpers import AbstractText, int_to_bytes, bytes_to_int

def encrypt(m_: AbstractText, e: int, n: int, pad_type: Optional[str]="pkcs1") -> AbstractText:
    
    if pad_type and not pad_type in ["pkcs1", "oeap", "none"]:
        raise ValueError(f"Invalid padding mode \"{pad_type}\: selected. Valid choices are \"pkcs1\", \"oeap\", \"none\"") 
    
    pad_function = {
        "pkcs1": RSAPad.pad_pkcs1_v1_5,
        "oeap":  RSAPad.pad_oeap,
        "none":  lambda x: x,
        None  :  lambda x: x
    }[pad_type]
    
    # pad our plaintext accordingly
    m = pad_function(m_)

    if isinstance(m, bytes):
        m = bytes_to_int(m)
    
    if not (0 <= m < n):
        print(f"m = {m}")
        raise ValueError("m too big. Assertion 0 <= m < n should hold at all times")

    c =  pow(m, e, n)
    
    if isinstance(m_, bytes):
        return int_to_bytes(c)
    else:
        return c
    
