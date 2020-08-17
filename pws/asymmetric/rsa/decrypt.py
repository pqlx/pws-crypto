from typing import Optional
#import pad as RSAPad

from pws.asymmetric.rsa.helpers import AbstractText, int_to_bytes, bytes_to_int
from pws.asymmetric.rsa.pad import unpad_pkcs1_v1_5, unpad_oeap

def decrypt(c_: AbstractText, d: int, n: int, pad_type: Optional[str]="pkcs1") -> AbstractText:
    
    if pad_type and not pad_type in ["pkcs1", "oeap", "none"]:
        raise ValueError(f"Invalid padding mode \"{pad_type}\: selected. Valid choices are \"pkcs1\", \"oeap\", \"none\"") 
    
    if isinstance(c_, bytes):
        c = bytes_to_int(c_)
    else:
        c = c_

    m = pow(c, d, n)
 
    unpad_function = {

        "pkcs1": RSAPad.unpad_pkcs1_v1_5,
        "oeap": RSAPad.pad_oeap,
        "none": lambda x: x,
        None  : lambda x: x
    }[pad_type]

    m = unpad_function(m)

    if isinstance(c_, bytes):
        return int_to_bytes(m)
    else:
        return m
