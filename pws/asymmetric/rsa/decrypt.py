from typing import Optional
#import pad as RSAPad

from pws.asymmetric.rsa.helpers import AbstractText, int_to_bytes, bytes_to_int, byte_length
from pws.asymmetric.rsa.pad import unpad_pkcs1_v1_5, unpad_oaep

def decrypt(c_: AbstractText, d: int, n: int, pad_type: Optional[str]="pkcs1", **kwargs) -> AbstractText:
    
    if pad_type and not pad_type in ["pkcs1", "oaep", "none"]:
        raise ValueError(f"Invalid padding mode \"{pad_type}\: selected. Valid choices are \"pkcs1\", \"oaep\", \"none\"") 
    
    if isinstance(c_, bytes):
        c = bytes_to_int(c_)
    else:
        c = c_

    m = pow(c, d, n)
 
    unpad_function = {

        "pkcs1": unpad_pkcs1_v1_5,
        "oaep": lambda x: unpad_oaep(x, n_size=byte_length(n), label=kwargs.get("oaep_label", b"")),
        "none": lambda x: x,
        None  : lambda x: x
    }[pad_type]

    m = unpad_function(m)

    if isinstance(c_, bytes):
        return int_to_bytes(m)
    else:
        return m
