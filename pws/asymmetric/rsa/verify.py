from typing import Optional

from pws.asymmetric.rsa.helpers import AbstractText, int_to_bytes, bytes_to_int, byte_length

from pws.asymmetric.rsa.pad import unpad_verify_pss
from pws.hash import SHA1


def verify(m: AbstractText, sigma: AbstractText, e: int, n: int, pad_type: Optional[str]="pss", **kwargs) -> bool:

    if pad_type and not pad_type in ["pss", "none"]:
        raise ValueError("Invalid padding mode \"{pad_type}\" selected. Valid choices are \"pss\", \"none\"")
    

    hash_func = kwargs.get("hash_func", lambda x: SHA1(x).digest)
    
    # We want our signature to be exponentiable
    if isinstance(sigma, bytes):
        sigma = bytes_to_int(sigma)
    
    # We want our message to be hashable
    if isinstance(m, int):
        m = int_to_bytes(m)
    
    decrypted = pow(sigma, e, n)

    
    # takes a digest and a "decrypted" signature
    unpad_verify_function = {
        "pss": lambda m_, a: unpad_verify_pss(m_, a, n_size=byte_length(n), hash_func=hash_func),
        "none": lambda m_, a: m_ == a,
        None: lambda m_, a: m_ == a
    }[pad_type]

    return unpad_verify_function(hash_func(m), decrypted)



