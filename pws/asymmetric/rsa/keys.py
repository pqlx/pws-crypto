from typing import Tuple, Optional

from pws.asymmetric.rsa.helpers import AbstractText
from pws.asymmetric.rsa.encrypt import encrypt as rsa_encrypt
from pws.asymmetric.rsa.decrypt import decrypt as rsa_decrypt
from pws.asymmetric.rsa.sign import sign as rsa_sign
from pws.asymmetric.rsa.verify import verify as rsa_verify


class RSAPublicKey:
    
    def __init__(self, e, n):
        self.e = e
        self.n = n


    def encrypt(self, m: AbstractText, pad_type: Optional[str]="pkcs1") -> AbstractText:
        return rsa_encrypt(m, self.e, self.n, pad_type)
    
    def verify(self, m: AbstractText, sigma: AbstractText, pad_type: Optional[str]="pss") -> bool:
        return rsa_verify(m, sigma, e=self.e, n=self.n, pad_type=pad_type)

    def __repr__(self):
        return f"RSAPublicKey(e={hex(self.e)}, n={hex(self.n)})"


class RSAPrivateKey:

    def __init__(self, d, n):
        self.d = d
        self.n = n

    def decrypt(self, c: AbstractText, pad_type: Optional[str]="pkcs1") -> AbstractText:

        return rsa_decrypt(c, self.d, self.n, pad_type)
    
    def sign(self, m: AbstractText, pad_type: Optional[str]="pss") -> AbstractText:
        
        return rsa_sign(m, d=self.d, n=self.n, pad_type=pad_type)


    def __repr__(self):
        return f"RSAPrivateKey(d={hex(self.d)}, n={hex(self.n)})"


class RSAKeyPair:

    def __init__(self, pub: RSAPublicKey, priv: RSAPrivateKey):
        self.pub = pub
        self.priv = priv
    
    def __repr__(self):
        return f"RSAKeyPair(pub={self.pub}, priv={self.priv})"
