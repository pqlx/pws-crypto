from typing import Tuple, Optional

from pws.asymmetric.rsa.helpers import AbstractText
from pws.asymmetric.rsa.encrypt import encrypt as rsa_encrypt
from pws.asymmetric.rsa.decrypt import decrypt as rsa_decrypt



class RSAPublicKey:
    
    def __init__(self, e, n):
        self.e = e
        self.n = n


    def encrypt(self, m: AbstractText, pad_type: Optional[str]="pkcs1") -> AbstractText:
        return rsa_encrypt(m, self.e, self.n, pad_type)


    def __repr__(self):
        return f"RSAPublicKey(\n\te={hex(self.e)},\n\tn={hex(self.n)}\n)"


class RSAPrivateKey:

    def __init__(self, d, n):
        self.d = d
        self.n = n

    def decrypt(self, c: AbstractText, pad_type: Optional[str]="pkcs1") -> AbstractText:

        return rsa_decrypt(c, self.d, self.n, pad_type)
    
    def __repr__(self):
        return f"RSAPrivateKey(\n\td={hex(self.d)},\n\tn={hex(self.n)}\n)"


def demo():
    
    import random
    import string
    from pwn import hexdump # TODO find non-pwn alternative!

    modulus = 0x6e3911ee8445b70a36b0ce6d8bf4163ffc9402fd1aacd90051f1da33683ea88bf2a4af02a6a7c400c03b1788767aab359afd3cf4c29215993a4c54f8e1fbfa46c80d38fbd2633f9f3ec893c6c6872db672fed81ed9e8e536154e7b739afccf88afd60c622a50033d474c66a0aee6620f8a61f6017f741dc259fa38bc2de2dfc7

    pub = RSAPublicKey(
            e=0x10001,
            n=modulus
          )
            
    priv = RSAPrivateKey(
            d=0x5e2be2572fa9c496345de1309527692f2824695d48422f70e792440431e77ee77adb1b2f9fa5ac7f9bbda10095817eefe0c8c620b4704d85c9da57ab00a0e196223691157b4d82d6950ef56c20fb2f5316cecf09bca9f1ddc12602a36bec3ed04c9d9410d826ddd6076c61a99f9714a39057cd084a5197ef35fd778f497039d9,
            n=modulus)

    print("[+] Generating random ASCII string sequence `m` of length 64 to encrypt")
    
    selection_space = string.ascii_uppercase + string.ascii_lowercase + string.digits + ' ' 
    m = bytes([ ord(random.choice(selection_space)) for _ in range(0x40)])
    
    print(hexdump(m))
    print(f"== {m}")
    print("-"*80)
    print(pub)
    print("-"*80)

    print("[+] Encrypting `m` with padding scheme: PKCS#1 v1.5")
    
    c = pub.encrypt(m, pad_type="pkcs1")
    print(hexdump(c))

    print("-"*80)
    print(priv)
    print("-"*80)
    print("[+] Subsequently decrypting `c` using the same padding scheme")

    m_2 = priv.decrypt(c, pad_type="pkcs1")

    print(hexdump(m_2))

    print("[*] Checking m_1 == m_2")
    if m == m_2:
        print("[+] Success! Original and decrypted match.")
    else:
        print("[x] Fail! Original and decrypted do NOT match.")


class RSAKeyPair:

    def __init__(self, pub: RSAPublicKey, priv: RSAPrivateKey):
        self.pub = pub
        self.priv = priv

if __name__ == "__main__":
    demo()

