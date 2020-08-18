from typing import Callable
import secrets

from pws.math import lcm
from pws.math import modinv

from pws.asymmetric.rsa.keys import RSAPublicKey, RSAPrivateKey, RSAKeyPair
from pws.math.primality_tests import PrimalityType, division_test, miller_rabin_test

def generate_rsa_prime(bits: int, random_source: Callable[[int], int]=secrets.randbits):
    """Generate a prime of size (in bits) `bits`"""
    
    candidate = random_source(bits)

    if not candidate & 1:
        candidate += 1
    
    def test_primality(n: int) -> bool:
        
        # First do a lightweight divisor test
        if division_test(n) == PrimalityType.COMPOSITE:
             return False
        
        # If `n` passed the divisor test, proceed with Miller-Rabin (40 rounds)
        if miller_rabin_test(n, rounds=40) == PrimalityType.PROBABLY_PRIME:
            return True
        else:
            return False
       
    while not test_primality(candidate):
        candidate += 2
    
    # prime is too big.
    if candidate >= 1 << bits:
        return generate_rsa_prime(bits, random_source)

    return candidate

def generate_keypair(keysize: int = 3072, totient_type: str="carmichael") -> RSAKeyPair:
    
    """
    Generate a RSA Keypair with size (in bits) `keysize`
    """
    
    # We don't supprt moduli smaller than 512 bits, as it is inherently insecure.
    assert keysize >= 512
    
    # Amount of bits should be divisible by eight
    assert not keysize & 111
    
    assert totient_type in ["carmichael", "euler"]

    prime_size = keysize // 2
    
    # Start off by generating two primes.
    p, q = generate_rsa_prime(prime_size), generate_rsa_prime(prime_size)

    # |p - q| > 2**((bits/2)-100)

    if abs(p - q) <= (1 << ((prime_size) - 100)):
        
        # Start over
        generate_keypair(keysize)

    # Compute our modulus
    n = p * q

    if totient_type == "carmichael":
        
        # lambda(pq) = lcm(lambda(p), lambda(q))
        # lambda(z) = phi(z) = (z - 1) with prime z
        # thus we get lcm(p - 1, q - 1)

        totient = lcm(p - 1, q - 1)

    elif totient_type == "euler":
        
        # phi(n) = phi(p) * phi(q), since gcd(p, q) == 1
        # phi(z) == (z - 1), with prime z
        # thus we get phi(n) = phi(p) * phi(q) = (p - 1) * (q - 1)

        totient = (p - 1) * (q - 1)
    
    # Hardcoded e
    e = 65537
    
    # Calculate modular multiplicative inverse of e (mod totient)
    d = modinv(e, totient)[0] 

    priv = RSAPrivateKey(n = n, d = d)
    pub  = RSAPublicKey(n = n, e = e)

    return RSAKeyPair(priv=priv, pub=pub)

    
