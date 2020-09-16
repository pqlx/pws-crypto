import random
from enum import Enum

from pws.math.pow import int_pow
from pws.math.gcd import gcd

class PrimalityType(Enum):
    """
    Class to represent a primality of an interger.
    Since there some applicable algorithms in this namespace
    are compositeness tests and some are prime tests, as well
    as the probablistic nature of said test, it is conventient
    to have every such test return a standardized value.
    """

    COMPOSITE = 0
    PROBABLY_PRIME = 1
    POSSIBLY_PRIME = 2
    
    PRIME = 3
    
    # for 1
    NEITHER = 4


def division_test(n: int):
    """
    Small compositeness test by dividing by the first 20 primes.
    """

    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
    
    for p in primes:
        if n % p == 0:
            return PrimalityType.COMPOSITE

    return PrimalityType.POSSIBLY_PRIME

def fermat_test(n: int, rounds: int=2) -> PrimalityType:
    """
    The Fermat compositeness test is a very performant and lightweight test.
    
    Fermat's little theorem states:
    
    if `p` is prime and `a` is not divisible by `p`, then a^{p-1} \equiv 1 (mod p)

    This congruence is unlikely (but far from impossible) to hold for a random `a` with composite `p`.
    Additionally, a powerful contradiction primitive is present:
    if a**(p - 1) (mod n) != 1, the number is composite.

    The odds of a PROBABLY_PRIME number not being prime are inversely proportional to the amount of `rounds`.
    """
    
    assert rounds > 0
    assert n > 0

    # 1 is neither composite nor prime
    if n == 1:
        return PrimalityType.NEITHER
    

    for _ in range(rounds):

        # pick our "witness", a random number `a` such that 1 < a < n-1
        a = random.randint(2, n - 1)
        
        # If a and n share other denominators, n is obviously not prime.
        if gcd(a, n) != 1:
            print(a, n)
            return PrimalityType.COMPOSITE
        
        # compute a**(n-1) mod n
        z = int_pow(a, (n-1), n)
        if z != 1:
            return PrimalityType.COMPOSITE
    
    return PrimalityType.PROBABLY_PRIME

def miller_rabin_test(n: int, rounds: int = 32):
    
    if n in (2, 3):
        return PrimalityType.PRIME
    
    if n == 1:
        return PrimalityType.COMPOSITE

    if not n & 1:
        return PrimalityType.COMPOSITE

    # Let's calculate `r`, d first, such that 2**r * d = n, with odd d
    r, d = 0, n - 1
    
    while not d & 1:
        r += 1
        d >>= 1
    
    for _ in range(rounds):
        
        # pick our "witness", a random number `a` such that 1 < a < n - 1
        
        a = random.randint(2, n - 2)
        
        x = int_pow(a, d, n)
        
        # Fermat's little theorem.. next round
        if x in (1, n - 1):
            continue

        for _ in range(r - 1):
            x = int_pow(x, 2, n)
            if x == n - 1:
                break # next round
        else:
            return PrimalityType.COMPOSITE

    return PrimalityType.PROBABLY_PRIME

# TODO lucas test, erastothenes sieve
