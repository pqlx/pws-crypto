from typing import List
from sys import getrecursionlimit, setrecursionlimit

def int_pow(base: int, power: int, modulus: int=None, safe: bool=True):
    """
    Calculate `base` raised to `power`, optionally mod `modulus`
    The python standard library offers the same functionality,
    and this function exists only as a proof of Concept.

    This function only aims to support positive integer operands.

    the `safe` parameter only applies to modular exponentiation.
    for values with a large hamming weight, the recursion limit
    can be hit quite easily, as one round of recursion is needed
    for every set bit. If `safe` is set to true, the recursion
    depth is adjusted accordingly during the computation, then
    restored. 
    
    ---------------------------------------------------------------
    Benchmark compared to native python pow():
    
    pow(a, b, c) 10k times using random pool of a, b, c { [2, 99999999999999999999999999999999999999999999999999999]:
        702 ms ± 5.44 ms per loop (mean ± std. dev. of 7 runs, 1 loop each)
    
    int_pow(a, b, c) 10k times using same pool:
        1.31 s ± 2.81 ms per loop (mean ± std. dev. of 7 runs, 1 loop each)

    """
    
    if base < 0 or power < 0 or (modulus and modulus < 0):
        raise ValueError("Invalid operand. Only positive integer operands allowed.")

    def pow_nomod(base: int, power: int):
        """Calculate `base` raised to `power`."""
        
        # Keep a copy
        base_ = base
        
        for _ in range(power - 1):
            base *= base_
        return base 

    if not modulus:
        return pow_nomod(base, power)

    # Here the fun part comes.
    # There exists an optimization for modular exponentiation which
    # allows for a much faster computation than (base**power) % modulus.

    # the identity `(a * b) mod n = (a mod n) * (b mod n) mod n` aids us here.
    
    # We start by splitting the power up in a sum of powers of two.
        
    n = 0
    
    po2 = []

    while power >> n:
        
        # if the bit is set, we have a match:
        if power & (1 << n):
            po2.append(n)

        n += 1
    
    # We can now represent our evaluation as an expression of the form:
    # (base**(2**a_0) * base**(2**a_1) * ... * base**(2**a_2) ) % modulus
    # which we can calculate quite fast using the identity below


    # Take the highest power of two and evaluate it using our identity.
    # We can fill the cache with the results of all the lower powers, mod n.
    highest = po2[-1] 

    # cache for `base` raised to powers of two, modulus `n`.
    # the indices shall denote the power.
    cache = [None] * (highest + 1)
    
       
    result = cache[0] = base % modulus # base**1 # modulus
    
    # Square, then reduce modulo `modulus`
    for cycle in range(highest):
        result *= result
        result %= modulus

        cache[cycle + 1] = result
    
    def product_mod_n(args: List[int], n: int):
        """ 
        Calculate (base**(2**a_0) * base**(2**a_1) * ... * base**(2**a_k)) mod n, with every `a` in cache.
        """
        
        # BEWARE: this function can easily exceed python max recursion depth (of 1000).
        # for values with a large hamming weight, adjust the recursion depth limit accordingly.

        # Identity: (a * b) mod n = (a mod n) * (b mod n) mod n 
        # this can be applied recursively with relative ease.
        
        # Recursion ending condition:
        
        if len(args) == 1:
            return cache[args[0]]
        #   
        return (cache[args.pop()]) * (product_mod_n(args, n)) % n
    
    if safe:
        # Make sure we won't hit the recursion limit
        
        old = getrecursionlimit()
        setrecursionlimit(999999999)
        result = product_mod_n(po2, modulus)
        setrecursionlimit(old)

        return result
    else:
        return product_mod_n(po2, modulus)
