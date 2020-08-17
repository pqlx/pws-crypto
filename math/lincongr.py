from typing import Union, Optional, List, Tuple

from egcd import egcd # for gcd + bezout coeffs.

def solve_lincongr(a: int, b: int, n: int, simplify: bool=True) -> Optional[ Union[ List[Tuple[int, int]], Tuple[int, int] ] ]:
    """
    Solve a linear congruence a * x \equiv b (mod n)
    
    If `simplify` is set to False, a list of variable length, holding solution tuples (base, mod),
    which represent a solution `base + mod * k`, with k { Z, is returned
    
    If `simplify` is set to True, a single instance of such a solution tuple is returned.
    
    If no solution is found, None is returned

    """

    # Start by reducing a, b mod n
    a %= n
    b %= n
    gcd_a_n, x, y = egcd(a, n)
    
    if not (b / gcd_a_n).is_integer():
        # gcd(a, n) does not evenly divide b. This means there are no solutions
        return None
    
    # all solutions are given by ((bx + nk)/gcd(a, n)) (mod n) with k { [0, gcd(a, n) - 1]
    
    bases = [(b*x + n*k) // gcd_a_n for k in range(0, gcd_a_n)] # all (mod n)
    
    if simplify:
        return (bases[0], n // gcd_a_n )
    else:
        return [ (b, n) for b in bases]
