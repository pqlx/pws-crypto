from typing import Optional, Tuple

from lincongr import solve_lincongr

def modinv(a: int, n: int) -> Optional[Tuple[int, int]]:
    """
    Compute the multiplicative modular inverse of `a` mod n.
    That is, solve the linear congruence a * x \equiv 1 (mod n).

    On success, a solution tuple (base, mod), which represents a solution ` base + mod * k`, with k { Z, is returned.

    If no solution is found (that is, gcd(a, n) != n), None is returned

    """
    
    return solve_lincongr(a, 1, n, simplify=True)

