from typing import Optional, List, Tuple

from modinv import modinv
from gcd import gcd
from prod import prod

def crt(*system: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        """
        Uses the Chinese Remainder Theorem (CRT)
        to find a solution to a system of linear congruences.
        
        `system` contains a list of congruence tuples (a, n),
        denoting the linear congruence x \equiv a (mod n).

        On failure, this function returns None.
        On success, this function returns a tuple (a, n), denoting
        the solution congruence: x \equiv a (mod n)


        The Chinese Remainder Theorem states, for a system of linear congruences:
        {
            x \equiv a_0 (mod n_0)
            x \equiv a_1 (mod n_1)
            ...
            x \equiv a_k (mod n_k)

        }

        with gcd(n_0, n_1, ..., n_k) = 1 (that is: n_0, n_1, ..., n_k are relatively prime)
        AND 0 <= a_j < n_j for every (a_j, n_j),
        
        There exists one, and only one solution x = p such that 0 <= p < \prod_{j=0}^k (n_j)
        AND all solutions x to the system are of the form x \equiv p (mod \prod_{j=0}^k (n_j))
        """
        
       
        moduli = [congruence[1] for congruence in system]
        bases  = [congruence[0] for congruence in system]
        
        
        # First perform some checks.
        
        for congruence in system:
            # If even a single base is greater than the modulus, bail out
            if not (0 <= congruence[0] < congruence[1]):
                return None
            
        # If a single argument is supplied, just return it; no further computation needed
        if len(system) == 1:
            congruence = system[0]
            # reduce a_0 mod n_0
            return (congruence[0] % congruence[1], congruence[1])
        

        # If all the moduli are not relatively prime to eachother, bail out:
        if gcd(*moduli) != 1:
            return None
        
                # Now that we are guaranteed a result, let's start by computing the product of the moduli.
        N = prod(*moduli)
        N_j = lambda j: N // moduli[j]

        # N_j * m_j \equiv q (mod n_j)
        m_j = lambda j: modinv(N_j(j), n = moduli[j])[0]
        
        # p = \sum_{j=0}^k ( N_j * a_j * m_j)
        p = sum( N_j(j) * bases[j] * m_j(j) for j in range(len(system)))
        
        # Be sure to reduce base mod N.
        return (p % N, N)

