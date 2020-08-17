from typing import Tuple


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Calculates the Greatest Common Divisor (gcd) of the integers `a`, and `b`. 
    Additionally, calculates the Bézout coefficients `x`, `y` associated with a and b, all using the extended Euclidean algorithm
    """
    
    swapped = False
    if a < b:
        a, b = b, a
        swapped = True

    def _recurse_egcd(a: int, b: int):
        """Small stub so the unnecessary compare/swap does not occur for recursion"""

        # No remainder left.
        if a == 0:
            
            return (b, 0, 1)

        gcd, x_0, y_0 = _recurse_egcd(b % a, a)
        
        # Recursively "fill up" bezout coefficients.
        x = y_0 - (b // a) * x_0
        y = x_0
        
        return (gcd, x, y)
    


    gcd, x, y =  _recurse_egcd(a, b)
    
    # If a swap took place previously,
    # we need to swap the associated coefficients as well.
    
    if swapped:
        return gcd, y, x
    else:
        return gcd, x, y

