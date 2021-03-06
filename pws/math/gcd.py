from sys import getrecursionlimit, setrecursionlimit 


def gcd(*args: int, safe: bool=True):
    """
    Calculates the Greatest Common Divisor (gcd) of the integers `args`, using the Euclidean algorithm.
    
    `safe` mode will ensure the recursion depth limit will not be reached.
    """
    
    # Calculating the gcd of more than two integers can be done iteratively:
    # i.e gcd(a, b, c) = gcd(gcd(a, b), c) ...
    
    # The Euclidean Algorithm can only compute the gcd of two integers a, b
    # which is what we will implement first. We can just utilize a stack to proceed
    # in the case of len(args) > 2
    
    def binary_gcd(a: int, b: int):
        """
        Calculates the Greatest Common Divisor of `a` and `b`, using the Euclidean algorithm
        """

        # There exists a very elegant method to compute the gcd:
        # we first need to assure that a >= b..
        
        # if b is greater than a, swap them.
        
        if(a < b):
            a, b = b, a
        
        def _recurse_gcd(a: int, b: int):
            """Small stub so the unnecessary compare/swap does not occur for recursion."""
            
            # No remainder left
            if a == 0:
                # gcd has been found, return the remainder
                return b
            
            return _recurse_gcd(b % a, a)
        
        if safe:
            old = getrecursionlimit()
            setrecursionlimit(999999999)
            result = _recurse_gcd(a, b)
            setrecursionlimit(old)
            return result
        else:
            return _recurse_gcd(a, b)

    if len(args) == 1:
        return args[0] # gcd(a) = a
    
    result = None
    args = list(args)    
    
    while True:
        
        a, b = args.pop(), args.pop()  
        result = binary_gcd(a, b)
        
        # The list is empty.. we're done!
        # if the result is 1 we can return prematurely, 
        # because gcd(a, 1) == 1 for any positive integer a
        if len(args) == 0 or result == 1:
            
            # Return the last result.
            return result

        args.append(result)
    

