from pws.math.gcd import gcd

def lcm(*args: int):
    """Calculates the Least Common Multiple (lcm) of the integers `args`."""

    # There is no efficient algorithm to *directly* find the lcm,
    # e.g one that does not rely on prime factorization.

    # However, we can shortcut it by using the gcd.
    # lcm(a, b) = |a * b| / gcd(a, b)
    # note that this only holds for two operands.

    # We'll use the same logic as in gcd.py
    

    def binary_lcm(a: int, b: int):
        """
        Calculates the Least Common Multiple of `a`, and `b`
        """
        return abs(a * b) // gcd(a, b)

    
    if len(args) == 1:
        return args[0]

    result = None
    args = list(args)
    
    while True:

        a, b = args.pop(), args.pop()
        result = binary_lcm(a, b)

        # The list is empty.. we're done!
        if len(args) == 0:
            
            # Return the last result
            return result
        
        args.append(result)
