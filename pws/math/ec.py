from pws.math import modinv, modsqrt

class ECurvePoint:
    
    def __init__(self, curve: 'ECurve', x, y):
        self.curve = curve
        self.x = x
        self.y = y

    def copy(self):
        return ECurvePoint(self.curve, self.x, self.y)

    def __neg__(self):
        new_x = self.x
        new_y = (-self.y % self.curve.modulus)

        point = ECurvePoint(self.curve, new_x, new_y)

        assert self.curve.is_element(point)

        return point
    
    def __mul__(self, other):
        if not isinstance(other, int):
            return NotImplemented
    
        Q = self
        R = self.curve.identity
        n = other
        while n > 0:

            if n & 1:
                R = R + Q

            Q = Q + Q
            n = n // 2
        
        return R
    
    def __rmul__(self, other):
        if not isinstance(other, int):
            return NotImplemented

        return self.__mul__(other)

    def __add__(self, other):
        
        if not isinstance(other, ECurvePoint):
            return NotImplemented

        if self == self.curve.identity:
            return other.copy()
        
        if other == self.curve.identity:
            return self.copy()
        
        p = self.curve.modulus

        x1, y1 = self
        x2, y2 = other

        if x1 == x2 and y1 == (-y2 % self.curve.modulus):
            return self.curve.identity.copy()
        
        # calculate the slope
        if self != other:
            l = (((y2 - y1) % p) * modinv( x2 - x1 , p)[0]) % p
        else:
            l = (((3 * pow(x1, 2, p) + self.curve.a) % p) * modinv(2 * y1, p)[0]) % p
        
        x3 = (pow(l, 2, p) - x1 - x2) % p
        y3 = ((l * (x1 - x3) ) - y1) % p

        point = ECurvePoint(self.curve, x3, y3)
        
        assert self.curve.is_element(point)

        return point

    def __eq__(self, other: 'ECurvePoint'):
        assert self.curve == other.curve
        return self.x == other.x and self.y == other.y
    
    def __iter__(self):
        return (_ for _ in (self.x, self.y))

    def __repr__(self):
        return f"ECurvePoint(curve={repr(self.curve)}, x={self.x}, y={self.y})"
    
    def __str__(self):
        return f"({self.x}, {self.y})"

class ECurveIdentity(ECurvePoint):

    def __init__(self, curve: 'ECurve'):

        super(ECurveIdentity, self).__init__(curve, float("inf"), float("inf"))

    def copy(self):
        return ECurveIdentity(self.curve)

    def __neg__(self):
        return self.copy()
    
    def __eq__(self, other: 'ECurvePoint'):
        assert self.curve == other.curve
        return type(other) == ECurveIdentity
    
    def __iter__(self):
        return None

    def __repr__(self):
        return f"ECurveIdentity(curve={repr(self.curve)})"

    def __str__(self):
        return f"Identity element O (point at infinity)"

class ECurve:
    
    """Represents an elliptic curve defined over a finite integer field F_p"""
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.modulus = p
        self.identity = ECurveIdentity(self)

    def is_element(self, point: ECurvePoint):

        if isinstance(point, ECurveIdentity):
            return True

        p = self.modulus
        return pow(point.y, 2, p) == ((point.x**3 + (self.a * point.x) + self.b) % p)

    def point(self, x: int, y: int):
        point = ECurvePoint(self, x, y)

        assert self.is_element(point)
        return point
    
    def points_for_x(self, x: int):
        p = self.modulus
        
        y_squared = (x**3 + self.a * x + self.b) % p
        
        y = modsqrt(y_squared, p)[0]
        
        if y == 0:
            return (self.point(x, 0),)
        
        return (self.point(x, y), self.point(x, (-y % p)))
        

    def __eq__(self, other: 'ECurve'):
        return self.a == other.a and self.b == other.b and self.modulus == other.modulus

    def __repr__(self):
        return f"ECurve(a={self.a}, b={self.b}, p={self.modulus})"

    def __str__(self):
        return f"Elliptic curve y^2 = x^3 + {self.a}x + {self.b} (defined over finite field F_p = {{0, 1, ..., {self.modulus-1}}})"
