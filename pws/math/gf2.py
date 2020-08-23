from typing import Union, Optional

from math import log, floor

class GF2:

    def __init__(self, power: int, modulus: int):
        self.power = power
        self.mod = modulus
        self.order = 1 << power

    def element(self, value: int):
        return GF2Element(self, value)



AbstractGF2 = Union[int, 'GF2Element']

class GF2Element:

    def __init__(self, field: GF2, value: int):
        self.field = field
        self._value = value % field.order
    
    def _gf2_abstract_value(self, value: AbstractGF2):
        if isinstance(value, GF2Element):
            if value.field.power != self.field.power:
                raise ValueError("Operation between two GF(2^p) elements of different field order.")
            return value.value
        return value % self.field.order

    @property
    def value(self):
        return self._value
    
    @property
    def degree(self) -> int:
        """Find the highest polynomial degree of a GF2 element"""
        return floor(log(self._value, 2))

    @property
    def inverse(self) -> Optional['GF2Element']:
        """Find the multiplicative inverse of a GF2 element using the extended euclidean algorithm"""
        
        # 0 has no multiplicative inverse
        if self._value == 0:
            return None

        value = self._value

        mod = self.field.mod
        g = [1, 0]
        
        deg = self.degree - self.field.power
        
        while value != 1:
            if deg < 0:
                mod, value = value, mod
                g[0], g[1] = g[1], g[0]
                deg = -deg

            value ^= mod << deg
            g[0] ^= g[1] << deg

            value %= self.field.order
            g[0] %= self.field.order

            deg = self.field.element(value).degree - self.field.element(mod).degree

        return self.field.element(g[0])


    def __add__(self, other: 'GF2Element') -> 'GF2Element':
        return self.field.element( self._value ^ other.value)
    
    def __radd__(self, other: 'GF2Element') -> 'GF2Element':
        return self.__add__(other)

    def __sub__(self, other: 'GF2Element') -> 'GF2Element':
        return self.__add__(other)

    def __rsub__(self, other: 'GF2Element') -> 'GF2Element':
        return self.__add__(other)
    
    def __mul__(self, other: 'GF2Element') -> 'GF2Element':
        """Multiply self times other (mod self.field.modulus)""" 
        v = [self._value, other.value]

        sigma = 0

        while v[1] > 0:
            if v[1] & 1:
                sigma ^= v[0]
            v[1] >>= 1
            v[0] <<= 1
            if v[0] & self.field.order:
                v[0] ^= self.field.mod  
            
        return self.field.element(sigma)

    def __floordiv__(self, other: 'GF2Element'):
        """Multiply self times other.inverse (mod self.field.modulus)"""
        return self.__mul__(other.inverse)

    def __str__(self):
        return str(self._value)

    def __repr__(self):
        return str(self._value)
