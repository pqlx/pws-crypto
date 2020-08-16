from typing import Union
import math

AbstractText = Union[int, bytes]

def byte_length(i: int) -> int:
    """Returns the minimal amount of bytes needed to represent unsigned integer `i`."""
    
    # we need to add 1 to correct the fact that a byte can only go up to 255, instead of 256:
    # i.e math.log(0x100, 0x100) = 1 but needs 2 bytes
    return math.ceil(math.log(i + 1, 0x100))


def int_to_bytes(i: int) -> bytes:
    """Converts integer to a MSB-first byte sequence using the least amount of bytes possible"""

    return i.to_bytes(byte_length(i), "big")

def bytes_to_int(b: bytes) -> int:
    """Converts MSB-first byte sequence to an integer"""
    return int.from_bytes(b, "big")


