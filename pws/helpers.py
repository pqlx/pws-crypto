import struct

def lcs32(b: bytes, s: int):
    """Shift 32-bit quantity `b` `s` bytes to the left."""

    u = struct.unpack(">I", b)[0]
    
    return struct.pack(">I", ((u << (s*8)) | (u >> (32 - s*8))) & 0xffffffff)



def xor_bytes(a: bytes, b: bytes):
    """XOR function for two byte sequences of arbitrary (but equal) length"""
    assert len(a) == len(b)

    return bytes([x ^ y for x,y in zip(a, b)])


def xor_bytes_int(a: bytes, b: int):
    assert 0 <= b < 0x100

    return bytes([x ^ b for x in a])
