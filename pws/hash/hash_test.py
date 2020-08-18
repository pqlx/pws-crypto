from typing import Type

from pws.hash.abstracthash import Hash as OurHash
from hashlib import _hashlib

TheirHash = _hashlib.HASH

def run_test(hash_name: str, our_hash: Type[OurHash], their_hash: Type[TheirHash], **kwargs):

    print(f"[+] {hash_name} demo:")
    print("-"*80)

    import secrets
    import hashlib
    import random
    from pwn import hexdump # really need a better library but this looks pretty.

    n_blobs = kwargs.get("n_blobs") or 8
    blob_range = kwargs.get("blob_range") or (128, 512)


    blobs = [secrets.token_bytes(random.randint(*blob_range)) for _ in range(n_blobs)]

    result = True
    for i, blob in enumerate(blobs):
        print(f"[*] Blob {i}:")
        print(hexdump(blob))

        our = our_hash(blob).hexdigest
        their = their_hash(blob).hexdigest()

        print(f"{our} <===== {hash_name} digest of this implementation")
        print(f"{their} <===== {hash_name} digest of hashlib implementation")

        if our == their:
            print("[+] Correct result!")
        else:
            result = False
            print("[x] Incorrect result!")

    return result
