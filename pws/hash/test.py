from pws.hash.md5 import MD5
from pws.hash.sha1 import SHA1
from pws.hash.sha256 import SHA256

from typing import Type

import hashlib

TheirHash = hashlib._hashlib.HASH

def do_test(hash_name: str, our_hash: Type['OurHash'], their_hash: Type[TheirHash], **kwargs):

    print(f"[+] {hash_name} demo:")
    print("-"*80)

    import secrets
    import hashlib
    import random
    from hexdump import hexdump

    n_blobs = kwargs.get("n_blobs") or 8
    blob_range = kwargs.get("blob_range") or (128, 2048)


    blobs = [secrets.token_bytes(random.randint(*blob_range)) for _ in range(n_blobs)]
    
    n_success = 0
    
    for i, blob in enumerate(blobs):
        print(f"[*] Blob {i}:")
        hexdump(blob)

        our = our_hash(blob).hexdigest
        their = their_hash(blob).hexdigest()

        print(f"{our} <===== {hash_name} digest of this implementation")
        print(f"{their} <===== {hash_name} digest of hashlib implementation")

        if our == their:
            print("[+] Correct result!")
            n_success += 1
        else:
            print("[x] Incorrect result!")
        print()    
    print("Results:")
    print("-"*80)
    print(f"{n_success}/{n_blobs} blobs sucessfully hashed with hash {hash_name}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
            description=f"Hash Testing module",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument("hash", choices=["md5", "sha1", "sha256"], type=str, help="Hashing algorithm to test.")
    parser.add_argument("--blobs", type=int, help="Amount of random plaintext blobs to generate.", default=32)
    parser.add_argument("--min-size", type=int, help="Minimum blob size.", default=128)
    parser.add_argument("--max-size", type=int, help="Maximum blob size.", default=2048)

    args = parser.parse_args()
    

    if args.hash == "sha1":
        name, our, their = "SHA-1", SHA1, hashlib.sha1
    elif args.hash == "md5":
        name, our, their = "MD5", MD5, hashlib.md5
    elif args.hash == "sha256":
        name, our, their = "SHA-256", SHA256, hashlib.sha256

    do_test(hash_name=name, our_hash=our, their_hash=their, n_blobs=args.blobs, blob_range=(args.min_size, args.max_size))

