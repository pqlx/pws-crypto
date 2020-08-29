from typing import Optional

from pws.symmetric.aes import AESKey
from hexdump import hexdump

import secrets
import random

def do_test(**kwargs):


    h = lambda x: bytearray.fromhex(x)
    test_vectors = (
        {
            "plaintext": h("00112233445566778899aabbccddeeff"),
            "key": h("000102030405060708090a0b0c0d0e0f"),
            "ciphertext": h("69c4e0d86a7b0430d8cdb78070b4c55a")
        },
        {
            "plaintext": h("00112233445566778899aabbccddeeff"),
            "key": h("000102030405060708090a0b0c0d0e0f1011121314151617"),
            "ciphertext": h("dda97ca4864cdfe06eaf70a0ec0d7191")
        },
        {
            "plaintext": h("00112233445566778899aabbccddeeff"),
            "key": h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            "ciphertext": h("8ea2b7ca516745bfeafc49904b496089")
        }
    )

    def test_vector(plaintext: bytes, key: bytes, mode: str="ECB", ciphertext_should_match: Optional[bytes]=None) -> bool:
        
        mode = mode.upper()

        if mode == "CBC" and ciphertext_should_match:
            raise ValueError("No deterministic ciphertext possible for CBC mode!")

        success = False
        
        key_ = AESKey(key)

        print("[*] Testing vector:")
        print("-"*80)
        print("[*] Plaintext:")
        hexdump(plaintext)
        print()
        print("[*] Key:")
        hexdump(key)
        print()
        print("[*] Encrypting plaintext:")
        
               
        if ciphertext_should_match:
            
            ciphertext = key_.encrypt(plaintext, mode="ECB", padding_mode="none")
            hexdump(ciphertext)
 
            # truncate padding, only compare first block
            if ciphertext != ciphertext_should_match:
                print("[x] Ciphertext did not match. Expected:")
                hexdump(ciphertext_should_match)
            else:
                print("[+] Ciphertext matched with expected value!")
                success = True
        else:
            # just test if decryption works.
            
            ciphertext = key_.encrypt(plaintext, mode=mode)
            hexdump(ciphertext)
 

            plaintext_prime = key_.decrypt(ciphertext)
            if plaintext_prime != plaintext:
                print("[x] Decrypted ciphertext did not match with plaintext. Got:")
                hexdump(plaintext_prime)
            else:
                print("[+] Decrypted ciphertext matched plaintext!")
                success = True
        print()
        return success

    n_fips_success = 0
    n_blob_success = 0

    print("[*] Testing AES")
    print("-"*80)
    print()
    print("[*] Testing FIPS 197 test vectors")
    

    for vector in test_vectors:
        n_fips_success += int(test_vector(
            plaintext=vector["plaintext"],
            key=vector["key"],
            mode="ECB",
            ciphertext_should_match=vector["ciphertext"]))
    
    n_blobs = kwargs.get("n_blobs", 32)
    blob_range = kwargs.get("blob_range", (16, 256))
    keysize = kwargs.get("keysize", 128) // 8
    mode    = kwargs.get("mode", "CBC")

    blobs = [secrets.token_bytes(random.randint(*blob_range)) for _ in range(n_blobs)]
    keys  = [secrets.token_bytes(keysize) for _ in range(n_blobs)] 
    
    for i, blob in enumerate(blobs):
        n_blob_success += int(test_vector(
            plaintext=blob,
            key=keys[i],
            mode = mode
            ))
    
    print("Results:")
    print("-"*80)
    print(f"{n_fips_success}/{len(test_vectors)} FIPS 197 test vector tests passed.")
    print(f"{n_blob_success}/{n_blobs} random blob encryption + decryption tests passed. (mode: {mode})")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
            description="AES Testing module",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--mode", type=str, default="CBC", choices=["CBC", "ECB"], help="Mode of operation to use to encrypt blocks.")
    
    parser.add_argument("--blobs", type=int, default=32, help="Amount of random plaintext blobs to generate.")
    parser.add_argument("--min-size", type=int, default=16, help="Minimum plaintext blob size.")
    parser.add_argument("--max-size", type=int, default=256, help="Maxmimum plaintext blob size.")
    parser.add_argument("--keysize", type=int, default=128, choices=[128, 192, 256], help="Bit size of generated keys.")
    
    args = parser.parse_args()

    do_test(n_blobs=args.blobs, blob_range=(args.min_size, args.max_size), keysize=args.keysize)
