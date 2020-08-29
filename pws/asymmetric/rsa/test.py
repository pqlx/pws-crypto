from pws.asymmetric.rsa import generate_keypair, RSAKeyPair, RSAPublicKey, RSAPrivateKey

from hexdump import hexdump

from datetime import datetime
import secrets
import random
import time

def do_test(key_size: int=2048, **kwargs):
    print("[*] Testing RSA")
    print("-"*80)
    print()
    print(f"[*] Generating {key_size}-bit keypair...")
    
    first = datetime.now()
    
    kp = generate_keypair(key_size)

    ms_elapsed = round((datetime.now() - first).total_seconds() * 1000.0)
    
    print("[+] Generated keypair!")
    print(kp)
    print(f"[*] Generation took {ms_elapsed} ms..")
    print(80*"-")
    print()
    n_blobs = kwargs.get("n_blobs", 8)
    blob_range = kwargs.get("blob_range", (key_size // (8 * 4), key_size // (8 * 3)))
    
    
    print(f"[*] Generating {n_blobs} blobs of data with length inbetween {blob_range} (in bytes)")

    blobs = [secrets.token_bytes(random.randint(*blob_range)) for _ in range(n_blobs)]
    
    print("[+] Done generating blobs!")
    print()
    
    encrypt_pad_type = kwargs.get("encryption_pad_type", "pkcs1")

    print(f"[*] Proceeding to encrypt and subsequently decrypt {n_blobs} blobs using padding scheme: {encrypt_pad_type}") 
    print("-"*80)
    print()
    
    time.sleep(1)
    
    n_encrypt_success = 0
    for i, blob in enumerate(blobs):
        
        print(f"[*] Blob {i}:")
        print(hexdump(blob))
        print()

        encrypted = kp.pub.encrypt(blob, pad_type=encrypt_pad_type)

        print("[*] Encrypted:")
        print(hexdump(encrypted)) 
        print()
        
        decrypted = kp.priv.decrypt(encrypted, pad_type=encrypt_pad_type)
        
        print("[*] Decrypted:")
        print(hexdump(decrypted))

        if decrypted == blob:
            print("[+] Success! m == decrypt(encrypt(m))")
            n_encrypt_success += 1
        else:
            print("[x] Fail! m != decrypt(encrypt(m))")
        print("-"*80)
        print()
        
        time.sleep(0.5)

    sign_pad_type = kwargs.get("signature_pad_type", "pss")
    
    print(f"[*] Proceeding to sign a subsequently verify {n_blobs} blobs using padding scheme: {sign_pad_type}")
    print("-"*80)
    print()
    
    time.sleep(1)
    
    n_signature_success = 0
    for i, blob in enumerate(blobs):

        print(f"[*] Blob {i}:")
        print(hexdump(blob))
        print()

        signature = kp.priv.sign(blob, pad_type=sign_pad_type)

        print("[*] Signed:")
        print(hexdump(signature))
        print()

        print("[*] Verifying signature:")
        verified = kp.pub.verify(blob, signature, pad_type=sign_pad_type)
        
        if verified:
            print("[+] Success! Signature verified correctly.")
            n_signature_success += 1
        else:
            print("[x] Fail! Signature failed verification.")
        
        print("-"*80)
        print()
        time.sleep(0.5)
    
    print("Results:")
    print("-"*80)
    print(f"{n_encrypt_success}/{n_blobs} blobs successfully encrypted + decrypted (padding scheme: {encrypt_pad_type})")
    print(f"{n_signature_success}/{n_blobs} blobs successfully signed + verified (padding scheme: {sign_pad_type})")
    
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
            description="RSA Testing module",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument("--encryption-padding", choices=["pkcs1", "oaep", "none"], default="pkcs1", type=str, help="Padding mode to use for encryption") 
    parser.add_argument("--signature-padding", choices=["pss", "none"], default="pss", type=str, help="Padding mode to use for signatures")
    parser.add_argument("--keysize", "-n", default=2048, type=int, help="Key size to generate (in bits). Should be divisible by eight.")
    parser.add_argument("--blobs", "-b", default=8, type=int, help="Amount of random plaintext blobs to generate.:")
    args = parser.parse_args()
    
    print(args)
    do_test(key_size=args.keysize, n_blobs=args.blobs, encryption_pad_type=args.encryption_padding, signature_pad_type=args.signature_padding)
