from pws.asymmetric.rsa import generate_keypair, RSAKeyPair, RSAPublicKey, RSAPrivateKey

from pwn import hexdump

from datetime import datetime
import secrets
import random

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
    n_blobs = kwargs.get("n_blobs") or 8
    blob_range = kwargs.get("blob_range") or (key_size // (8 * 4), key_size // (8 *2))
    
    
    print(f"[*] Generating {n_blobs} blobs of data with length inbetween {blob_range} (in bytes)")

    blobs = [secrets.token_bytes(random.randint(*blob_range)) for _ in range(n_blobs)]
    
    print("[+] Done generating blobs!")
    print()
    
    pad_type = kwargs.get("pad_type") or "pkcs1"

    print(f"[*] Proceeding to encrypt and subsequently decrypt {n_blobs} blobs using padding scheme: {pad_type}") 
    print("-"*80)
    print()
    for i, blob in enumerate(blobs):
        
        print(f"[*] Blob {i}:")
        print(hexdump(blob))
        print()

        encrypted = kp.pub.encrypt(blob, pad_type=pad_type)

        print("[*] Encrypted:")
        print(hexdump(encrypted)) 
        print()
        
        decrypted = kp.priv.decrypt(encrypted, pad_type=pad_type)
        
        print("[*] Decrypted:")
        print(hexdump(decrypted))

        if decrypted == blob:
            print("[+] Success! m == decrypt(encrypt(m)) !")
        else:
            print("[x] Fail! m != decrypt(encrypt(m))")
        print("-"*80)
        print()

if __name__ == "__main__":
    do_test()
