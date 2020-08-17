from pws.asymmetric.rsa.keys import RSAPublicKey, RSAPrivateKey, RSAKeyPair


def generate_keypair(keysize: int = 3072) -> RSAKeyPair:
    
    """
    Generate a RSA Keypair with size (in bits) `keysize`
    """

