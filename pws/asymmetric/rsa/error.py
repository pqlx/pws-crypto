class RSAException(Exception):
    pass

class RSAEncryptionException(RSAException):
    pass

class RSADecryptionException(RSAException):
    pass

class RSASignException(RSAException):
    pass

class RSAVerifyException(RSAException):
    pass

class RSAPaddingException(RSAException):
    pass

class RSAPKCS1PaddingException(RSAPaddingException):
    pass

class RSAOAEPPaddingException(RSAPaddingException):
    pass

class RSAPSSPaddingException(RSAPaddingException):
    pass
