class AESException(Exception):
    pass


class AESKeyException(AESException):
    pass

class AESEncryptionException(AESException):
    pass

class AESDecryptionException(AESException):
    pass

class AESPaddingException(AESException):
    pass

class AESPKCS7PaddingException(AESPaddingException):
    pass
