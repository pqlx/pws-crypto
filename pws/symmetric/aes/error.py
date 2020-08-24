class AESException(Exception):
    pass

class AESPaddingException(AESException):
    pass

class AESPKCS7PaddingException(AESPAddingException):
    pass
