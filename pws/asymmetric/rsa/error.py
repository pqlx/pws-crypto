class BadPaddingException(Exception):
    pass

class BadPKCS1PaddingException(BadPaddingException):
    pass

class BadOAEPPaddingException(BadPaddingException):
    pass

class BadPSSPaddingException(BadPaddingException):
    pass
