class CryptexError(Exception):
    """Generic base class for all Cryptex errors.
    """
    pass


class KeysizeError(CryptexError):
    """Raised when keysize is invalid for the Cryptex operation.

    Attributes:
        message -- explanation of error
    """

    def __init__(self, message):
        self.message = message


class ExpirationError(CryptexError):
    """Raised when the token is past the expiration ttl length.

    Attributes:
        message -- explanation of error
        expired -- number of seconds since message expired
    """

    def __init__(self, message, expired):
        self.message = message
        self.expired = expired


class NoValidKeyError(CryptexError):
    """Raised when no valid key could be used during multicryptex decryption.

    Attributes:
        message -- explanation of error
    """

    def __init__(self, message):
        self.message = message
