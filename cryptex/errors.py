class KeysizeError(Exception):
    """Raised when keysize is invalid for the Cryptex operation.

    Attributes:
        message -- explanation of error
    """

    def __init__(self, message):
        self.message = message


class ExpirationError(Exception):
    """Raised when the token is past the expiration ttl length.

    Attributes:
        message -- explanation of error
        expired -- number of seconds since message expired
    """

    def __init__(self, message, expired):
        self.message = message
        self.expired = expired


class NoValidKeyError(Exception):
    """Raised when no valid key could be used during multicryptex decryption.

    Attributes:
        message -- explanation of error
    """


    def __init__(self, message):
        self.message = message
