from .cryptex import Cryptex


class MultiCryptex(object):
    def __init__(self, keys):
        self.ciphers = [Cryptex(key) for key in keys]

    def encrypt(self, data, ttl=None):
        return self.ciphers[0].encrypt(data, ttl=ttl)

    def decrypt(self, token):
        for cipher in self.ciphers:
            try:
                return cipher.decrypt(token)
            except ValueError:
                continue
        else:
            raise ValueError("No valid key found or token expired.")
