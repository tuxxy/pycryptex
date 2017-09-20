import base64
import struct
import time

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

from .errors import KeysizeError, ExpirationError


_AES_256_KEYSIZE_BYTES = 32
_TAG_DIGEST_LENGTH_BYTES = 16
_NONCE_LENGTH_BYTES = 12


class Cryptex(object):
    def __init__(self, key):
        self.key = base64.urlsafe_b64decode(key)
        if len(self.key) != _AES_256_KEYSIZE_BYTES:
            raise KeysizeError(
                'Keysize is invalid. Key must be 32 bytes.'
            )

    def encrypt(self, data, ttl=None):
        nonce = get_random_bytes(_NONCE_LENGTH_BYTES)

        cipher = AES.new(
            self.key,
            AES.MODE_GCM,
            nonce=nonce,
            mac_len=_TAG_DIGEST_LENGTH_BYTES
        )

        current_time = int(time.time())
        if ttl is not None:
            timestamp = current_time + ttl
        else:
            timestamp = 0
        timestamp = timestamp.to_bytes(8, byteorder='big')
        cipher.update(timestamp)

        ciphertext, tag = cipher.encrypt_and_digest(data)

        token = (timestamp + tag + nonce + ciphertext)
        return base64.urlsafe_b64encode(token)

    def decrypt(self, token):
        token = base64.urlsafe_b64decode(token)

        metadata = token[:36]
        ciphertext = token[36:]

        timestamp = metadata[:8]
        tag = metadata[8:24]
        nonce = metadata[24:]
        current_time = int(time.time())

        cipher = AES.new(
            self.key,
            AES.MODE_GCM,
            nonce=nonce,
            mac_len=_TAG_DIGEST_LENGTH_BYTES
        )

        cipher.update(timestamp)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        timestamp = int.from_bytes(timestamp, byteorder='big')
        if timestamp != 0:
            if current_time > timestamp:
                raise ExpirationError(
                    'Token is past expiration time.',
                    current_time - timestamp,
                )
        return plaintext

    def generate_key():
        return base64.urlsafe_b64encode(get_random_bytes(32))
