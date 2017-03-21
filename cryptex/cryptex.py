import base64
import struct
import time

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


_AES_256_KEYSIZE_BYTES = 32
_TAG_DIGEST_LENGTH = 16
_NONCE_LENGTH = 16


class Cryptex(object):
    def __init__(self, key):
        self.key = base64.b64decode(key)
        if len(self.key) != _AES_256_KEYSIZE_BYTES:
            raise ValueError(
                'Keysize is invalid. Key must be 32 bytes.')

    def encrypt(self, data):
        nonce = get_random_bytes(_NONCE_LENGTH)

        cipher = AES.new(
            self.key,
            AES.MODE_GCM,
            nonce=nonce,
            mac_len=_TAG_DIGEST_LENGTH
        )

        current_time = int(time.time())
        timestamp = struct.pack('<L', current_time)
        cipher.update(timestamp)

        ciphertext, tag = cipher.encrypt_and_digest(data)

        token = (timestamp + tag + nonce + ciphertext)
        return base64.b64encode(token)

    def decrypt(self, token, ttl=None):
        token = base64.b64decode(token)

        metadata = token[:36]
        ciphertext = token[36:]

        timestamp = metadata[:4]
        tag = metadata[4:20]
        nonce = metadata[20:]

        cipher = AES.new(
            self.key,
            AES.MODE_GCM,
            nonce=nonce,
            mac_len=_TAG_DIGEST_LENGTH
        )

        cipher.update(timestamp)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        if ttl is not None:
            timestamp = struct.unpack('<L', timestamp)[0]
            if timestamp + ttl < int(time.time()):
                raise ValueError(
                    'Token is past expiration time.')
        return plaintext

    def generate_key():
        return base64.b64encode(get_random_bytes(32))
