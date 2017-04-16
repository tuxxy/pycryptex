import unittest
import base64
import time

from Cryptodome.Random import get_random_bytes
from cryptex import Cryptex, MultiCryptex
from cryptex.errors import KeysizeError, ExpirationError, NoValidKeyError


class TestCryptex(unittest.TestCase):
    def setUp(self):
        self.test_data = b'Test data'

    def test_key_generation(self):
        key = Cryptex.generate_key()

        # Ensure that all keys are 32 bytes in length
        self.assertEqual(32, len(base64.urlsafe_b64decode(key)))

    def test_keysize_error(self):
        # Create a key with an invalid keysize for AES-256
        invalid_key = base64.urlsafe_b64encode(get_random_bytes(16))
        with self.assertRaises(KeysizeError):
            Cryptex(invalid_key)

    def test_encryption_and_decryption(self):
        cryptex = Cryptex(Cryptex.generate_key())
        try:
            token = cryptex.encrypt(self.test_data)
        except Exception as e:
            self.fail("Encryption failed with {}".format(e))
        self.assertNotEqual(self.test_data, token)
        
        try:
            plaintext = cryptex.decrypt(token)
        except Exception as e:
            self.fail("Decryption failed with {}".format(e))
        self.assertEqual(self.test_data, plaintext)

    def test_ttl_encryption_decryption(self):
        cryptex = Cryptex(Cryptex.generate_key())
        try:
            # Set ttl to 5 to test ttl 
            token = cryptex.encrypt(self.test_data, ttl=5)
        except Exception as e:
            self.fail("Encryption failed with {}".format(e))
        self.assertNotEqual(self.test_data, token)

        try:
            plaintext = cryptex.decrypt(token)
        except Exception as e:
            self.fail("Decryption failed with {}".format(e))
        self.assertEqual(self.test_data, plaintext)

        # Test ttl by sleeping over expiration time
        time.sleep(6)
        with self.assertRaises(ExpirationError):
            cryptex.decrypt(token)

    def test_multicryptex_encryption_and_decryption(self):
        keys = [Cryptex.generate_key() for _ in range(2)]
        multicryptex = MultiCryptex(keys)

        try:
            token = multicryptex.encrypt(self.test_data)
        except Exception as e:
            self.fail("Encryption failed with {}".format(e))
        self.assertNotEqual(self.test_data, token)

        try:
            plaintext = multicryptex.decrypt(token)
        except Exception as e:
            self.fail("Decryption failed with {}".format(e))
        self.assertEqual(self.test_data, plaintext)

    def test_multicryptex_old_key_encryption_and_decryption(self):
        keys = [Cryptex.generate_key() for _ in range(2)]
        multicryptex = MultiCryptex(keys)

        # Create a Cryptex object with "old key"
        cryptex2 = Cryptex(keys[1])
        try:
            token = cryptex2.encrypt(self.test_data)
        except Exception as e:
            self.fail("Encryption failed with {}".format(e))
        self.assertNotEqual(self.test_data, token)

        # Test the MultiCryptex key attempt
        try:
            plaintext = multicryptex.decrypt(token)
        except Exception as e:
            self.fail("Decryption failed with {}".format(e))
        self.assertEqual(self.test_data, plaintext)

    def test_multicryptex_ttl_encryption_and_decryption(self):
        keys = [Cryptex.generate_key() for _ in range(2)]
        multicryptex = MultiCryptex(keys)

        try:
            token = multicryptex.encrypt(self.test_data, ttl=5)
        except Exception as e:
            self.fail("Encryption failed with {}".format(e))
        self.assertNotEqual(self.test_data, token)

        try:
            plaintext = multicryptex.decrypt(token)
        except Exception as e:
            self.fail("Decryption failed with {}".format(e))
        self.assertEqual(self.test_data, plaintext)

        # Test ttl by sleeping over expiration time
        time.sleep(6)
        with self.assertRaises(ExpirationError):
            multicryptex.decrypt(token)

    def test_multicryptex_no_key_error(self):
        keys = [Cryptex.generate_key() for _ in range(2)]
        multicryptex = MultiCryptex(keys)

        try:
            token = Cryptex(Cryptex.generate_key()).encrypt(self.test_data)
        except Exception as e:
            self.fail("Encryption failed with {}".format(e))
        self.assertNotEqual(self.test_data, token)

        with self.assertRaises(NoValidKeyError):
            multicryptex.decrypt(token)
