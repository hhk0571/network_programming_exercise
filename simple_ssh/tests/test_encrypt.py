# coding: utf-8

import os
import sys

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, SRC_DIR)

from encrypt import RSA_Encryptor, RSA_Decryptor, AES_Encryptor, get_random_str

import unittest

class Test_RSA(unittest.TestCase):
    def setUp(self):
        self.pri_key = os.path.expanduser('~/.ssh/id_rsa')
        self.pub_key = os.path.expanduser('~/.ssh/id_rsa.pub')
        self.encryptor = RSA_Encryptor('~/.ssh/id_rsa.pub')
        self.decryptor = RSA_Decryptor('~/.ssh/id_rsa')

    def tearDown(self):
        pass

    def test_RSA_ascii(self):
        cipher = get_random_str(128)
        encrypted_text = self.encryptor.encrypt(cipher.encode())
        decrypted_text = self.decryptor.decrypt(encrypted_text)
        self.assertEqual(cipher, decrypted_text.decode())

    def test_RSA_unicode(self):
        cipher = 'Hello, 世界. 中华复兴'
        encrypted_text = self.encryptor.encrypt(cipher.encode())
        decrypted_text = self.decryptor.decrypt(encrypted_text)
        self.assertEqual(cipher, decrypted_text.decode())


    def test_RSA_b64(self):
        cipher = 'Hello, 世界. 中华复兴'
        encrypted_text = self.encryptor.encrypt_b64(cipher.encode())
        decrypted_text = self.decryptor.decrypt_b64(encrypted_text)
        self.assertEqual(cipher, decrypted_text.decode())


    def test_RSA_load_keystr(self):
        cipher = 'Hello, 世界. 中华复兴'
        encryptor = RSA_Encryptor()
        with open(self.pub_key) as f:
            encryptor.load_keystr(f.read())
        encrypted_text = encryptor.encrypt_b64(cipher.encode())
        decrypted_text = self.decryptor.decrypt_b64(encrypted_text)
        self.assertEqual(cipher, decrypted_text.decode())


    def test_RSA_pri_key_encrypt(self):
        cipher = 'Hello, 世界. 中华复兴'
        encryptor = RSA_Encryptor(self.pri_key)
        encrypted_text = encryptor.encrypt_b64(cipher.encode())
        decrypted_text = self.decryptor.decrypt_b64(encrypted_text)
        self.assertEqual(cipher, decrypted_text.decode())


    def test_RSA_invalid_key(self):
        with self.assertRaises(AttributeError):
            decryptor = RSA_Decryptor(None)

        with self.assertRaises(TypeError):
            decryptor = RSA_Decryptor()

        with self.assertRaises(ValueError):
            encryptor = RSA_Encryptor( os.path.join(SRC_DIR, 'requirements.txt')  )


class Test_AES(unittest.TestCase):
    def setUp(self):
        self.key = get_random_str(20).encode()
        self.aes = AES_Encryptor(self.key)

    def tearDown(self):
        pass

    def test_init(self):
        key = get_random_str(20).encode()
        aes = AES_Encryptor(key, key_align=32)
        self.assertIsNotNone(aes._aes)

        key = get_random_str(20).encode()
        aes = AES_Encryptor(key, key_align=16)
        self.assertIsNotNone(aes._aes)

        key = get_random_str(20).encode()
        aes = AES_Encryptor(key, key_align=24)
        self.assertIsNotNone(aes._aes)

        key = get_random_str(30).encode()
        aes = AES_Encryptor(key, key_align=16)
        self.assertIsNotNone(aes._aes)

        key = get_random_str(30).encode()
        aes = AES_Encryptor(key, key_align=32)
        self.assertIsNotNone(aes._aes)

    def test_long_key(self):
        with self.assertRaises(ValueError):
            key = get_random_str(33).encode()
            aes = AES_Encryptor(key, key_align=32)

        with self.assertRaises(ValueError):
            key = get_random_str(33).encode()
            aes = AES_Encryptor(key, key_align=24)

        with self.assertRaises(ValueError):
            key = get_random_str(30).encode()
            aes = AES_Encryptor(key, key_align=24)

        with self.assertRaises(ValueError):
            key = get_random_str(33).encode()
            aes = AES_Encryptor(key, key_align=16)


    def test_pad(self):
        original_s = get_random_str(9).encode()
        padded_s   = self.aes._pad(original_s, alignment=16)
        expected_s = original_s + self.aes.PADDING_CHAR * (16 - len(original_s))
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 16)


        original_s = get_random_str(9).encode()
        padded_s   = self.aes._pad(original_s, alignment=32)
        expected_s = original_s + self.aes.PADDING_CHAR * (32 - len(original_s))
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 32)


        original_s = get_random_str(18).encode()
        padded_s   = self.aes._pad(original_s, alignment=16)
        expected_s = original_s + self.aes.PADDING_CHAR * (32 - len(original_s))
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 32)

        original_s = get_random_str(18).encode()
        padded_s   = self.aes._pad(original_s, alignment=24)
        expected_s = original_s + self.aes.PADDING_CHAR * (24 - len(original_s))
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 24)

        original_s = get_random_str(30).encode()
        padded_s   = self.aes._pad(original_s, alignment=24)
        expected_s = original_s + self.aes.PADDING_CHAR * 18
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 48)

    def test_en_decryption(self):
        cipher = 'Hello, 世界. 中华复兴. 床前明月光 疑是地上霜 举头望山月 低头思故乡'
        encrypted_text = self.aes.encrypt(cipher.encode())
        decrypted_text = self.aes.decrypt(encrypted_text)
        self.assertEqual(cipher, decrypted_text.decode())

    def test_en_decryption_b64(self):
        cipher = 'Hello, 世界. 中华复兴. 床前明月光 疑是地上霜 举头望山月 低头思故乡'
        encrypted_text = self.aes.encrypt_b64(cipher.encode())
        decrypted_text = self.aes.decrypt_b64(encrypted_text)
        self.assertEqual(cipher, decrypted_text.decode())

if __name__ == '__main__':
    unittest.main()