# coding: utf-8

import os
import sys

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, SRC_DIR)

from encrypt import RSA_Cipher, RSA_Decipher, AES_Cipher, get_random_str

import unittest

class Test_RSA(unittest.TestCase):
    def setUp(self):
        self.pri_key = os.path.expanduser('~/.ssh/id_rsa')
        self.pub_key = os.path.expanduser('~/.ssh/id_rsa.pub')
        self.cipher = RSA_Cipher('~/.ssh/id_rsa.pub')
        self.decipher = RSA_Decipher('~/.ssh/id_rsa')

    def tearDown(self):
        pass

    def test_RSA_ascii(self):
        text = get_random_str(128)
        encrypted_text = self.cipher.encrypt(text.encode())
        decrypted_text = self.decipher.decrypt(encrypted_text)
        self.assertEqual(text, decrypted_text.decode())

    def test_RSA_unicode(self):
        text = 'Hello, 世界. 中华复兴'
        encrypted_text = self.cipher.encrypt(text.encode())
        decrypted_text = self.decipher.decrypt(encrypted_text)
        self.assertEqual(text, decrypted_text.decode())


    def test_RSA_b64(self):
        text = 'Hello, 世界. 中华复兴'
        encrypted_text = self.cipher.encrypt_b64(text.encode())
        decrypted_text = self.decipher.decrypt_b64(encrypted_text)
        self.assertEqual(text, decrypted_text.decode())


    def test_RSA_load_keystr(self):
        text = 'Hello, 世界. 中华复兴'
        cipher = RSA_Cipher()
        with open(self.pub_key) as f:
            cipher.load_keystr(f.read())
        encrypted_text = cipher.encrypt_b64(text.encode())
        decrypted_text = self.decipher.decrypt_b64(encrypted_text)
        self.assertEqual(text, decrypted_text.decode())


    def test_RSA_pri_key_encrypt(self):
        text = 'Hello, 世界. 中华复兴'
        cipher = RSA_Cipher(self.pri_key)
        encrypted_text = cipher.encrypt_b64(text.encode())
        decrypted_text = self.decipher.decrypt_b64(encrypted_text)
        self.assertEqual(text, decrypted_text.decode())


    def test_RSA_invalid_key(self):
        with self.assertRaises(AttributeError):
            decipher = RSA_Decipher(None)

        with self.assertRaises(TypeError):
            decipher = RSA_Decipher()

        with self.assertRaises(ValueError):
            cipher = RSA_Cipher( os.path.join(SRC_DIR, 'requirements.txt')  )


    def test_decrypt_b64_invalid_data(self):
        with self.assertRaises(ValueError):
            decrypted_text = self.decipher.decrypt_b64('Hello, 世界')


class Test_AES(unittest.TestCase):
    def setUp(self):
        self.key = get_random_str(20).encode()
        self.cipher = AES_Cipher(self.key)

    def tearDown(self):
        pass

    def test_init(self):
        key = get_random_str(20).encode()
        cipher = AES_Cipher(key, key_align=32)
        self.assertTrue(len(cipher.key)==32)

        key = get_random_str(20).encode()
        cipher = AES_Cipher(key, key_align=16)
        self.assertTrue(len(cipher.key)==32)

        key = get_random_str(20).encode()
        cipher = AES_Cipher(key, key_align=24)
        self.assertTrue(len(cipher.key)==24)

        key = get_random_str(30).encode()
        cipher = AES_Cipher(key, key_align=16)
        self.assertTrue(len(cipher.key)==32)

        key = get_random_str(30).encode()
        cipher = AES_Cipher(key, key_align=32)
        self.assertTrue(len(cipher.key)==32)

    def test_long_key(self):
        with self.assertRaises(ValueError):
            key = get_random_str(33).encode()
            cipher = AES_Cipher(key, key_align=32)

        with self.assertRaises(ValueError):
            key = get_random_str(33).encode()
            cipher = AES_Cipher(key, key_align=24)

        with self.assertRaises(ValueError):
            key = get_random_str(30).encode()
            cipher = AES_Cipher(key, key_align=24)

        with self.assertRaises(ValueError):
            key = get_random_str(33).encode()
            cipher = AES_Cipher(key, key_align=16)


    def test_pad_key(self):
        original_s = get_random_str(9).encode()
        padded_s   = self.cipher._pad_key(original_s, alignment=16)
        expected_s = original_s + self.cipher.PADDING_CHAR * (16 - len(original_s))
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 16)


        original_s = get_random_str(9).encode()
        padded_s   = self.cipher._pad_key(original_s, alignment=32)
        expected_s = original_s + self.cipher.PADDING_CHAR * (32 - len(original_s))
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 32)


        original_s = get_random_str(18).encode()
        padded_s   = self.cipher._pad_key(original_s, alignment=16)
        expected_s = original_s + self.cipher.PADDING_CHAR * (32 - len(original_s))
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 32)

        original_s = get_random_str(18).encode()
        padded_s   = self.cipher._pad_key(original_s, alignment=24)
        expected_s = original_s + self.cipher.PADDING_CHAR * (24 - len(original_s))
        self.assertEqual(padded_s, expected_s)
        self.assertEqual(len(padded_s), 24)

        with self.assertRaises(ValueError):
            original_s = get_random_str(30).encode()
            padded_s   = self.cipher._pad_key(original_s, alignment=24)

    def test_en_decryption(self):
        text = 'Hello, 世界. 中华复兴. 床前明月光 疑是地上霜 举头望山月 低头思故乡'
        encrypted_text = self.cipher.encrypt(text.encode())
        decrypted_text = self.cipher.decrypt(encrypted_text)
        self.assertEqual(text, decrypted_text.decode())

    def test_en_decryption_b64(self):
        text = 'Hello, 世界. 中华复兴. 床前明月光 疑是地上霜 举头望山月 低头思故乡'
        encrypted_text = self.cipher.encrypt_b64(text.encode())
        decrypted_text = self.cipher.decrypt_b64(encrypted_text)
        self.assertEqual(text, decrypted_text.decode())

    def test_decrypt_b64_invalid_data(self):
        with self.assertRaises(ValueError):
            decrypted_text = self.cipher.decrypt_b64('Hello, 世界')

if __name__ == '__main__':
    unittest.main()