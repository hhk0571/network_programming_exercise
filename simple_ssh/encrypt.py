# coding: utf-8

import functools

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from base64 import b64encode, b64decode
import os
import random


def get_random_str(len=8):
    seed = ''.join([chr(i) for i in range(32,127)])
    sa = []
    for _ in range(len):
        sa.append(random.choice(seed))
    return ''.join(sa)

class RSA_Encryptor(object):
    '''
    RSA-Encrypt bytes-like object text using public/private key.
    '''
    def __init__(self, key_file=None):
        '''
        either private key or public key is OK.
        '''
        if key_file is None:
            return
        with open(os.path.expanduser(key_file)) as f:
            key_str = f.read()
        key = RSA.importKey(key_str)
        self._rsa = PKCS1_OAEP.new(key)

    def load_keystr(self, key_str):
        '''
        either private key or public key is OK.
        '''
        key = RSA.importKey(key_str)
        self._rsa = PKCS1_OAEP.new(key)

    def encrypt(self, text):
        '''
        RSA-Encrypt bytes-like object text and return a bytes object.
        '''
        return self._rsa.encrypt(text)

    def encrypt_b64(self, text):
        '''
        RSA-Encrypt bytes-like object text and return a base64-encoded bytes object.
        '''
        return b64encode(self._rsa.encrypt(text))



class RSA_Decryptor(object):
    '''
    RSA-Decrypt bytes-like object text using private key.
    '''
    def __init__(self, key_file, passphrase=None):
        '''
        private key only
        '''
        with open(os.path.expanduser(key_file)) as f:
            key_str = f.read()
        key = RSA.importKey(key_str, passphrase=passphrase)
        self._rsa = PKCS1_OAEP.new(key)

    def decrypt(self, text):
        '''
        RSA decrypt bytes-like object text and return a bytes object.
        '''
        return self._rsa.decrypt(text)

    def decrypt_b64(self, text):
        '''
        RSA decrypt base64-encoded bytes-like object text and return a bytes object.
        '''
        text = b64decode(text)
        return self._rsa.decrypt(text)


class AES_Encryptor(object):
    PADDING_CHAR = b'\x00'  # zero-padding
    TEXT_ALIGN = 16         # 128bits (16)
    KEY_ALIGN  = 32         # 128bits (16), 192bits (24), 256bits (32)
    MAX_KEY_LEN= 32

    def __init__(self, key, padding_char=PADDING_CHAR, key_align=KEY_ALIGN, text_align=TEXT_ALIGN):
        '''
        key is bytes-like object
        '''
        remainder = len(key) % key_align
        if (len(key) + key_align - remainder) > self.MAX_KEY_LEN:
            raise ValueError('key is too long')

        self._pad_text = functools.partial(self._pad, padding_char=padding_char, alignment=text_align)
        self._pad_key  = functools.partial(self._pad, padding_char=padding_char, alignment=key_align)
        self._aes = AES.new(self._pad_key(key), AES.MODE_ECB)

    @classmethod
    def _pad(cls, text, padding_char=PADDING_CHAR, alignment=TEXT_ALIGN):
        '''
        Add padding bytes to bytes object text and return a bytes object with padding
        '''
        remainder = len(text) % alignment
        return text + padding_char * (alignment - remainder)

    @classmethod
    def _unpad(cls, text, padding_char=PADDING_CHAR):
        return text.replace(padding_char, b'')

    def encrypt(self, text):
        '''
        Encrypt bytes-like object text using AES and return a bytes object.
        '''
        return self._aes.encrypt(self._pad_text(text))

    def decrypt(self, text):
        '''
        Decrypt bytes-like object text using AES and return a bytes object.
        '''
        return self._unpad(self._aes.decrypt(text))

    def encrypt_b64(self, text):
        '''
        Encrypt bytes-like object text using AES and return a base64-encoded bytes object.
        '''
        return b64encode(self._aes.encrypt(self._pad_text(text)))

    def decrypt_b64(self, text):
        '''
        Decrypt base64-encoded bytes-like object text using AES and return a bytes object.
        '''
        text = b64decode(text)
        return self._unpad(self._aes.decrypt(text))