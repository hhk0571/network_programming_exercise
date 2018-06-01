# coding: utf-8
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

class RSA_Cipher(object):
    '''
    RSA-Encrypt bytes-like data using public/private key.
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
        self._cipher = PKCS1_OAEP.new(key)

    def load_keystr(self, key_str):
        '''
        either private key or public key is OK.
        '''
        key = RSA.importKey(key_str)
        self._cipher = PKCS1_OAEP.new(key)

    def encrypt(self, data):
        '''
        RSA-Encrypt bytes-like data and return a bytes data.
        '''
        return self._cipher.encrypt(data)

    def encrypt_b64(self, data):
        '''
        RSA-Encrypt bytes-like data and return a base64-encoded bytes data.
        '''
        return b64encode(self._cipher.encrypt(data))



class RSA_Decipher(object):
    '''
    RSA-Decrypt bytes-like data using private key.
    '''
    def __init__(self, key_file, passphrase=None):
        '''
        private key only
        '''
        with open(os.path.expanduser(key_file)) as f:
            key_str = f.read()
        key = RSA.importKey(key_str, passphrase=passphrase)
        self._cipher = PKCS1_OAEP.new(key)

    def decrypt(self, data):
        '''
        RSA decrypt bytes-like data and return a bytes data.
        '''
        return self._cipher.decrypt(data)

    def decrypt_b64(self, data):
        '''
        RSA decrypt base64-encoded bytes-like data and return a bytes data.
        '''
        try:
            data = b64decode(data)
        except:
            raise ValueError('invaid base64 encoded data')

        return self._cipher.decrypt(data)


class AES_Cipher(object):
    PADDING_CHAR = b'\x00'  # zero-padding
    KEY_ALIGN  = 32         # 128bits (16), 192bits (24), 256bits (32)
    MAX_KEY_LEN= 32

    def __init__(self, key, padding_char=PADDING_CHAR, key_align=KEY_ALIGN):
        '''
        key is bytes-like data
        '''
        self.key = self._pad_key(key, alignment=key_align)

    @classmethod
    def _pad_key(cls, data, padding_char=PADDING_CHAR, alignment=KEY_ALIGN):
        '''
        Add padding to bytes data and return padded data
        '''
        remainder = len(data) % alignment
        if (len(data) + alignment - remainder) > cls.MAX_KEY_LEN:
            raise ValueError('key is too long')
        return data + padding_char * (alignment - remainder)

    def encrypt(self, data):
        '''
        Encrypt bytes-like data using AES and return a bytes data.
        '''
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def decrypt(self, data):
        '''
        Decrypt bytes-like data using AES and return a bytes data.
        '''
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data

    def encrypt_b64(self, data):
        '''
        Encrypt bytes-like data using AES and return a base64-encoded bytes data.
        '''
        return b64encode(self.encrypt(data))

    def decrypt_b64(self, data):
        '''
        Decrypt base64-encoded bytes-like data using AES and return a bytes data.
        '''
        try:
            data = b64decode(data)
        except:
            raise ValueError('invaid base64 encoded data')

        return self.decrypt(data)