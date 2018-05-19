# coding: utf-8
import struct
from encrypt import RSA_Encryptor, get_random_str, AES_Encryptor

MAGIC_STR = b'MSG'
STRUCT_FMT = '!3s2I?'

def calc_header_size():
    data = (MAGIC_STR, 1, 1024, False)
    return len(struct.pack(STRUCT_FMT, *data))

HEADER_SIZE = calc_header_size() 

def create_msg_header(body_size, encrypt=False, version=1):
    data = (MAGIC_STR,version, HEADER_SIZE+body_size, encrypt)
    return struct.pack(STRUCT_FMT, *data)

def parse_msg_header(data):
    magic,ver,msg_size,encryted = struct.unpack(STRUCT_FMT, data)
    return magic,ver,msg_size,encryted
