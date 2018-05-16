#! /usr/bin/env python
# coding: utf-8
'''
# ./ssh_client.py 192.168.56.111 54321
>> ls
1024.txt
2048.txt
2050.txt
4096.txt
index.html
ssh_client.py
ssh_server.py

'''

import socket, sys, io, os, json
from encrypt import RSA_Decryptor, AES_Encryptor
from base64 import b64encode, b64decode
import hashlib


BUF_SIZE = 4096

host = sys.argv[1]
port = int(sys.argv[2])



def set_io_utf8():
    if sys.stdout.encoding.lower() != 'utf-8':
        print('change stdout encoding from %s to utf-8' % sys.stdout.encoding)
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    if sys.stdin.encoding.lower() != 'utf-8':
        print('change stdin encoding from %s to utf-8' % sys.stdin.encoding)
        sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')


class SSH_Client(object):
    def __init__(self, host, port):
        self.socket = socket.socket()
        self.socket.connect((host,port))
        print('[%s:%s]' % self.socket.getsockname())

    def auth(self):
        data = self.recv_json()
        if not data or data.get('action') != 'AUTH':
            return False

        decryptor = RSA_Decryptor('~/.ssh/id_rsa')
        if decryptor is not None:
            pwd = decryptor.decrypt_b64(data.get('data').encode())
            cipher = decryptor.decrypt_b64(data.get('cipher').encode())
        else:
            pwd = b'unknown'

        self.aes = AES_Encryptor(pwd)
        encipher = self.aes.encrypt_b64(cipher)

        response = {'action':'AUTH', 'data':encipher.decode()}
        self.send_json(response)
        
        data = self.recv_json()
        return data and data.get('status') == 200

    def run(self):
        try:
            if self.auth():
                print('Authentication OK')
            else:
                print('Authentication NOK')
                return 1

            while True:
                cmd = input(">> ").strip()
                if len(cmd) == 0: continue
                if cmd == 'exit': break
                
                data = {'action':'CMD', 'cmd':cmd}
                self.secure_send_json(data)

                data = self.secure_recv_json()
                if not data:
                    print('Server disconnected')
                    break
                
                if data.get('status') != 205:
                    print(data.get('msg'))
                    continue

                data_len = data.get('size')
                data = {'action':'SIZE_CONFIRMED', 'data':data_len}
                self.secure_send_json(data)

                all_data = b''
                recv_size = 0
                while recv_size < data_len:
                    data = self.socket.recv(BUF_SIZE)
                    #print('received %d bytes' %len(data))
                    recv_size += len(data)
                    all_data  += data
                
                plain_data = self.aes.decrypt(all_data)
                print(plain_data.decode('utf-8')) #命令执行结果

        except KeyboardInterrupt:
            print('\nBye bye!')
        except PermissionError:
            pass
        finally:
            self.socket.close()


    def send_json(self, data):
        '''
        send json data to client
        '''
        # print('send:', data)
        self.socket.sendall(json.dumps(data).encode())


    def recv_json(self):
        '''
        receive json data from client
        '''
        try:
            data = self.socket.recv(BUF_SIZE)
            # print('recv:', data)
            if data:
                data = json.loads(data.decode())
            return data
        except Exception as e:
            print('load json failed', e)


    def secure_send(self, data):
        '''
        send encrypted json data to peer
        '''
        secure_data = self.aes.encrypt(data)
        self.socket.sendall(secure_data)


    def secure_recv(self):
        '''
        receive encrypted data from peer
        '''
        try:
            secure_data = self.socket.recv(BUF_SIZE)
            if secure_data:
                plain_data = self.aes.decrypt(secure_data)
                return plain_data
        except Exception as e:
            print('secure_recv failed', e)


    def secure_send_json(self, data):
        '''
        send encrypted json data to peer
        '''
        plain_data  = json.dumps(data).encode()
        secure_data = self.aes.encrypt_b64(plain_data)
        self.socket.sendall(secure_data)



    def secure_recv_json(self):
        '''
        receive encrypted json data from peer
        '''
        try:
            secure_data = self.socket.recv(BUF_SIZE)
            if secure_data:
                plain_data = self.aes.decrypt_b64(secure_data)
                data = json.loads(plain_data.decode())
                return data
        except Exception as e:
            print('load json failed', e)


def main():
    set_io_utf8()
    client = SSH_Client(host, port)
    client.run()

if __name__ == '__main__':
    main()





