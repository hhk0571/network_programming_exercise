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
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode


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


def decrypt(key_str, text, passphrase=None):
    private_key = RSA.importKey(key_str, passphrase=passphrase)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_text = cipher_rsa.decrypt(b64decode(text))
    
    return decrypted_text.decode()


class SSH_Client(object):
    def __init__(self, host, port):
        self.socket = socket.socket()
        self.socket.connect((host,port))
        print('[%s:%s]' % self.socket.getsockname())

    def auth(self):
        data = self.recv_data()
        if not data or data.get('action') != 'AUTH':
            return False

        key_file = os.path.expanduser('~/.ssh/id_rsa')
        if os.path.exists(key_file):
            key = open(key_file).read()
            decrypted_text = decrypt(key, data.get('data'))
        else:
            decrypted_text='unknown'

        response = {'action':'AUTH', 'data':decrypted_text}
        self.send_data(response)
        
        data = self.recv_data()
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
                self.send_data(data)

                data = self.recv_data()
                if not data:
                    print('Server disconnected')
                    break
                
                if data.get('status') != 205:
                    print(data.get('msg'))
                    continue

                data_len = data.get('size')
                data = {'action':'SIZE_CONFIRMED', 'data':data_len}
                self.send_data(data)

                all_data = b''
                recv_size = 0
                while recv_size < data_len:
                    data = self.socket.recv(BUF_SIZE)
                    #print('received %d bytes' %len(data))
                    recv_size += len(data)
                    all_data  += data
                print(all_data.decode('utf-8')) #命令执行结果

        except KeyboardInterrupt:
            print('\nBye bye!')
        except PermissionError:
            pass
        finally:
            self.socket.close()


    def send_data(self, data):
        '''
        send json data to client
        '''
        # print('send:', data)
        self.socket.sendall(json.dumps(data).encode())


    def recv_data(self):
        '''
        receive json data from client
        '''
        data = self.socket.recv(BUF_SIZE)
        # print('recv:', data)
        if data:
            data = json.loads(data.decode())
        return data


def main():
    set_io_utf8()
    client = SSH_Client(host, port)
    client.run()

if __name__ == '__main__':
    main()





