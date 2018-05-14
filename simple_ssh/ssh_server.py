#! /usr/bin/env python
# coding: utf-8
'''
# ./ssh_server.py 
Server is running on port 54321; press Ctrl-C to terminate.

[192.168.56.111:53596] connected
[192.168.56.111:53596] generate password: ':?m/d=9\\'
[192.168.56.111:53596] recv: b'{"data": ":?m/d=9\\\\", "action": "AUTH"}'
[192.168.56.111:53596] send: {'msg': 'Authentication OK', 'status': 200}
[192.168.56.111:53596] recv: b'{"cmd": "ls", "action": "CMD"}'
[192.168.56.111:53596] cmd output: b'1024.txt\n2048.txt\n2050.txt\n4096.txt\nindex.html\nssh_client.py\nssh_serve' ...
[192.168.56.111:53596] send: {'size': 101, 'msg': 'Command executed', 'error': 0, 'status': 205}
[192.168.56.111:53596] recv: b'{"data": 101, "action": "SIZE_CONFIRMED"}'
[192.168.56.111:53596] cmd done: sent 101 bytes

'''
import socket, socketserver
import sys, os, random, json
import threading
from subprocess import PIPE, Popen, STDOUT, TimeoutExpired 

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

BUF_SIZE = 4096
host = ''
port = 54321

def encrypt(key_str, text):
    key = RSA.importKey(key_str)
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted_text = cipher_rsa.encrypt(text.encode())
    
    return b64encode(encrypted_text).decode()


def decrypt(key_str, text, passphrase=None):
    private_key = RSA.importKey(key_str, passphrase=passphrase)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_text = cipher_rsa.decrypt(b64decode(text))
    
    return decrypted_text.decode()


def get_random_str(len=8):
    seed = ''.join([chr(i) for i in range(32,127)])
    sa = []
    for i in range(len):
        sa.append(random.choice(seed))
    return ''.join(sa)


def exe_cmd(cmd, timeout=5):
    '''
    execute command.
    return output, errcode
    '''
    process = Popen(cmd, stdout=PIPE, stderr=STDOUT, shell=True)
    try:
        outs = process.communicate(timeout=5)[0]
    except TimeoutExpired:
        process.terminate()
        process.communicate()[0]
        outs = cmd.encode() + b': command timeouted\n'

    err = process.returncode
    if len(outs) == 0: outs = b'\r'
    return outs, err


STATUS = {
    200:"Authentication OK",
    201:"Invalid auth data",
    202:"Wrong username or password",
    203:"Invalid request",
    204:"Invalid cmd",
    205:'Command executed'
}

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    conn_list=[]
    lock = threading.Lock()

    # override
    def setup(self):
        self.print_msg('connected')
        with self.lock:
            self.conn_list.append(self.request)
        #self.request.settimeout(1800) # 30 mins
        #print('timeout=', self.request.gettimeout())

    # override
    def handle(self):
        try:
            if self.auth():
                self.send_response(200) # authentication ok
            else:
                self.send_response(201) # authentication nok
                return

            while True:
                data = self.recv_data()
                if not data: # client disconnected
                    break
                if data.get('action') != 'CMD':
                    self.send_response(203)

                res, err = exe_cmd(data.get('cmd'))
                self.print_msg('cmd output:', res[:70], '...' if len(res)>70 else '')
                
                self.send_response(205, {'error':err, 'size': len(res)}) 

                data = self.recv_data()
                if not data: # client disconnected
                    break
                self.request.sendall(res)
                self.print_msg('cmd done: sent', len(res), 'bytes')
        except socket.timeout:
            self.print_msg('connection timeout')
        except Exception as e:
            self.print_msg(e)
        finally:
            # don't need to explictly close the socket
            pass

    # override
    def finish(self):
        self.print_msg('disconnected')
        with self.lock:
            self.conn_list.remove(self.request)
        
    
    def print_msg(self, *args, **kw):
        print('[%s:%s]' % self.client_address, *args, **kw)


    def auth(self):
        '''
        verify authentication of connection.
        return True on authentication ok, otherwise False.
        '''
        rand_text = get_random_str(8)
        self.print_msg('generate password:',repr(rand_text))
        try:
            with open(os.path.expanduser('~/.ssh/authorized_keys')) as f:
                for key in f.readlines():
                    encrypted_text = encrypt(key, rand_text)
                    data = {'action':'AUTH', 'data':encrypted_text}
                    self.send_data(data)
                    data = self.recv_data()
                    if data.get('action') == 'AUTH' and data.get('data') == rand_text:
                        return True
                return False
        except FileNotFoundError as e:
            return False
        except Exception as e:
            print(e)
            return False

    def send_data(self, data):
        '''
        send json data to client
        '''
        self.print_msg('send:', data)
        self.request.sendall(json.dumps(data).encode())


    def recv_data(self):
        '''
        receive json data from client
        '''
        data = self.request.recv(BUF_SIZE)
        self.print_msg('recv:', data)
        if data:
            data = json.loads(data.decode())
        return data

    def send_response(self, status_code, data=None):
        '''
        send response with json format to client
        '''
        response = {'status':status_code, 'msg':STATUS[status_code]}
        if data:
            response.update(data)
        self.print_msg('send:', response)
        self.request.sendall(json.dumps(response).encode())

    @classmethod
    def clean(cls):
        with cls.lock:
            for c in cls.conn_list:
                # shutdown sockects then recv functions return 
                # empty data (b''), so that sub-threads terminate
                c.shutdown(socket.SHUT_RDWR)


def main():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)
    print("Server is running on port %d; press Ctrl-C to terminate." % port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nBye bye')
    finally:
        server.shutdown()
        server.server_close()
        server.RequestHandlerClass.clean()

if __name__ == '__main__':
    main()



