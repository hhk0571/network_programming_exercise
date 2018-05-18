#! /usr/bin/env python
# coding: utf-8
import socket, socketserver
import sys, os, json
import threading
import time
from subprocess import PIPE, Popen, STDOUT, TimeoutExpired 

from encrypt import RSA_Encryptor, get_random_str, AES_Encryptor


import hashlib

BUF_SIZE = 4096
host = ''
port = 54321


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
            self.auth()
            while True:
                data = self.secure_recv_json()
                func = getattr(self, data.get('action', ''), None)
                if func is not None:
                    func(data)
                else:
                    self.secure_send_response(203) #Invalid request
        except socket.timeout:
            self.print_msg('connection timeout')
        except ConnectionAbortedError:
            pass
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
        print('%s [%s:%s]' % (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            self.client_address[0],
            self.client_address[1]), *args, **kw)


    def auth(self):
        '''
        verify authentication of connection, return True on success, otherwise False.

        idea is as below:
        1. randomly generate password and cipher
        2. encrypted them using RSA public key
        3. send encrypted password and cipher to client
        4. client recevie encrypted password and cipher
        5. client decrypt them using RSA private key
        6. client encrypt the received cipher using the received password as AES key
        7. client reply server with the AES encrypted cipher
        8. server decrypt the received cipher, and verify if it's same to the sent cipher

        '''
        rsa = RSA_Encryptor()
        password = get_random_str(8) # AES key shared between server and client
        cipher   = get_random_str(8) # cipher for checking authentication of client
        
        self.aes = AES_Encryptor(password.encode())
        self.print_msg('generate password:',repr(password), 'cipher:', repr(cipher))

        with open(os.path.expanduser('~/.ssh/authorized_keys')) as f:
            for key in f.readlines():
                rsa.load_keystr(key)
                enpwd = rsa.encrypt_b64(password.encode())
                encipher = rsa.encrypt_b64(cipher.encode())
                data = {'action':'AUTH', 'data':enpwd.decode(), 'cipher':encipher.decode()}
                self.send_json(data)
                data = self.recv_json()
                recv_cipher = self.aes.decrypt_b64(data.get('data').encode())
                if data.get('action') == 'AUTH' and  recv_cipher.decode() == cipher:
                    self.send_response(200) # authentication ok
                    return
            else:
                self.send_response(201) # authentication nok
                raise PermissionError('Authentication failed')


    def CMD(self, *args, **kw):
        data = args[0]
        res, err = exe_cmd(data.get('cmd'))
        self.print_msg('cmd output:', res[:70], '...' if len(res)>70 else '')
        
        encrypted_res = self.aes.encrypt(res)
        self.secure_send_response(205, {'error':err, 'size': len(encrypted_res)}) 

        data = self.secure_recv_json()

        self.request.sendall(encrypted_res)
        self.print_msg('cmd done: sent', len(encrypted_res), 'bytes')


    def send_json(self, data):
        '''
        send json data to client
        '''
        self.print_msg('send:', data)
        self.request.sendall(json.dumps(data).encode())


    def recv_json(self):
        '''
        receive json data from client
        '''
        data = self.request.recv(BUF_SIZE)
        self.print_msg('recv:', data)
        if data:
            data = json.loads(data.decode())
            return data
        else:
            raise ConnectionAbortedError('client disconnected')
        

    def send_response(self, status_code, data=None):
        '''
        send response with json format to client
        '''
        response = {'status':status_code, 'msg':STATUS[status_code]}
        if data:
            response.update(data)
        self.send_json(response)


    def secure_send(self, data):
        '''
        send encrypted json data to peer
        '''
        secure_data = self.aes.encrypt(data)
        self.request.sendall(secure_data)


    def secure_recv(self):
        '''
        receive encrypted data from peer
        '''
        secure_data = self.request.recv(BUF_SIZE)
        if secure_data:
            plain_data = self.aes.decrypt(secure_data)
            return plain_data
        else:
            raise ConnectionAbortedError('client disconnected')


    def secure_send_json(self, data):
        '''
        send encrypted json data to peer
        '''
        self.print_msg('secure send:', data)
        plain_data  = json.dumps(data).encode()
        secure_data = self.aes.encrypt_b64(plain_data)
        self.request.sendall(secure_data)


    def secure_recv_json(self):
        '''
        receive encrypted json data from peer
        '''
        secure_data = self.request.recv(BUF_SIZE)
        if secure_data:
            plain_data = self.aes.decrypt_b64(secure_data)
            self.print_msg('secure recv:', plain_data)
            data = json.loads(plain_data.decode())
            return data
        else:
            raise ConnectionAbortedError('client disconnected')


    def secure_send_response(self, status_code, data=None):
        '''
        send encrypted response with json format to peer
        '''
        response = {'status':status_code, 'msg':STATUS[status_code]}
        if data:
            response.update(data)
        self.secure_send_json(response)

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



