#! /usr/bin/env python
# coding: utf-8
import socket, socketserver
import sys, os, json
import threading
import time
from subprocess import PIPE, Popen, STDOUT, TimeoutExpired
from encrypt import RSA_Cipher, get_random_str, AES_Cipher
from msg import HEADER_SIZE, create_msg_header, parse_msg_header

BUF_SIZE = 4096
host = ''
port = 54321


def exe_cmd(cmd, timeout=10):
    '''
    execute command.
    return output, errcode
    '''
    process = Popen(cmd, stdout=PIPE, stderr=STDOUT, shell=True)
    try:
        outs = process.communicate(timeout=timeout)[0]
    except TimeoutExpired:
        process.terminate()
        process.communicate()
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

    # override
    def handle(self):
        try:
            self.recv_data = b''
            self.auth()
            self.request.settimeout(1800) # 30 mins
            while True:
                data = self.recv_msg()
                func = getattr(self, data.get('action', ''), None)
                if func is not None:
                    func(data)
                else:
                    self.send_response(203, encrypt=True) #Invalid request
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
        password = get_random_str(8) # AES key shared between server and client
        cipher   = get_random_str(8) # cipher for checking authentication of client

        self.aes = AES_Cipher(password.encode())
        self.print_msg('generate password:',repr(password), 'cipher:', repr(cipher))
        self.request.settimeout(1) # 1 sec
        with open(os.path.expanduser('~/.ssh/authorized_keys')) as f:
            for key in f.readlines():
                rsa = RSA_Cipher()
                rsa.load_keystr(key)
                enpwd = rsa.encrypt_b64(password.encode())
                encipher = rsa.encrypt_b64(cipher.encode())
                data = {'action':'AUTH', 'data':enpwd.decode(), 'cipher':encipher.decode()}
                self.send_msg(data, encrypt=False)
                data = self.recv_msg()
                try:
                    recv_cipher = self.aes.decrypt_b64(data.get('data').encode())
                    if data.get('action') == 'AUTH' and  recv_cipher.decode() == cipher:
                        self.send_response(200) # authentication ok
                        return
                except:
                    self.send_response(201) # authentication nok
            else:
                raise PermissionError('Authentication failed')


    def CMD(self, *args, **kw):
        data = args[0]
        res, err = exe_cmd(data.get('cmd'))
        self.send_response(205, {'error':err, 'output': res.decode()}, encrypt=True)

    def send_msg(self, data, encrypt=False):
        '''
        send msg with header + body to client
        '''
        body = json.dumps(data).encode()
        self.print_msg('send msg:', body[:1024])
        if encrypt:
            body = self.aes.encrypt_b64(body)
        header = create_msg_header(len(body), encrypt)
        self.request.sendall(header+body)


    def recv_msg(self):
        '''
        receive msg with header + body
        '''
        while True:
            if len(self.recv_data) >= HEADER_SIZE:
                magic,ver,msg_size,encryted = parse_msg_header(self.recv_data[:HEADER_SIZE])
                #self.print_msg('recv header: magic=%r ver=%r size=%r encrypted=%r' % (magic,ver,msg_size,encryted))

                if magic != b'MSG':
                    raise PermissionError('Invalid msg')

                while len(self.recv_data) < msg_size:
                    data = self.request.recv(BUF_SIZE)
                    if not data:
                        raise ConnectionAbortedError('client disconnected')
                    self.recv_data += data

                body = self.recv_data[HEADER_SIZE:msg_size]
                self.recv_data = self.recv_data[msg_size:]
                if encryted:
                    body = self.aes.decrypt_b64(body)
                self.print_msg('recv msg:', body)
                return json.loads(body.decode())
            else:
                # header not completed, continue receive data
                data = self.request.recv(BUF_SIZE)
                if not data:
                    raise ConnectionAbortedError('client disconnected')
                self.recv_data += data


    def send_response(self, status_code, data=None, encrypt=False):
        '''
        send response with json format to client
        '''
        response = {'status':status_code, 'msg':STATUS[status_code]}
        if data:
            response.update(data)
        self.send_msg(response, encrypt)


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



