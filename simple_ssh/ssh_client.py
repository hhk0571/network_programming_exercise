#! /usr/bin/env python
# coding: utf-8

import socket, sys, io, os, json, struct
import logging
from encrypt import RSA_Decryptor, AES_Encryptor
from msg import HEADER_SIZE, create_msg_header, parse_msg_header

logger = logging.getLogger('ssh_client')
# logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

BUF_SIZE = 4096

host = sys.argv[1]
port = int(sys.argv[2])

HELP = '''\
<CMD> .................. Non-interactive commands, e.g. ls
debug on ............... Turn on debugging
debug off .............. Turn off debugging
exit ................... Exit
'''


def set_io_utf8():
    if sys.stdout.encoding.lower() != 'utf-8':
        print('change stdout encoding from %s to utf-8' % sys.stdout.encoding)
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    if sys.stdin.encoding.lower() != 'utf-8':
        print('change stdin encoding from %s to utf-8' % sys.stdin.encoding)
        sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')


class SSH_Client(object):
    def __init__(self, host, port):
        self.request = socket.socket()
        self.request.connect((host,port))
        self.recv_data = b''
        print('[%s:%s]' % self.request.getsockname())

    def auth(self):
        while True:
            try:
                data = self.recv_msg()
            except ConnectionAbortedError:
                print('Authentication NOK')
                raise

            if data.get('action') != 'AUTH':
                raise PermissionError('Received invalid authentication data')
            try:
                decryptor = RSA_Decryptor('~/.ssh/id_rsa')
                pwd = decryptor.decrypt_b64(data.get('data').encode())
                cipher = decryptor.decrypt_b64(data.get('cipher').encode())
            except: # invalid decryption
                pwd    = b'unknown'
                cipher = b'unknown'

            self.aes = AES_Encryptor(pwd)
            encipher = self.aes.encrypt_b64(cipher)
            response = {'action':'AUTH', 'data':encipher.decode()}
            self.send_msg(response)
            data = self.recv_msg()
            if data and data.get('status') == 200:
                print('Authentication OK')
                return


    def run(self):
        try:
            self.auth()
            while True:
                cmd = input(">> ").strip()
                if len(cmd) == 0: continue
                if cmd == 'exit':
                    break
                elif cmd == 'help':
                    print(HELP)
                    continue
                elif cmd == 'debug off':
                    logger.setLevel(logging.WARN)
                    continue
                elif cmd == 'debug on':
                    logger.setLevel(logging.DEBUG)
                    continue

                data = {'action':'CMD', 'cmd':cmd}
                self.send_msg(data,encrypt=True)

                data = self.recv_msg()
                if data.get('status') != 205:
                    print(data.get('msg'))
                    continue
                print(data.get('output'))

# ###########################
# # 粘包测试, 将3条消息放在一起发送, 检测server 端是否正确分包
#                 data = {'action':'CMD', 'cmd':cmd}
#                 self.send_msg_3times(data,encrypt=True)

#                 data = self.recv_msg()
#                 if data.get('status') != 205:
#                     print(data.get('msg'))
#                     continue
#                 print(data.get('output'))

#                 data = self.recv_msg()
#                 if data.get('status') != 205:
#                     print(data.get('msg'))
#                     continue
#                 print(data.get('output'))


#                 data = self.recv_msg()
#                 if data.get('status') != 205:
#                     print(data.get('msg'))
#                     continue
#                 print(data.get('output'))
# ###########################

        except KeyboardInterrupt:
            print('\nBye bye!')
        except PermissionError as e:
            print(e)
        except ConnectionAbortedError as e:
            print(e)
        except Exception as e:
            print(e)
        finally:
            # self.request.shutdown(socket.SHUT_RDWR)
            self.request.close()


    def send_msg(self, data, encrypt=False):
        '''
        send msg with header + body to client
        '''
        body = json.dumps(data).encode()
        logger.debug(b'body to send: '+body)
        if encrypt:
            body = self.aes.encrypt_b64(body)

        header = create_msg_header(len(body), encrypt)
        logger.debug(b'send msg: '+header+body)
        self.request.sendall(header+body)


    def recv_msg(self):
        '''
        receive msg with header + body
        '''
        while True:
            if len(self.recv_data) >= HEADER_SIZE:
                magic,ver,msg_size,encryted = parse_msg_header(self.recv_data[:HEADER_SIZE])
                logger.debug('recv header: magic=%r ver=%r size=%r encrypted=%r' % (magic,ver,msg_size,encryted))

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
                logger.debug(b'recv body: '+body)
                return json.loads(body.decode())
            else:
                # header not completed, continue receive data
                data = self.request.recv(BUF_SIZE)
                if not data:
                    raise ConnectionAbortedError('client disconnected')
                self.recv_data += data

    def send_msg_3times(self, data, encrypt=False):
        '''
        粘包测试, 将3条消息放在一起发送, 检测server 端是否正确分包
        '''
        body = json.dumps(data).encode()
        logger.debug(b'body to send: '+body)
        if encrypt:
            body = self.aes.encrypt_b64(body)

        header = create_msg_header(len(body), encrypt)
        logger.debug(b'send msg: '+header+body)
        self.request.sendall(header+body+header+body+header+body)


def main():
    set_io_utf8()
    client = SSH_Client(host, port)
    client.run()

if __name__ == '__main__':
    main()





