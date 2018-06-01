#!/usr/bin/env python
# coding:utf-8

import os
import sys
import argparse
import socketserver

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from core.ftphandler import FTPHandler
from conf import settings

class FTPServer(object):
    def __init__(self):
        parser = argparse.ArgumentParser(description='Simple FTP server with few functionalites')
        parser.add_argument("-s", "--host", type=str, default=settings.HOST, help='server binding host address')
        parser.add_argument("-p", "--port", type=int, default=settings.PORT, help="server binding port")
        parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')
        self.args = parser.parse_args()


    def start(self):
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        server = socketserver.ThreadingTCPServer((self.args.host, self.args.port), FTPHandler)
        print("FTP server is running on %s:%d; press Ctrl-C to terminate." % (self.args.host, self.args.port))

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nBye bye')
        finally:
            server.shutdown()
            server.server_close()
            server.RequestHandlerClass.clean()



if __name__ == '__main__':
    ftpsrv = FTPServer()
    ftpsrv.start()