#!/usr/bin/env python
#_*_coding:utf-8_*_

import socketserver, socket
import json
import configparser
import os
import hashlib
import threading
from subprocess import PIPE, Popen, STDOUT, TimeoutExpired 
from conf import settings

BUF_SIZE = 4096

STATUS_CODE = {
    200:"Authentication OK",
    201:"Invalid auth data",
    202:"Wrong username or password",
    203:"Invalid request",
    204:"Invalid cmd",
    205:'Command executed',

    250:"Invalid cmd format, e.g:{'action':'get','filename':'test.py','size':344}",
    251:"Invalid cmd",
    252:"Invalid auth data",
    253:"Wrong username or password",
    254:"Passed authentication",
    255:"Filename doesn't provided",
    256:"No such file or directory",
    257:"ready to send file",
    258:"md5 verification",
}


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
        outs = cmd + ': command timeouted'

    err = process.returncode
    return outs, err

class FTPHandler(socketserver.BaseRequestHandler):
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
    def finish(self):
        self.print_msg('disconnected')
        with self.lock:
            self.conn_list.remove(self.request)

    @classmethod
    def clean(cls):
        with cls.lock:
            for c in cls.conn_list:
                # shutdown sockects then recv functions return 
                # empty data (b''), so that sub-threads terminate
                c.shutdown(socket.SHUT_RDWR)

    def print_msg(self, *args, **kw):
        print('[%s:%s]' % self.client_address, *args, **kw)

    # override
    def handle(self):
        try:
            while True:
                data = self.recv_json()
                if not data: # client disconnected
                    break
                if data.get('action') is not None:  #action不为空
                    if hasattr(self, "_%s" % data.get('action')): #客户端action 符合服务端action
                        func = getattr(self, "_%s" % data.get('action'))
                        self.print_msg('func:', func.__name__)
                        ret = func(data)
                    else:  #客户端action 不符合服务端action
                        self.print_msg("invalid cmd")
                        self.send_response(251)  # 251：“无效的CMD”
                else:  #客户端action 不正确
                    self.print_msg("invalid cmd format")
                    self.send_response(250) # 250：“无效的cmd格式，例如：{'action'：'get'，'filename'：'test.py'，'size'：344}”
        except socket.timeout:
            self.print_msg('connection timeout')
        except Exception as e:
            self.print_msg(e)
        finally:
            # don't need to explictly close the socket
            pass


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
        try:
            data = self.request.recv(BUF_SIZE)
            self.print_msg('recv:', data)
            if data:
                data = json.loads(data.decode())
            return data
        except Exception as e:
            self.print_msg('recv_json:', e)
        
    def send_response(self, status_code, data=None):
        '''
        send response with json format to client
        '''
        response = {'status_code':status_code, 'status_msg':STATUS_CODE[status_code]}
        if data:
            response.update(data)
        self.send_json(response)


    def _auth(self,*args,**kwargs):
        '''核对服务端 发来的用户，密码'''
        data = args[0]
        if data.get("username") is None or data.get("password") is None: #客户端的用户和密码有一个为空 则返回错误
            self.send_response(252)  # 252：“验证数据无效”
            raise PermissionError('Invalid auth data')

        user = self.authenticate(data.get("username"),data.get("password")) #把客户端的用户密码进行验证合法性
        if user is None: #客户端的数据为空 则返回错误
            self.send_response(253)  # 253：“错误的用户名或密码”
            raise PermissionError('Wrong username or password')
            
        else:
            self.print_msg("password authentication",user)
            self.user = user
            self.home = "%s/%s" %(settings.USER_HOME,self.user["Username"]) #当前连接用户的目录
            os.chdir(self.home)
            self.send_response(254)  # 254：“通过身份验证”

    def authenticate(self,username,password):
        '''验证用户合法性，合法就返回数据，核对本地数据'''
        config = configparser.ConfigParser()
        config.read(settings.ACCOUNT_FILE)
        if username in config.sections():  #用户匹配成功
            _password = config[username]["Password"]
            if _password == password:  #密码匹配成功
                self.print_msg("pass auth..",username)
                config[username]["Username"] = username
                return config[username]

    def _put(self,*args,**kwargs):
        "client send file to server"
        print(args)
        data = args[0]
        if data.get('filename') is None:
            self.send_response(255)  # 255：“文件名不提供”
        file_abs_path = "%s/%s" %(self.home, data.get('filename'))  #客户端发送过来的目录文件
        file_size = data.get('filesize')
        print('filename:', file_abs_path, 'filesize:', file_size)
        self.request.send(b'1')
        received_size = 0
        with open(file_abs_path, 'wb') as file_obj:
            while received_size < file_size: #当接收的量 小于 文件总量 就循环接收文件
                data = self.request.recv(BUF_SIZE) #一次接收4096
                received_size += len(data) #本地接收总量每次递增
                file_obj.write(data) #把接收的数据 写入文件
            else:
                self.print_msg("--->file recv done<---") #成功接收文件

    def _get(self,*args,**kwargs):
        '''get 下载方法'''
        data = args[0]
        if data.get('filename') is None:
            self.send_response(255)  # 255：“文件名不提供”，
        file_abs_path = "%s/%s" %(os.path.realpath(os.curdir), data.get('filename'))  #客户端发送过来的目录文件
        self.print_msg("file abs path",file_abs_path)

        if os.path.isfile(file_abs_path):  #客户端目录文件名 存在服务端
            file_obj = open(file_abs_path,'rb')  # 用bytes模式打开文件
            file_size = os.path.getsize(file_abs_path)  #传输文件的大小
            self.send_response(257,data={'file_size':file_size}) #返回即将传输的文件大小 和状态码

            self.request.recv(1)  #等待客户端确认

            if data.get('md5'): #有 --md5 则传输时加上加密
                md5_obj = hashlib.md5()
                for line in file_obj:
                    self.request.send(line)
                    md5_obj.update(line)
                else:
                    file_obj.close()
                    md5_val = md5_obj.hexdigest()
                    self.send_response(258,{'md5':md5_val})
                    print("send file done....")
            else:  #没有 --md5  直接传输文件
                for line in file_obj:
                    self.request.send(line)
                else:
                    file_obj.close()
                    self.print_msg("send file done....")

        else:
            self.send_response(256) # 256：“服务器上不存在文件”=


    def _ls(self,*args,**kwargs):
        data = args[0]
        path= data.get('path')
        file_abs_path = self.__get_realpath(path)
        self.print_msg("file path:", file_abs_path)
        if file_abs_path is None:
            outs = 'cannot access %s: No such file or directory' % path
            outs = outs.encode()
        else:
            file_rel_path = os.path.relpath(file_abs_path, os.path.realpath(os.curdir))
            cmd = 'ls -al ' + file_rel_path
            self.print_msg(cmd)
            outs, err = exe_cmd(cmd)
            self.print_msg(outs, err)

        self.request.send(outs)
        
    def _cd(self,*args,**kwargs):
        data = args[0]
        path = data.get('path', '')
        file_abs_path = self.__get_realpath(path)
        if file_abs_path is None:
            self.send_response(256)
        else:
            try:
                os.chdir(file_abs_path)
                curdir = self.__get_curdir()
                self.send_response(205,{'curdir':curdir})
            except NotADirectoryError:
                self.send_response(256,{'status_msg':'Not a directory'})
            except:
                self.send_response(256,{'status_msg':'Failed to change dir'})


    def __get_realpath(self, path):
        if path.startswith('~'):
            file_abs_path = os.path.realpath("%s/%s" %(self.home, path[1:]))
        elif path.startswith('/'):
            file_abs_path = os.path.realpath("%s/%s" %(self.home, path))
        else:    
            file_abs_path = os.path.realpath("%s/%s" %(os.curdir, path))

        if self.home in file_abs_path:
            return file_abs_path


    def __get_curdir(self):
        curdir = os.path.realpath(os.curdir)
        curdir = curdir.replace(self.home, '') or '/'
        return curdir

    def _pwd(self,*args,**kwargs):
        curdir = self.__get_curdir()
        self.request.send(curdir.encode())


    

if __name__ == '__main__':
    HOST, PORT = "127.0.0.1", 9999