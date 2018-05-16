simple TCP Server/Client model to simulate ssh
==============================

Table of Contents
+ [porpuse](#porpuse)
+ [preparation](#preparation)
+ [sequence diagram](#sequence-diagram)
    + [overview](#overview-sequence)
    + [authentication](#authentication-sequence)
+ [example](#example)
    + [server](#server)
    + [client](#client)

## porpuse
simulate simple ssh, just for network programming exercice, please don't report bug to me ^_^

## preparation
1. requires Python 3.5 or newer version
1. requires 3rd-party modules, e.g. pycryptodome
    ```
    pip install -r equirements.txt
    ```
1. generate RSA key pair: id_rsa (priviate key) and  id_rsa.pub (public key)
    ```
    ssh-keygen -t rsa -C
    ls ~/.ssh
    $ authorized_keys  id_rsa  id_rsa.pub  known_hosts
    ```
1. register public key to ~/.ssh/authorized_keys in remote host
    ```
    ssh-copy-id -i id_rsa.pub root@192.168.56.111
    ```

## sequence diagram
### overview sequence
![sequence](seq_overview.png "overview sequence")
### authentication sequence
![sequence](seq_authentication.png "authentication sequence")

## example
### server
``` bash
[root@MiniCentOS_1 simple_ssh]# ./ssh_server.py 
Server is running on port 54321; press Ctrl-C to terminate.
[192.168.56.111:40744] connected
[192.168.56.111:40744] generate password: '7I!^6M+4' cipher: '}Q{G7G43'
[192.168.56.111:40744] send: {'cipher': 'Y8ZJytzorEXzHJ8ZOrcHlXGnnmwNK9VUqVmy+3yOwl9yWJ/e0d3RRmPP6RdG6NIs5REKocZzanppbHUJyqtpwTWb+La8RqjgLcOuivxINKAoTJOS79t/htU0XL2pZPI7JJyH2
PusnKnEm1OIhGMUW/1ekoLX3G0KV+KOXQQzBEvyil86FZL3CfodO4zxMatPZHgS/rLkid3CPulIoifn0kdU0RjV460XcnHFkrx7T8dqU2bwkf8UEiPDMhFl933SVboeItM+Xgway7OFkh/rN5wdKjg/JTejeo4uFJqyFcSBZAZk4v8vOr51KVWJ7wWGKCMSZu/Tx4jotbQdop7aKQ==', 'data': 'RRUSlu8aQ4AzitUHHFfZvLY9VKW4P96cnWivIzm8k0N6sdBKZZrHne9UuqmszrSN0+oJDZYcQhBRwaLM0rBPa6ANkULcS3IgX8UKnl8OsxJqMZzASa0oDaPdUQChNDIBentHwkHvlX2hPKb8mBTi/7X0ot9Kfqeg4Rdq2l7mDEW2ukgk5C86lRTUcK2Qh5ftUqLi9Z486hOGb+8mqK0NkHcpSauy3IFkpCL0lbWAfGUh1F5RxAFROiC2JsPXna0f048i4yi8vz/c0EBWF3rIQJBCgD1EjPkank0rsTLSVrnvzxY1cjWQ+nOgiRkf9IQNCD4GYr7WHB68wV2hC3YjQA==', 'action': 'AUTH'}[192.168.56.111:40744] recv: b'{"action": "AUTH", "data": "lyFkD6g+b/Vh5XnIcemYOg=="}'
[192.168.56.111:40744] send: {'msg': 'Authentication OK', 'status': 200}
[192.168.56.111:40744] secure recv: b'{"action": "CMD", "cmd": "ls"}'
[192.168.56.111:40744] cmd output: b'docs\nencrypt.py\n__pycache__\nREADME.md\nrequirements.txt\nsequence_diagra' ...
[192.168.56.111:40744] secure send: {'msg': 'Command executed', 'error': 0, 'size': 128, 'status': 205}
[192.168.56.111:40744] secure recv: b'{"action": "SIZE_CONFIRMED", "data": 128}'
[192.168.56.111:40744] cmd done: sent 128 bytes

```
### client
``` bash
# ./ssh_client.py 192.168.56.111 54321
[192.168.56.111:50456]
Authentication OK
>> ls
README.md
requirements.txt
sequence_diagram.png
sequence.uml
ssh_client.py
ssh_server.py

>> 

```
