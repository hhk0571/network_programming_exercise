simple FTP Server/Client for exercice
==============================

Table of Contents
+ [porpuse](#porpuse)
+ [sequence diagram](#sequence-diagram)
+ [example](#example)
    + [server](#server)
    + [client](#client)

## porpuse
simulate simple FTP, just for network programming exercice, please don't report bug to me ^_^

## description
only implemented following commands

| command | notes |
| ------- | ----- |
| ls \[dir\|file\] | list directories or files |
| cd \<dir\> | change dir |
| pwd | current dir |
| get \<filename\> | get file from server |
| put \<filename\> | put file to server |
| exit | disconnect from server |

## sequence diagram
TBD

## example
### server
``` bash
# ftpServer/bin/ftp_server.py 
FTP server is running on 127.0.0.1:9999; press Ctrl-C to terminate.

```
### client
``` bash
# ./ftp_client.py 
test001 123
Passed authentication!
--start interactive with u...
[test001 /]:ls
total 245174
drwxrwx--- 1 root vboxsf      4096 May 20 21:31 .
drwxrwx--- 1 root vboxsf         0 May 17 21:38 ..
-rwxrwx--- 1 root vboxsf 216445599 May 18 08:54 2015.12.25花絮.mp4
drwxrwx--- 1 root vboxsf         0 May 20 21:31 backup_tool
-rwxrwx--- 1 root vboxsf         0 May 12 15:45 data
-rwxrwx--- 1 root vboxsf       136 May 12 14:55 file
-rwxrwx--- 1 root vboxsf  34603008 May 13 19:37 linux.iso
drwxrwx--- 1 root vboxsf      4096 May 20 21:31 ping_proxy

[test001 /]:pwd
/
[test001 /]:cd backup_tool
[test001 /backup_tool]:pwd
/backup_tool
[test001 /backup_tool]:ls
total 6
drwxrwx--- 1 root vboxsf    0 May 20 21:31 .
drwxrwx--- 1 root vboxsf 4096 May 20 21:31 ..
-rwxrwx--- 1 root vboxsf 1439 Jul  6  2016 backup.py
-rwxrwx--- 1 root vboxsf   38 Jul  1  2016 excludes

[test001 /backup_tool]:cd ..
[test001 /]:put linux.iso
put-- ['put', 'linux.iso']
100%
--->file putting done<---
[test001 /]:get file
get-- ['get', 'file']
{'file_size': 136, 'status_code': 257, 'status_msg': 'ready to send file'}
100%
--->file getting done<---
[test001 /]:

```
