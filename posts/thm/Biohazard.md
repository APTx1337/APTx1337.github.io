---
layout: default
title : bvr0n - Biohazard Write-up
---

_**Oct 02, 2020**_

[Biohazard](https://tryhackme.com/room/biohazard) Writeup

## Nmap Scan :

```
bvr0n@kali:~$ nmap -sC -sV 10.10.56.77
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c9:03:aa:aa:ea:a9:f1:f4:09:79:c0:47:41:16:f1:9b (RSA)
|   256 2e:1d:83:11:65:03:b4:78:e9:6d:94:d1:3b:db:f4:d6 (ECDSA)
|_  256 91:3d:e4:4f:ab:aa:e2:9e:44:af:d3:57:86:70:bc:39 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Beginning of the end
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
## Questions : 

```
- On the /mansionmain/ we see a note in the code source that says :
<!-- It is in the /diningRoom/ -->

- When going to /diningRoom/ we see a base64 code when decoded gives : 
How about the /teaRoom/

- When we go to /teaRoom/ we see a path that lead to /artRoom/ & a lock pick that give the lock pick flag.

- After going to the /artRoom/ we clicked on the YES button to get a map that looks like this : 

Location:
/diningRoom/
/teaRoom/
/artRoom/
/barRoom/
/diningRoom2F/
/tigerStatusRoom/
/galleryRoom/
/studyRoom/
/armorRoom/
/attic/

- Visiting the /barRoom/ and submitting the lockpick flag we got earlier we get redirected to submitting the piano flag, clicking on the READ button we get a music note encoded in base32 when decoded gives the music sheet flag.

- After submiting the Music sheet flag we get redirected to a Secret bar room to enter an emblem, we submit the emblem we got earlier and get a name : 
rebecca

- the rebecca actually is a key for decoding a Vigenère encoding we get from `/diningRoom/emblem_slot.php` , when decoded it gives this : 
``there is a shield key inside the dining room. The html page is called the_great_shield_key``

- going to `/diningRoom/the_great_shield_key.html` we get the Shield key flag.

- going to /diningRoom2F/ we can see in the code source some endoded text, it was ROT13 :

You get the blue gem by pushing the status to the lower floor. The gem is on the diningRoom first floor. Visit sapphire.html

- the note says we need to go the /diningRoom/sapphire.html so let's go and grab the blue gem flag.

- Next step is to go to /tigerStatusRoom/ and submit the blue gem flag to get the 1st crest.

- Going to /galleryRoom/ and examining the note we get our 2d crest.

- visiting /armorRoom/ with the shield flag, we get the 3rd crest.

- Then to /attic/ to enter the shield flag, after that read the note.txt for the 4th crest.
```
 ## Flags :

```
#4 Emblem flag : emblem{fec8326*******************21d58727}
#5 Lock pick flag : lock_pick{037b35e*******************9c8e1837}
#6 Music sheet flag : music_sheet{362d72d*******************6a1f676e}
#7 Gold emblem : gold_emblem{58a8c4*******************a4d7ff4843}
#8 Shield key flag : shield_key{48a7a92*******************0798cbac}
#9 blue gem flag : blue_jewel{e1d45*******************bc475d48aa}
```
## Crest :

```
1 Crest : [base64] S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9 [base32] KJWFEUKJJBLHUWSYJE3ESRY = RlRQIHVzZXI6IG
2 Crest : [base32] GVFWK5KHK5WTGTCILE4DKY3DNN4GQQRTM5AVCTKE [base58] 5KeuGWm3LHY85cckxhB3gAQMD = h1bnRlciwgRlRQIHBh
3 Crest : [base64] MDAxMTAxMTAgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAxMDAgMDExMDAxMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMTEgMDAxMDAwMDAgMDAxMTAxMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTAxMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMDEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTEwMDA= [binary] 00110110 00110011 00100000 00110011 00110011 00100000 00110100 01100100 00100000 00110011 00110110 00100000 00110100 00111001 00100000 00110100 00111000 00100000 00110110 01100011 00100000 00110111 00110110 00100000 00110110 00110100 00100000 00110101 00110110 00100000 00110011 00111001 00100000 00110110 01100001 00100000 00110101 00111001 00100000 00110101 00110111 00100000 00110011 00110101 00100000 00110011 00110000 00100000 00110101 00111000 00100000 00110011 00110010 00100000 00110110 00111000 [HEX] 63 33 4d 36 49 48 6c 76 64 56 39 6a 59 57 35 30 58 32 68 = c3M6IHlvdV9jYW50X2h
4 Crest : [base58] gSUERauVpvKzRpyPpuYz66JDmRTbJubaoArM6CAQsnVwte6zF9J4GGYyun3k5qM9ma4s [HEX] 70 5a 47 56 66 5a 6d 39 79 5a 58 5a 6c 63 67 3d 3d = pZGVfZm9yZXZlcg==

Final crest : RlRQIHVzZXI6IGh1bnRlciwgRlRQIHBhc3M6IHlvdV9jYW50X2hpZGVfZm9yZXZlcg==

- Decoding it from base64 we get :

FTP user: hunter, FTP pass: you_cant_hide_forever

- Login to ftp we get a file that is protected by gpg and 3 other jpgg images, following the rooms hint "Three picture, three hints: hide, comment and walk away", means 1st steghide, exiftool to see comments and binwalk.
```
* 1st image :

```
bvr0n@kali:~/CTF/THM/Biohazard$ steghide extract -sf 001-key.jpg 
Enter passphrase: (no password) 
wrote extracted data to "key-001.txt".
```
* 2d image :

```
bvr0n@kali:~/CTF/THM/Biohazard$ exiftool 002-key.jpg 
X Resolution                    : 1
Y Resolution                    : 1
Comment                         : 5fYmVfZGVzdHJveV9
Image Width                     : 100
```

* 3rd image :

```
bvr0n@kali:~/CTF/THM/Biohazard$ binwalk --dd=".*" 003-key.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
1930          0x78A           Zip archive data, at least v2.0 to extract, uncompressed size: 14, name: key-003.txt
2124          0x84C           End of Zip archive, footer length: 22
```

```
- After getting all the cipher we get base64 encoded text when decoded it give us the password for the gpg file :

cGxhbnQ0Ml9jYW5fYmVfZGVzdHJveV93aXRoX3Zqb2x0 = plant42_can_be_destroy_with_vjolt

- let's grabe the helmet key :

bvr0n@kali:~/CTF/THM/Biohazard$ gpg -d helmet_key.txt.gpg 
gpg: AES256 encrypted data
gpg: encrypted with 1 passphrase
helmet_key{458493193501d2b94bbab2e727f8db4b}

- After going to /studyRoom/ and submiting the helmet key we get a file named doom.tar.gz :

bvr0n@kali:~/CTF/THM/Biohazard$ gunzip doom.tar.gz
bvr0n@kali:~/CTF/THM/Biohazard$ tar -xf doom.tar
bvr0n@kali:~/CTF/THM/Biohazard$ cat eagle_medal.txt 

SSH user: umbrella_guest

- going to /hidden_closet/ (this path we got earlier in FTP inside a file named important) submiting the helmet key we get our ssh password :

SSH password: T_virus_rules
```

## Internal Enum :

```
- for the weasker's password, we saw earlier a cipherd text inside /hiddenCloset/MO_DISK1.txt the key for it's inside the /home/umbrella_guest/.jailcell/chris.txt

Weasker's password : stars_members_are_my_guinea_pig

- When we check weasker's permission we notice that he have it all haha :

weasker@umbrella_corp:/var/backups$ sudo -l
[sudo] password for weasker: 
User weasker may run the following commands on umbrella_corp:
    (ALL : ALL) ALL

weasker@umbrella_corp:/var/backups$ sudo su
root@umbrella_corp:/var/backups# id
uid=0(root) gid=0(root) groups=0(root)
```
<br>
best regards

[bvr0n](https://github.com/bvr0n)


<br>
[back to main()](../../index.md)

<br>
