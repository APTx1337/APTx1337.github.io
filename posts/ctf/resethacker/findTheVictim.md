---
layout: default
---

## RESTHACKER_CTF() - Find the victim

_**Aug 29, 2020**_

<br>

### Challenge Description
>Binod is a detective. He is spying on someone but he don't know his name. He got some files from the victim's house. Now, he trying to find the victim name through files. Can you help him out to grab the name from ?? - wantpassword.txt - somethingishere.txt.

<br>

### How We Solve it :


We get 2 initial files from this challenge, Let's check every one of them !

`wantpassword.txt` had this inside :
```
01110 11000 01010 11000 01100 00011 10011 00110 10010 10010 00001 01100 01001 00110 01100 11011 10011 10110 10011 10110
```


first look, i thought it was either Binary or Bacon Cipher, but it wasn't :( 

after a while i realised that there is an encryption simillar called **Baudot Murray**, so i give it a try and i was correct.

Decoding it gives : `coronawillendin2020`

so we know that it's a password for something, let's keep it & check the second file


`somethingishere.txt` had some base64 inside so my first thought is to decode it : 

```sh
cat somethingishere.txt | base64 -d (running this command give us something weird, 2 files inside)
```

so i went to Cyberchef and dropped the file & decode it from base64 we get a ZIP file.

after downloading the ZIP we use the password we found earlier to unzip it and we got 2 files inside of it:

- `secret_here.zip`
- `findmeifyoucan.txt`


the zip file is password protected so i thought that the other text file maybe the password

<br>

`findmeifyoucan.txt` had this inside : 
```
kGiq5xttamckpwwipsH179eYpE5QhQnk3VfgWi46YjjWW3VqAavJ3aDR53UdbwNBut2HxFpyYztatLaGrwtbhHxoEjZsSVnheVVJwA7GX4jPg2ETX
```

it was base58 so when decoding it we get this : 

```
.. .  .. ....  ... ...  . ....  .... ....  .. ...  . .....  .. .  ... .  . .  .. ..
```

this is where i found myself wondering again ahah, after searching i found out that it's TAP encoding 

Decoding it gives us : **findtheflag** (the password for the zip file)

after unziping it we get a png image, looks like something in the top left corner, i open it with StegoSolve and i found a QR code !

after scanning the QR code we get a link : 
`https://anonymousfiles.io/4KRZLYGm/`

I downloaded the WAV file and played it,it was morse code, decode it here and get the flag :) 
`https://morsecode.world/international/decoder/audio-decoder-adaptive.html`

Final Flag : `RESTCON{MYN4ME1S4LBERTOP4ST4}`

<br>
best regards

bvr0n


<br>
<br>

[back to RESTHACKER_CTF](../../ctf/resethacker.md)

[back to main()](../../../index.md)

<br>
<br>
