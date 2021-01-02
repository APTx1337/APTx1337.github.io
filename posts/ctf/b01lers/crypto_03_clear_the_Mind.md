---
layout : default
title  : APTx1337 | B01lers_CTF - Clear the Mind Writeup
---

## B01lers_CTF(Clear the Mind)

_**Oct 3-4, 2020**_


<br>

<h3 id="Challenge Description">Challenge Description</h3>

![Banner](../../../assets/images/b01lers_ctf/clear_the_Mind_banner.png "Banner")

> They've gotten into your mind, but haven't managed to dive that deep yet. Root them out before it becomes an issue.




<br>

<h3 id="Solution">Solution</h3>


Same as the Dream Stealing challenge, this one also inlcudes an attack against (textbook) RSA. At first I tried to obtain p and q and then solve the challenge but [factordb](http://factordb.com) did not work for me :(.

Then it was observed that here the value of e is relatively small compared to the modulus N. So we can perform what is called a low public exponent attack and obtain the flag.

As we remember, RSA works by raising a plaintext to a power e and then modulo that to n. So 

c = plaintext**e (mod N)
 
Because of the small value of `e, (plaintext**e) < N`, so the mod N operation is basically useless. Therfore : 

`c = plaintext ** 3`

so

`plaintext = 3√c` (Notice it is cube root not 3*√c).

Basically we need to calculate the cube root of c which can be done using gmpy.

```python
import gmpy
from Crypto.Util.number import long_to_bytes

# low public exponent attack

n = 102346477809188164149666237875831487276093753138581452189150581288274762371458335130208782251999067431416740623801548745068435494069196452555130488551392351521104832433338347876647247145940791496418976816678614449219476252610877509106424219285651012126290668046420434492850711642394317803367090778362049205437
c = 4458558515804625757984145622008292910146092770232527464448604606202639682157127059968851563875246010604577447368616002300477986613082254856311395681221546841526780960776842385163089662821
e = 3

m = gmpy.root(c, 3)[0]
print(long_to_bytes(m))
```

Flag : `flag{w3_need_7o_g0_d3ep3r}`


<br>
<br>

best regards

[Y3tAn0th3rN0ob](https://github.com/y3tan0th3rn0ob)

--------------

[back to B01lers_CTF()](../../ctf/b01lers.md)

[back to main()](../../../index.md)


