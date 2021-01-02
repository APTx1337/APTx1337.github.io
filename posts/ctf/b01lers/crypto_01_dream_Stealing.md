---
layout : default
title  : APTx1337 | B01lers_CTF - Dream Stealing Writeup
---

## B01lers_CTF(Dream_Stealing)

_**Oct 3-4, 2020**_


<br>

<h3 id="Challenge Description">Challenge Description</h3>

![Banner](../../../assets/images/b01lers_ctf/dream_Stealing_banner.png "Banner")

> I've managed to steal some secrets from their subconscious, can you figure out anything from this?




<br>

<h3 id="Solution">Solution</h3>

We have been given :

- A Modulus, N
- One Factor of Modulus, (let it be p)
- Public Exponent, e
- Ciphertext, c

This is a simple attack against (textbook) RSA, where we have to decrypt c. As we know that N is made up of two primes, p and q. Since p is given here then q can be calculated and the ciphertext can be decrypted to get the flag.

As we know RSA works by raising a plaintext to a power e and then modulo that to n. So

`c = plaintext**e (mod n).`

So by reversing this process we can get the plaintext which is our flag. If you want to know how to reverse this, then have a look at https://stackoverflow.com/questions/49818392/how-to-find-reverse-of-powa-b-c-in-python.

Here's the solve script. 

```python
from Crypto.Util.number import long_to_bytes

e = 65537
c = 75665489286663825011389014693118717144564492910496517817351278852753259053052732535663285501814281678158913989615919776491777945945627147232073116295758400365665526264438202825171012874266519752207522580833300789271016065464767771248100896706714555420620455039240658817899104768781122292162714745754316687483
n = 98570307780590287344989641660271563150943084591122129236101184963953890610515286342182643236514124325672053304374355281945455993001454145469449640602102808287018619896494144221889411960418829067000944408910977857246549239617540588105788633268030690222998939690024329717050066864773464183557939988832150357227

p = 9695477612097814143634685975895486365012211256067236988184151482923787800058653259439240377630508988251817608592320391742708529901158658812320088090921919
q = 10166627341555233885462189686170129966199363862865327417835599922534140147190891310884780246710738772334481095318744300242272851264697786771596673112818133 #calculate this by dividing N by p, just some basic maths ;).

phi = (p-1)*(q-1)
z = pow(e, -1, phi)
m = pow(c, z, n)

print(long_to_bytes(m))
```

When we run this script, we get the flag : `flag{4cce551ng_th3_subc0nsc10us}`





<br>
<br>

best regards

[Y3tAn0th3rN0ob](https://github.com/y3tan0th3rn0ob)

--------------

[back to B01lers_CTF()](../../ctf/b01lers.md)

[back to main()](../../../index.md)


