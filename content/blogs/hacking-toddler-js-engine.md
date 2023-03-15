---
title: "Hacking Toddler Js Engine"
date: 2023-03-15T18:24:55+07:00
draft: true
iscjklanguage: false
isarchived: false
categories: ["CTF"]
images: ["https://images.unsplash.com/photo-1501139083538-0139583c060f?w=1920&q=50"]
aliases: []
description: "Noob approach to hacking javascript engine"
---


## Introduction

This article is a writeup of a challenge from [KalmarCTF](https://kalmarc.tf/) called mjs. The challenge is to hack a javascript engine and get the flag. The challenge is easy, but I think it's still a good challenge to learn about getting started with javascript engine.


## What is MJS ?

MJS is a javascript engine written in C. The source code is available [here](https://github.com/cesanta/mjs). The engine is a very simple and had few builtin function. for example :
<dl>
  <dt><tt>print(arg1, arg2, ...);</tt></dt>
  <dd>Print arguments to stdout, separated by space.</dd>

  <dt><tt>load('file.js', obj);</tt></dt>
  <dd>Execute file <tt>file.js</tt>. <tt>obj</tt> paramenter is
  optional. <tt>obj</tt> is a global namespace object.
  If not specified, a current global namespace is passed to the script,
  which allows <tt>file.js</tt> to modify the current namespace.</dd>

  <dt><tt>die(message);</tt></dt>
  <dd>Exit interpreter with the given error message</dd>

  <dt><tt>let value = JSON.parse(str);</tt></dt>
  <dd>Parse JSON string and return parsed value.</dd>

  <dt><tt>let str = JSON.stringify(value);</tt></dt>
  <dd>Get string representation of the mJS value.</dd>

  <dt><tt>let proto = {foo: 1}; let o = Object.create(proto);</tt></dt>
  <dd>Create an object with the provided prototype.</dd>

  <dt><tt>'some_string'.slice(start, end);</tt></dt>
  <dd>Return a substring between two indices. Example:
      <tt>'abcdef'.slice(1,3) === 'bc';</tt></dd>

  <dt><tt>'abc'.at(0);</tt></dt>
  <dd>Return numeric byte value at given string index. Example:
      <tt>'abc'.at(0) === 0x61;</tt></dd>

  <dt><tt>'abc'.indexOf(substr[, fromIndex]);</tt></dt>
  <dd>Return index of first occurence of substr within the string or `-1`
  if not found.
      <tt>'abc'.indexOf('bc') === 1;</tt></dd>

  <dt><tt>chr(n);</tt></dt>
  <dd>Return 1-byte string whose ASCII code is the integer `n`. If `n` is
    not numeric or outside of `0-255` range, `null` is returned. Example:
      <tt>chr(0x61) === 'a';</tt></dd>

  <dt><tt>let a = [1,2,3,4,5]; a.splice(start, deleteCount, ...);</tt></dt>
  <dd>Change the contents of an array by removing existing elements and/or
    adding new elements. Example:
  <tt>let a = [1,2,3,4,5]; a.splice(1, 2, 100, 101, 102); a === [1,100,101,102,4,5];</tt></dd>
<s>
  <dt><tt>let s = mkstr(ptrVar, length);</tt></dt>
  <dd>Create a string backed by a C memory chunk. A string <tt>s</tt> starts
  at memory location <tt>ptrVar</tt>, and is <tt>length</tt> bytes long.</dd>

  <dt><tt>let s = mkstr(ptrVar, offset, length, copy = false);</tt></dt>
  <dd>Like `mkstr(ptrVar, length)`, but string <tt>s</tt> starts
  at memory location <tt>ptrVar + offset</tt>, and the caller can specify
  whether the string needs to be copied to the internal mjs buffer. By default
  it's not copied.</dd>

  <dt><tt>let f = ffi('int foo(int)');</tt></dt>
  <dd>Import C function into mJS. See next section.</dd>

  <dt><tt>gc(full);</tt></dt>
  <dd>Perform garbage collection. If `full` is `true`, reclaim RAM to OS.</s></dd>
</dl>


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

## Vulnerability

By doing simple issue search, we can find a [Buffer Overflow Issue](https://github.com/cesanta/mjs/issues/191) in the repository. 

~~~javascript
(JSON.stringify([1, 2, 3]))((JSON.parse - 10900)(JSON.stringify([1, 2, 3])));
~~~
If we look into the payload, it substracting 10900 from the JSON.parse function. It doesnt make sense to me, but it is a valid javascript code.
