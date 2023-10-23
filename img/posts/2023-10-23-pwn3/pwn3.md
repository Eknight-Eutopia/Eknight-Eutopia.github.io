---
title: pwn3
---

## 题目考点

- 堆栈溢出原理
- ROP攻击
- Ida、pwndbg工具的使用
- 熟悉汇编语言

--------

## 解题思路

首先使用`checksec`工具检查`pwn3`文件基本信息，基本信息如下：

![checksec](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\checksec.png)

然后`./pwn3`运行一下，查看效果（注：权限可能需要修改以保证可以正常执行）

![正常运行](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\正常运行.png)

尝试输入较长字符串，查看结果，说明存在栈溢出漏洞。

![栈溢出漏洞](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\存在栈溢出漏洞.png)

使用ida工具逆向分析：

![main函数反汇编](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\main函数反汇编.png)

ROP攻击思路，将栈溢出到old_ebp下，后面覆盖要执行的`system("bin/sh")`代码：

<img src="C:\Users\Eknight\AppData\Roaming\Typora\typora-user-images\image-20230921223740755.png" alt="image-20230921223740755" style="zoom: 50%;" />

经过静态分析，得到`system`函数地址：

![system函数地址](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\system函数地址.png)

`"/bin/sh"`地址：

![字符串地址](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\字符串地址.png)

对pwn3进行动态调试，查看要填充多少字节才可以发生堆栈溢出：

在`stack_overflow`函数地址`0x800484F3`下断点:

![stackoverflow函数地址](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\stackoverflow函数地址.png)

查看`stack_overflow`内部`read`函数前设置了`0x28`字节的参数，因此需要输入28位以上才可以产生栈溢出覆盖返回地址。![image-20230921224714276](C:\Users\Eknight\AppData\Roaming\Typora\typora-user-images\image-20230921224714276.png)

构造`EXP.py`攻击`pwn3`

![python文件](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\python文件.png)

通过向`pwn3`发送超过`0x28+4`字节的输入，可以覆盖到返回地址，从而影响函数执行，使`pwn3`转去执行其他的函数

--------

## 结果

![结果](C:\SJTU\课程\大四上\信息安全综合实践（2）\练习\pwn3\images\结果.png)

成功弹出shell。