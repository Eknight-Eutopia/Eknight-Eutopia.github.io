---
layout:     post   				    # 使用的布局（不需要改）
title:      【网络攻防大作业】Magic Padding Oracle实验报告 				# 标题 
subtitle:   Eutopia's Blog #副标题
date:       2024-1-1				# 时间
author:     Eutopia 						# 作者
header-img: img/post-bg-1.png 	#这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								#标签
    - 密码
    - Padding Oracle
---

# Padding Oracle实验报告

## 1. Overview

Padding Oracle：一些系统在解密密文时，会先验证其填充是否合法，如果不合法则会抛出异常。针对此行为的攻击即为padding oracle攻击

## 2. Lab Environment

- Seed虚拟机
- Labsetup.zip

使用`dcbuild`和`dcup`命令启动docker环境

## 3. Task1：Getting Familiar with Padding

Padding：分组加密算法要求明文长度需要为分组长度的整数倍。因此需要padding填充末尾使长度满足要求

使用`echo -n`创建文件P，长度为5。`-n`参数表示结尾不带换行符

```shell
echo -n "12345" > P
```

使用openssl命令对文件进行加密，并且对加密文件解密查看padding

```shell
# 加密
openssl enc -aes-128-cbc -e -in P -out C

# 解密
openssl enc -aes-128-cbc -d -nopad -in C -out P_new
```

结果如下，可以看出P_new文件内容末尾出现`'\x0a'`，文件长度变为16。表明加密过程进行了padding `'\x0a'`字符到16位的操作。

![image-20231230192916386](/img/posts/2024-1-1-Padding_Oracle实验报告.assets/image-20231230192916386.png)

分别尝试文件长度为10， 16的文件，结果如下，可以得出padding规律（要填充的位数作为填充字符）

![image-20231230193317519](/img/posts/2024-1-1-Padding_Oracle实验报告.assets/image-20231230193317519.png)

## 4. Task2：Padding Oracle Attack（level 1）

 连接server端，获取到IV与密文

![image-20231230193641177](/img/posts/2024-1-1-Padding_Oracle实验报告.assets/image-20231230193641177.png)

```shell
01020304050607080102030405060708	# IV
a9b2554b0944118061212098f2f238cd779ea0aae3d9d020f3677bfcb3cda9ce # ciphertext
```

可以与server交互，向server发送输入，输入应为IV+密文，server会使用其K和IV解密，并且返回padding是否有效。尝试通过返回信息来得出密文的真实内容。

server端对密文解密过程如下，为CBC模式。padding oracle攻击的原理为假设未知Plaintext P2的填充位为0x01，那么可以通过构造C1来与D2异或使解密的P2填充位为0x01，此时server端会返回Valid信息，可以解出未知的D2.当D2完全解出时，即可使用正确C1与D2异或获取明文。

![在这里插入图片描述](/img/posts/2024-1-1-Padding_Oracle实验报告.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3lhbGVjYWx0ZWNo,size_16,color_FFFFFF,t_70.png)

`manual_attack.py`脚本如下，对通过尝试C1末位256种字符解出D2末位值：

```python
#!/usr/bin/python3
import socket
from binascii import hexlify, unhexlify

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

class PaddingOracle:

    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        ciphertext = self.s.recv(4096).decode().strip()
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> None:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        resp = self.s.recv(4096).decode().strip()
        return resp 

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()


if __name__ == "__main__":
    oracle = PaddingOracle('10.9.0.80', 5000)

    # Get the IV + Ciphertext from the oracle
    iv_and_ctext = bytearray(oracle.ctext)
    IV    = iv_and_ctext[00:16]
    C1    = iv_and_ctext[16:32]  # 1st block of ciphertext
    C2    = iv_and_ctext[32:48]  # 2nd block of ciphertext
    print("C1:  " + C1.hex())
    print("C2:  " + C2.hex())

    ###############################################################
    # Here, we initialize D2 with C1, so when they are XOR-ed,
    # The result is 0. This is not required for the attack.
    # Its sole purpose is to make the printout look neat.
    # In the experiment, we will iteratively replace these values.
    D2 = bytearray(16)

    D2[0]  = C1[0]
    D2[1]  = C1[1]
    D2[2]  = C1[2]
    D2[3]  = C1[3]
    D2[4]  = C1[4]
    D2[5]  = C1[5]
    D2[6]  = C1[6]
    D2[7]  = C1[7]
    D2[8]  = C1[8]
    D2[9]  = C1[9]
    D2[10] = C1[10]
    D2[11] = C1[11]
    D2[12] = C1[12]
    D2[13] = C1[13]
    D2[14] = C1[14]
    D2[15] = C1[15]
    ###############################################################
    # In the experiment, we need to iteratively modify CC1
    # We will send this CC1 to the oracle, and see its response.
    CC1 = bytearray(16)

    CC1[0]  = 0x00
    CC1[1]  = 0x00
    CC1[2]  = 0x00
    CC1[3]  = 0x00
    CC1[4]  = 0x00
    CC1[5]  = 0x00
    CC1[6]  = 0x00
    CC1[7]  = 0x00
    CC1[8]  = 0x00
    CC1[9]  = 0x00
    CC1[10] = 0x00
    CC1[11] = 0x00
    CC1[12] = 0x00
    CC1[13] = 0x00
    CC1[14] = 0x00
    CC1[15] = 0x00

    ###############################################################
    # In each iteration, we focus on one byte of CC1.  
    # We will try all 256 possible values, and send the constructed
    # ciphertext CC1 + C2 (plus the IV) to the oracle, and see 
    # which value makes the padding valid. 
    # As long as our construction is correct, there will be 
    # one valid value. This value helps us get one byte of D2. 
    # Repeating the method for 16 times, we get all the 16 bytes of D2.

    K = 1
    for i in range(256):
          CC1[16 - K] = i
          status = oracle.decrypt(IV + CC1 + C2)
          if status == "Valid":
              print("Valid: i = 0x{:02x}".format(i))
              print("CC1: " + CC1.hex())
    ###############################################################

    # Once you get all the 16 bytes of D2, you can easily get P2
    P2 = xor(C1, D2)
    print("P2:  " + P2.hex())
```

运行后可得结果，可以看到成功解出C1末位为0xcf时，padding正确，所以可以得出D2末位为`0xcf xor 0x01 = 0xce`：

![image-20231231105351823](/img/posts/2024-1-1-Padding_Oracle实验报告.assets/image-20231231105351823.png)

然后修改C1末位为`0xce xor 0x02`尝试C1倒数第二位解出使padding为0x02的valid情况，得到D2后两位`0x3b0xce`

![image-20231231105716391](/img/posts/2024-1-1-Padding_Oracle实验报告.assets/image-20231231105716391.png)

以此类推，可以得出D2值以及P2值：

![image-20231231111128460](/img/posts/2024-1-1-Padding_Oracle实验报告.assets/image-20231231111128460.png)

## 5. Task 3：Padding Oracle Attack（Level 2）

自动化进程，并获取所有分组的密文。

构造脚本如下：

```python
#!/usr/bin/python3
import socket
from binascii import hexlify, unhexlify

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

class PaddingOracle:

    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        ciphertext = self.s.recv(4096).decode().strip()
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> None:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        resp = self.s.recv(4096).decode().strip()
        return resp 

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()


if __name__ == "__main__":
    oracle = PaddingOracle('10.9.0.80', 6000)

    # Get the IV + Ciphertext from the oracle
    iv_and_ctext = bytearray(oracle.ctext)
    print(len(iv_and_ctext))
    # Num of ctext
    num = int(len(iv_and_ctext)/16 - 1)
    plain_text = ''
    for n in range(num):
        C = iv_and_ctext[(n)*16: (n+1)*16]
        if n == 0:
            print(f"IV:  " + C.hex())
        else:
            print(f"C{n}: " + C.hex())
        
        # initialize D, IV, P
        D = bytearray(16)
        CC = bytearray(16)
        P = bytearray(16)
        
        
        # Solve D
        for K in range(1, 17):
            for i in range(256):
                CC[16 - K] = i
                # initialize input
                tmp_input = iv_and_ctext[0:(n+2)*16]
                tmp_input[n*16:(n+1)*16] = CC
                status = oracle.decrypt(tmp_input)
                if status == "Valid":
                    print("Valid: i = 0x{:02x}".format(i))
                    print("D: "+ D.hex())
                    print("CC: " + CC.hex())
                    # Update D
                    D[16 - K] = i^K
                    # Update CC
                    for j in range(1, K+1):
                        CC[16 - j] = D[16 - j]^(K+1)
                    
                    break
        
        # Once you get all the 16 bytes of D2, you can easily get P2
        P = xor(C, D)
        print("P:  " + P.hex())
        for j in range(16):
            plain_text += chr(P[j])
            
       
    print("Plaintext: " + plain_text) 
```

![image-20231231130753727](/img/posts/2024-1-1-Padding_Oracle实验报告.assets/image-20231231130753727.png)