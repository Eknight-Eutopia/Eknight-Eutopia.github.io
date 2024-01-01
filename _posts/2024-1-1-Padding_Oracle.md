---
layout:     post   				    # 使用的布局（不需要改）
title:      【网络攻防大作业】Magic Padding Oracle实验报告 				# 标题 
subtitle:   Eutopia's Blog #副标题
date:       2024-1-1				# 时间
author:     Eutopia 						# 作者
header-img: img/post-bg-3.png 	#这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								#标签
    - 密码
    - Padding Oracle
---



## Magic Padding Oracle WriteUp

无需搭建环境、直接连接服务器`nc 202.120.1.66 1069`

服务器程序会判断客户端发送的密文填充是否有效，如果有效，则提取解密的cookie信息，并判断其中的`"is_admin"`和`"exptime"`是否符合要求，如果满足要求，则打印flag值。因此本实验任务为构造合适的密文。

### Padding Oracle攻击

`nc 202.120.1.66 1069`连接到服务器，输入示例cookie，结果如下。

/img/posts/![image-20231231160545230](/img/posts/2024-1-1-Padding_Oracle.assets/image-20231231160545230.png)

可以利用Padding Oracle攻击修改密文。具体原理参考下图：

![image-20240101004911270](/img/posts/2024-1-1-Padding_Oracle.assets/image-20240101004911270.png)

实现python脚本：

```python
#!/usr/bin/python3
import socket
from binascii import hexlify, unhexlify
import time
import os

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

class PaddingOracle:

    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self.s.recv(1024)
        self.s.recv(25)
        ciphertext = self.s.recv(192).decode().strip()
        # print("sample_cookie: ", ciphertext[0:192])
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> None:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        tmp = self.s.recv(1024)
        resp = self.s.recv(15).decode().strip()
        return resp 

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()


if __name__ == "__main__":
    oracle = PaddingOracle('202.120.1.66', 1069)

    # Get the IV + Ciphertext from the oracle
    iv_and_ctext = bytearray(oracle.ctext)
    print(len(iv_and_ctext))
    # Num of ctext
    num = int(len(iv_and_ctext)/16 - 1)
    plain_text = ''
    fake_plain_text = bytearray('{"username": "User", "is_admin": "true", "expires": "2025-01-01"}', 'utf-8')
    fake_plain_text += b'\x0f'*15
    print(len(fake_plain_text))
    D_list = bytearray(len(iv_and_ctext))
    fake_C_list = bytearray(len(iv_and_ctext))
    fake_C_list[-16:] = iv_and_ctext[-16:]
    
    # get last run result
    flag = False
    if os.path.exists('fake_tmp.txt'):
        flag = True
        with open('fake_tmp.txt', 'r') as file:
            post_tmp_input = bytearray.fromhex(file.readline().strip())
            post_fake_C_list = bytearray.fromhex(file.readline().strip())
            post_D_list = bytearray.fromhex(file.readline().strip())
            post_D = bytearray.fromhex(file.readline().strip())
            post_CC = bytearray.fromhex(file.readline().strip())
            post_P = bytearray.fromhex(file.readline().strip())
            post_plain_text = str(file.readline()).rstrip("\n")
            
            post_n = int(file.readline())
            post_K = int(file.readline())
            post_i = int(file.readline())
    for n in range(num):
        
        C = iv_and_ctext[(num-n)*16: (num-n+1)*16]
        if n == num:
            print(f"IV:  " + C.hex())
        else:
            print(f"C{num-n}: " + C.hex())
        
        if flag == True:
            if n < post_n:
                continue
    
        # initialize D, IV, P
        D = bytearray(16)
        CC = bytearray(16)
        P = bytearray(16)

        # Solve D
        for K in range(1, 17):
            if flag == True:
                if K < post_K:
                    continue
            for i in range(256):
                if flag == True:
                    if i < post_i:
                        continue
                    elif i == post_i:
                        flag = False
                        CC = post_CC
                        D = post_D
                        P = post_P
                        D_list = post_D_list
                        plain_text = post_plain_text
                        D_list = post_D_list
                        fake_C_list = post_fake_C_list
                        
                print(f"processing: {num-n}-{K}-{i+1}/{num}-{16}-{256}")
                CC[16 - K] = i
                # initialize input
                tmp_input = iv_and_ctext[0:(num+1-n)*16]
                tmp_input[(num-1 - n)*16:(num - n)*16] = CC
                

                status = oracle.decrypt(tmp_input)
                oracle = PaddingOracle('202.120.1.66', 1069)
                if i == 0:
                    
                    # save to file
                    with open(f'fake_tmp{num-n}-{K}.txt', 'w') as file:
                        file.write(tmp_input.hex() + '\n')
                        file.write(fake_C_list.hex() + '\n')
                        file.write(D_list.hex() + '\n')
                        file.write(D.hex() + '\n')
                        file.write(CC.hex() + '\n')
                        file.write(P.hex() + '\n')
                    
                        file.write(str(plain_text) + '\n')
                        file.write(str(n) + '\n')
                        file.write(str(K) + '\n')
                        file.write(str(i) + '\n')

                if status != "invalid padding":
                    print("status: ", status)
                    print("Valid: i = 0x{:02x}".format(i))
                    print("D: "+ D.hex())
                    print("CC: " + CC.hex())
                    
                    
                    # Update D
                    D[16 - K] = i^K
                    # Update CC
                    for j in range(1, K+1):
                        CC[16 - j] = D[16 - j]^(K+1)
                    
                    break
                if i == 255:
                    print("ERROR")
                    exit(0)
     
        # Once you get all the 16 bytes of D, you can easily get P
        fake_P = fake_plain_text[(num-n-1)*16:(num-n)*16]
        fake_CC = xor(fake_P, D)
        fake_C_list[(num-n-1)*16: (num-n)*16] = fake_CC 
        iv_and_ctext[(num-n-1)*16: (num-n)*16] = fake_CC 
        
        P = xor(C, D)
        D_list[(num-n)*16:(num-n+1)*16] = D
        print("P:  " + P.hex())
        print("fake_P: ", fake_P)
        print("fake_CC: ", fake_CC)
        print("fake_C_list: ", fake_C_list.hex())
        print("iv_and_ctext: ", iv_and_ctext.hex())
        
        tmp_text = ''
        for j in range(len(fake_P)):
            print(len(fake_P))
            tmp_text += chr(fake_P[j])
        plain_text = tmp_text+plain_text
       
    print("Plaintext: " + plain_text)
    plain_text = bytearray(plain_text, 'utf-8')

```

将原来的example_cookie修改为满足要求的fake_cookie，然后获取其对应的密文。

由于服务器不是很稳定，很容易卡住或崩溃，考虑将中间结果保存下来以备下次使用。

![image-20240101093325410](/img/posts/2024-1-1-Padding_Oracle.assets/image-20240101093325410.png)

获取到伪造密文：

```shell
8896dc585b850bee8da883eb5e042e27fbc364f7556876db74968ea8d15d9a162e74d20574276440c83266f33fb26c52dfe9c377028b821dcf098b7985db9f742b28724f9b02c8a53a925e0281e4ec7797430337b9187c93141d9ff994473d92
```

成功获取到 flag{0r4cl3s_c4n_l34k_ae6a}

![image-20240101093256130](/img/posts/2024-1-1-Padding_Oracle.assets/image-20240101093256130.png)