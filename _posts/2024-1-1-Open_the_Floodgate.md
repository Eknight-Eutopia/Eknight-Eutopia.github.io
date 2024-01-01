---
layout:     post   				    # 使用的布局（不需要改）
title:      【网络攻防大作业】Open_the_Floodgate实验报告 				# 标题 
subtitle:   Eutopia's Blog #副标题
date:       2024-1-1				# 时间
author:     Eutopia 						# 作者
header-img: img/post-bg-1.png 	#这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								#标签
    - 网络
    - 流量监测
    - wireshark

---



## Open_the_Floodgate WriteUp

### 1. 环境搭建

修改Flag为学号

运行docker程序`sudo ./dockerHelper.sh -k`（注：需要`chmod +x`修改脚本的权限），访问http://127.0.0.1:3580/，界面如下

![image-20231231132934965](2024-1-1-Open_the_Floodgate.assets/image-20231231132934965.png)

### 2.流量监测

执行curl.sh脚本，curl.sh脚本如下：可以看到对web网页的多个网址进行扫描。

![image-20231231133331947](/img/posts/2024-1-1-Open_the_Floodgate.assets/image-20231231133331947.png)

抓取数据包如下：

![image-20231231133241999](/img/posts/2024-1-1-Open_the_Floodgate.assets/image-20231231133241999.png)

### 3. WriteUp

查看数据包中web端对用户的request请求回复内容：

```shell
curl http://127.0.0.1:3580/
<h1><center><a href='https://en.wikipedia.org/wiki/Packet_analyzer' target='_blank'>Packet Analyzer</a></center></h1><h1><center>

curl http://127.0.0.1:3580/flag
<h1><center>The flag is: kM:juSh4/QnGJ0
</center></h1>

curl http://127.0.0.1:3580/apple
<h1><center>Welcome to apple</center></h1>

curl http://127.0.0.1:3580/flag
<h1><center>The flag is: );n#Mhrb]x'i~D </center></h1>

curl http://127.0.0.1:3580/flag
<h1><center>The flag is: BmkX'Z]vq7A/;d'n<</center></h1>

curl http://127.0.0.1:3580/book
<h1><center>Welcome to book</center></h1><h1><center><a href='https://en.wikipedia.org/wiki/User_Datagram_Protocol#Comparison_of_UDP_and_TCP' target='_blank'>UDP vs. TCP</a></center></h1>

curl http://127.0.0.1:3580/capture
<h1><center><a href='https://en.wikipedia.org/wiki/User_Datagram_Protocol#Comparison_of_UDP_and_TCP' target='_blank'>UDP vs. TCP</a></center></h1>[12/31/23]

curl http://127.0.0.1:3580/sniff
<h1><center><a href='https://datatracker.ietf.org/doc/html/rfc1035' target='_blank'>RFC 1035</a></center></h1>[12/31/23]

curl http://127.0.0.1:3580/flag
<h1><center>The flag is: R>`D,j&D</center></h1>[12/31/23]

curl http://127.0.0.1:3580/code
<h1><center>Welcome to code</center></h1>[12/31/23]
```

发现`curl http://127.0.0.1:3580/flag`的结果为随机值，查看flaskweb端处理源码，发现确实是随机值，

![image-20231231142741985](/img/posts/2024-1-1-Open_the_Floodgate.assets/image-20231231142741985.png)

真实flag处理逻辑如下：

![image-20231231142809244](/img/posts/2024-1-1-Open_the_Floodgate.assets/image-20231231142809244.png)

![image-20231231142754937](/img/posts/2024-1-1-Open_the_Floodgate.assets/image-20231231142754937.png)

可以看出为访问`/capture`url后调用`flood_http`函数，其中会随机出现flag值，其余值均为`123456789012`

因此访问`/capture`后过滤udp协议并且过滤掉为`123456789012`的包。结果如下，成功获取flag。

![image-20231231142616792](/img/posts/2024-1-1-Open_the_Floodgate.assets/image-20231231142616792.png)



