---
layout:     post   				    # 使用的布局（不需要改）
title:      Bochspwn学习		# 标题 
subtitle:   Eutopia's Blog #副标题
date:       2024-3-8				# 时间
author:     Eutopia 						# 作者
header-img: img/post-bg-8.png 	#这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								#标签
    - 论文复现
    - 内核
    - 条件竞争
---
# Bochspwn

## 目的

qiling为单线程的模拟，无法模拟并检测到内核中多线程由于条件竞争导致的内核漏洞。因此学习Bochspwn工具的使用，查看能否用于检测内核的多线程条件竞争的内核漏洞。

## 贡献

## 简介

Bochspwn是一个系统范围的工具，旨在记录操作系统内核执行的内存访问，并检查它们，以搜索提示存在某些漏洞的模式，比如“double fetch”。有关内存引用的信息是通过在Bochs IA-32仿真器中运行目标操作系统，在Windows内核中发现了超过50个竞争条件类的漏洞。