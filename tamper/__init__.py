#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""
'''
参考网址:http://drops.wooyun.org/tools/4760
第一：tamper脚本是什么时候被sqlmap载入的；
main()->init()->_setTamperingFunctions()
第二：tamper脚本是什么时候被sqlmap调用的；
tamper脚本在queryPage函数中被调用，queryPage函数是用来请求页面内容，在每次发送请求之前，先会将payload进行tamper函数处理。
第三：tamper脚本的里的内容有什么样的规范；
'''
pass
