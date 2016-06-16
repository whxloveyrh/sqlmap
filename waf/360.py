#!/usr/bin/env python
#-*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "360 Web Application Firewall (360)"
#检测的方法都比较简单，都是查看返回的数据库中是否包含了某些特殊的特征字符
def detect(get_page):
    retval = False   #ret-->retrieve

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = re.search(r"wangzhan\.360\.cn", headers.get("X-Powered-By-360wzb", ""), re.I) is not None
        retval |= code == 493 and "/wzws-waf-cgi/" in (page or "")
        if retval:
            break

    return retval
