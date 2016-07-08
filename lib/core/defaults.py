#!/usr/bin/env python
#-*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.datatype import AttribDict

_defaults = {
   "csvDel":       ",",
   "timeSec":      5,
   "googlePage":   1,
   "verbose":      1,  #信息显示等级，默认等级为1
   "delay":        0,
   "timeout":      30,
   "retries":      3,
   "saFreq":       0,
   "threads":      1,
   "level":        1,
   "risk":         1,
   "dumpFormat":   "CSV",
   "tech":         "BEUSTQ",
   "torType":      "HTTP",
}

defaults = AttribDict(_defaults)
