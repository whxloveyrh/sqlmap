#!/usr/bin/env python
#-*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os

from xml.etree import ElementTree as et

from lib.core.common import getSafeExString
from lib.core.data import conf
from lib.core.data import paths
from lib.core.datatype import AttribDict
from lib.core.exception import SqlmapInstallationException

def cleanupVals(text, tag):
    if tag in ("clause", "where"):
        text = text.split(',')

    if isinstance(text, basestring):
        text = int(text) if text.isdigit() else text

    elif isinstance(text, list):
        count = 0

        for _ in text:
            text[count] = int(_) if _.isdigit() else _
            count += 1

        if len(text) == 1 and tag not in ("clause", "where"):
            text = text[0]

    return text

def parseXmlNode(node):
    #读取xml/boundaries.xml中所有的boundary节点信息
    for element in node.getiterator('boundary'):
        boundary = AttribDict() #创建一个局部字典类型的变量boundary

        #读取boundary节点下面的子节点信息
        for child in element.getchildren():
            if child.text:
                values = cleanupVals(child.text, child.tag)
                boundary[child.tag] = values
            else:
                boundary[child.tag] = None

        conf.boundaries.append(boundary)

    #读取xml/payloads/*下面文件中每一个test节点
    for element in node.getiterator('test'):
        test = AttribDict() #创建一个字典类型的节点元素

        for child in element.getchildren():
            '''
            strip()函数原型  http://www.jb51.net/article/37287.htm
            声明：s为字符串，rm为要删除的字符序列
            s.strip(rm)        删除s字符串中开头、结尾处，位于 rm删除序列的字符
            s.lstrip(rm)       删除s字符串中开头处，位于 rm删除序列的字符
            s.rstrip(rm)       删除s字符串中结尾处，位于 rm删除序列的字符
            注意：
            1. 当rm为空时，默认删除空白符（包括'\n', '\r',  '\t',  ' ')
            2.这里的rm删除序列是只要边（开头或结尾）上的字符在删除序列内，就删除掉。
            '''
            if child.text and child.text.strip():
                values = cleanupVals(child.text, child.tag)
                test[child.tag] = values
            else:
                if len(child.getchildren()) == 0:
                    test[child.tag] = None
                    continue
                else:
                    test[child.tag] = AttribDict()

                #存在二级子节点元素信息
                for gchild in child.getchildren():
                    if gchild.tag in test[child.tag]:
                        prevtext = test[child.tag][gchild.tag]
                        test[child.tag][gchild.tag] = [prevtext, gchild.text]
                    else:
                        test[child.tag][gchild.tag] = gchild.text

        conf.tests.append(test)
#导入boundaries.xml文件
def loadBoundaries():
    try:
        doc = et.parse(paths.BOUNDARIES_XML)
    except Exception, ex:
        errMsg = "something appears to be wrong with "
        errMsg += "the file '%s' ('%s'). Please make " % (paths.BOUNDARIES_XML, getSafeExString(ex))
        errMsg += "sure that you haven't made any changes to it"
        raise SqlmapInstallationException, errMsg

    root = doc.getroot()
    parseXmlNode(root)
#导入payloads下面所有的文件
def loadPayloads():
    payloadFiles = os.listdir(paths.SQLMAP_XML_PAYLOADS_PATH)
    payloadFiles.sort()

    for payloadFile in payloadFiles:
        payloadFilePath = os.path.join(paths.SQLMAP_XML_PAYLOADS_PATH, payloadFile)

        try:
            doc = et.parse(payloadFilePath)
        except Exception, ex:
            errMsg = "something appears to be wrong with "
            errMsg += "the file '%s' ('%s'). Please make " % (payloadFilePath, getSafeExString(ex))
            errMsg += "sure that you haven't made any changes to it"
            raise SqlmapInstallationException, errMsg

        root = doc.getroot()
        parseXmlNode(root)
