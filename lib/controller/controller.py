#!/usr/bin/env python
#-*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re

from lib.controller.action import action
from lib.controller.checks import checkSqlInjection
from lib.controller.checks import checkDynParam
from lib.controller.checks import checkStability
from lib.controller.checks import checkString
from lib.controller.checks import checkRegexp
from lib.controller.checks import checkConnection
from lib.controller.checks import checkNullConnection
from lib.controller.checks import checkWaf
from lib.controller.checks import heuristicCheckSqlInjection
from lib.controller.checks import identifyWaf
from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import getFilteredPageContent
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import intersect
from lib.core.common import isListLike
from lib.core.common import parseTargetUrl
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import safeCSValue
from lib.core.common import showHttpErrorCodes
from lib.core.common import urlencode
from lib.core.common import urldecode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CONTENT_TYPE
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NOTE
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapValueException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import ASP_NET_CONTROL_REGEX
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import EMPTY_FORM_FIELDS_REGEX
from lib.core.settings import IGNORE_PARAMETERS
from lib.core.settings import LOW_TEXT_PERCENT
from lib.core.settings import GOOGLE_ANALYTICS_COOKIE_PREFIX
from lib.core.settings import HOST_ALIASES
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.target import initTargetEnv
from lib.core.target import setupTargetEnv
from thirdparty.pagerank.pagerank import get_pagerank


def _selectInjection():
    """
    Selection function for injection place, parameters and type.
    """

    points = {}

    for injection in kb.injections:
        place = injection.place
        parameter = injection.parameter
        ptype = injection.ptype

        point = (place, parameter, ptype)

        if point not in points:
            points[point] = injection
        else:
            for key in points[point].keys():
                if key != 'data':
                    points[point][key] = points[point][key] or injection[key]
            points[point]['data'].update(injection['data'])

    if len(points) == 1:
        kb.injection = kb.injections[0]

    elif len(points) > 1:
        message = "there were multiple injection points, please select "
        message += "the one to use for following injections:\n"

        points = []

        for i in xrange(0, len(kb.injections)):
            place = kb.injections[i].place
            parameter = kb.injections[i].parameter
            ptype = kb.injections[i].ptype
            point = (place, parameter, ptype)

            if point not in points:
                points.append(point)
                ptype = PAYLOAD.PARAMETER[ptype] if isinstance(ptype, int) else ptype

                message += "[%d] place: %s, parameter: " % (i, place)
                message += "%s, type: %s" % (parameter, ptype)

                if i == 0:
                    message += " (default)"

                message += "\n"

        message += "[q] Quit"
        select = readInput(message, default="0")

        if select.isdigit() and int(select) < len(kb.injections) and int(select) >= 0:
            index = int(select)
        elif select[0] in ("Q", "q"):
            raise SqlmapUserQuitException
        else:
            errMsg = "invalid choice"
            raise SqlmapValueException(errMsg)

        kb.injection = kb.injections[index]


def _formatInjection(inj):
    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else inj.place
    data = "Parameter: %s (%s)\n" % (inj.parameter, paramType)

    for stype, sdata in inj.data.items():
        title = sdata.title
        vector = sdata.vector
        comment = sdata.comment
        payload = agent.adjustLateValues(sdata.payload)
        if inj.place == PLACE.CUSTOM_HEADER:
            payload = payload.split(',', 1)[1]
        if stype == PAYLOAD.TECHNIQUE.UNION:
            count = re.sub(r"(?i)(\(.+\))|(\blimit[^A-Za-z]+)", "", sdata.payload).count(',') + 1
            title = re.sub(r"\d+ to \d+", str(count), title)
            vector = agent.forgeUnionQuery("[QUERY]", vector[0], vector[1], vector[2], None, None, vector[5], vector[6])
            if count == 1:
                title = title.replace("columns", "column")
        elif comment:
            vector = "%s%s" % (vector, comment)
        data += "    Type: %s\n" % PAYLOAD.SQLINJECTION[stype]
        data += "    Title: %s\n" % title
        data += "    Payload: %s\n" % urldecode(payload, unsafe="&", plusspace=(inj.place != PLACE.GET and kb.postSpaceToPlus))
        data += "    Vector: %s\n\n" % vector if conf.verbose > 1 else "\n"

    return data


def _showInjections():
    if kb.testQueryCount > 0:
        header = "sqlmap identified the following injection point(s) with "
        header += "a total of %d HTTP(s) requests" % kb.testQueryCount
    else:
        header = "sqlmap resumed the following injection point(s) from stored session"

    if hasattr(conf, "api"):
        conf.dumper.string("", kb.injections, content_type=CONTENT_TYPE.TECHNIQUES)
    else:
        data = "".join(set(map(lambda x: _formatInjection(x), kb.injections))).rstrip("\n")
        conf.dumper.string(header, data)

    if conf.tamper:
        warnMsg = "changes made by tampering scripts are not "
        warnMsg += "included in shown payload content(s)"
        logger.warn(warnMsg)

    if conf.hpp:
        warnMsg = "changes made by HTTP parameter pollution are not "
        warnMsg += "included in shown payload content(s)"
        logger.warn(warnMsg)


def _randomFillBlankFields(value):
    retVal = value

    if extractRegexResult(EMPTY_FORM_FIELDS_REGEX, value):
        message = "do you want to fill blank fields with random values? [Y/n] "
        test = readInput(message, default="Y")
        if not test or test[0] in ("y", "Y"):
            for match in re.finditer(EMPTY_FORM_FIELDS_REGEX, retVal):
                item = match.group("result")
                if not any(_ in item for _ in IGNORE_PARAMETERS) and not re.search(ASP_NET_CONTROL_REGEX, item):
                    if item[-1] == DEFAULT_GET_POST_DELIMITER:
                        retVal = retVal.replace(item, "%s%s%s" % (item[:-1], randomStr(), DEFAULT_GET_POST_DELIMITER))
                    else:
                        retVal = retVal.replace(item, "%s%s" % (item, randomStr()))

    return retVal


def _saveToHashDB():
    injections = hashDBRetrieve(HASHDB_KEYS.KB_INJECTIONS, True)
    if not isListLike(injections):
        injections = []
    injections.extend(_ for _ in kb.injections if _ and _.place is not None and _.parameter is not None)

    _ = dict()
    for injection in injections:
        key = (injection.place, injection.parameter, injection.ptype)
        if key not in _:
            _[key] = injection
        else:
            _[key].data.update(injection.data)
    hashDBWrite(HASHDB_KEYS.KB_INJECTIONS, _.values(), True)

    _ = hashDBRetrieve(HASHDB_KEYS.KB_ABS_FILE_PATHS, True)
    hashDBWrite(HASHDB_KEYS.KB_ABS_FILE_PATHS, kb.absFilePaths | (_ if isinstance(_, set) else set()), True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_CHARS):
        hashDBWrite(HASHDB_KEYS.KB_CHARS, kb.chars, True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_DYNAMIC_MARKINGS):
        hashDBWrite(HASHDB_KEYS.KB_DYNAMIC_MARKINGS, kb.dynamicMarkings, True)


def _saveToResultsFile():
    if not conf.resultsFP:
        return

    results = {}
    techniques = dict(map(lambda x: (x[1], x[0]), getPublicTypeMembers(PAYLOAD.TECHNIQUE)))

    for injection in kb.injections + kb.falsePositives:
        if injection.place is None or injection.parameter is None:
            continue

        key = (injection.place, injection.parameter, ';'.join(injection.notes))
        if key not in results:
            results[key] = []

        results[key].extend(injection.data.keys())

    for key, value in results.items():
        place, parameter, notes = key
        line = "%s,%s,%s,%s,%s%s" % (safeCSValue(kb.originalUrls.get(conf.url) or conf.url), place, parameter, "".join(map(lambda x: techniques[x][0].upper(), sorted(value))), notes, os.linesep)
        conf.resultsFP.writelines(line)

    if not results:
        line = "%s,,,,%s" % (conf.url, os.linesep)
        conf.resultsFP.writelines(line)


def start():
    """
    This function calls a function that performs checks on both URL
    stability and all GET, POST, Cookie and User-Agent parameters to
    check if they are dynamic and SQL injection affected
    """

    '''
    conf.direct是通过命令行参数："-d"指定的。
    通过参数"-d"指定要连接的数据库
    eg：-d "mysql:123123//root:@127.0.0.1:3306/security"
    '''
    if conf.direct:         # 调用时，使用了-d选项,那么sqlmap就会会直接进入action()函数中，连接数据库
        '''
        for example: python sqlmap.py -d "mysql://admin:admin@192.168.75.128:3306/testdb" -f --banner --dbs --user
        '''
        initTargetEnv()     # 函数主要就是完成全局变量conf和kb的初始化工作
        '''
        setupTargetEnv()
        该函数主要包含3个子功能：
        1.创建保存目标执行结果的目录和文件
        2.将get或post发送的数据解析成字典形式，并保存到conf.paramDict中
        3.读取session文件（如果存在的话），并提起文件中的数据，保存到kb变量中
        '''
        setupTargetEnv()
        '''
        action()是很重要的一个函数，该函数主要根据工程师的命令行参数选型，从而利用存在注入漏洞的url，以进一步获取工程师要获取的数据。
        比如：当前的数据库用户、枚举数据库的所有数据表等等
        '''
        action()
        return True

    if conf.url and not any((conf.forms, conf.crawlDepth)):
        '''
        将url,method,data,cookie等信息添加到kb.targets对象上
        '''
        kb.targets.add((conf.url, conf.method, conf.data, conf.cookie, None))

    if conf.configFile and not kb.targets:
        errMsg = "you did not edit the configuration file properly, set "
        errMsg += "the target URL, list of targets or google dork"
        logger.error(errMsg)
        return False

    if kb.targets and len(kb.targets) > 1:  # 需要测试多个目标URL
        infoMsg = "sqlmap got a total of %d targets" % len(kb.targets)
        logger.info(infoMsg)

    hostCount = 0
    initialHeaders = list(conf.httpHeaders)

    for targetUrl, targetMethod, targetData, targetCookie, targetHeaders in kb.targets:
        try:    # 开始检测
            conf.url = targetUrl                                                    # -u or --url 测试的目标URL
            conf.method = targetMethod.upper() if targetMethod else targetMethod    # --method 参数，默认情况下，sqlmap是自动检测，只有当需要检查的方法是put的时候，需要显示指定 --method=PUT
            conf.data = targetData                                                  # --data 参数，此参数是把数据以POST方式提交，sqlmap会像检测GET参数一样检测POST的参数。详细查看readme.pdf  28pages
            conf.cookie = targetCookie                                              # --cookie 参数， 当你使用--cookie参数时，当返回一个Set-Cookie头的时候，sqlmap会询问你用哪个cookie来继续接下来的请求。当--level的参数设定为2或者2以上的时候，sqlmap会尝试注入Cookie参数。
            conf.httpHeaders = list(initialHeaders)                                 # 参数：--headers  可以通过--headers参数来增加额外的http头
            conf.httpHeaders.extend(targetHeaders or [])

            initTargetEnv()     # 主要就是完成全局变量conf和kb的初始化工作
            parseTargetUrl()    # 主要完成针对目标网址的解析工作，如获取协议名、路径、端口、请求参数等信息

            testSqlInj = False  # 表示是否注入过，默认表示注入过(即testSqlInj=false)

            '''
            conf.parameters保存需要进行SQL注入点测试的参数信息，conf.parameters是一个字典
            kb.testedParams保存已经测试了的参数信息
            测试过的url参数信息会保存到kb.testedParams中（第230行和第259行），所以在进行test之前，会先判断当前的url是否已经test过
            如果没test过的话，则testSqlInj = True，否则testSqlInj = False。
            当testSqlInj = False的时候，表示当前需要进行测试的URL已经测试过了，就不会执行 injection = checkSqlInjection(place, parameter, value)这句代码了
            '''
            if PLACE.GET in conf.parameters and not any([conf.data, conf.testParameter]):
                for parameter in re.findall(r"([^=]+)=([^%s]+%s?|\Z)" % (re.escape(conf.paramDel or "") or DEFAULT_GET_POST_DELIMITER, re.escape(conf.paramDel or "") or DEFAULT_GET_POST_DELIMITER), conf.parameters[PLACE.GET]):
                    paramKey = (conf.hostname, conf.path, PLACE.GET, parameter[0])

                    if paramKey not in kb.testedParams:
                        testSqlInj = True
                        break
            else:
                paramKey = (conf.hostname, conf.path, None, None)  # 测试其他参数信息，判断是否存在注入信息
                if paramKey not in kb.testedParams:
                    testSqlInj = True

            if testSqlInj and conf.hostname in kb.vulnHosts:
                if kb.skipVulnHost is None:
                    message = "SQL injection vulnerability has already been detected "
                    message += "against '%s'. Do you want to skip " % conf.hostname
                    message += "further tests involving it? [Y/n]"
                    kb.skipVulnHost = readInput(message, default="Y").upper() != 'N'
                testSqlInj = not kb.skipVulnHost

            if not testSqlInj:          # 表示当前需要测试的URL已经测试过了，不需要进行测试了
                infoMsg = "skipping '%s'" % targetUrl
                logger.info(infoMsg)
                continue

            if conf.multipleTargets:    # 当检测的目标存在多个的时候
                hostCount += 1

                if conf.forms and conf.method:
                    message = "[#%d] form:\n%s %s" % (hostCount, conf.method, targetUrl)
                else:
                    message = "URL %d:\n%s %s%s" % (hostCount, HTTPMETHOD.GET, targetUrl, " (PageRank: %s)" % get_pagerank(targetUrl) if conf.googleDork and conf.pageRank else "")

                if conf.cookie:
                    message += "\nCookie: %s" % conf.cookie

                if conf.data is not None:
                    message += "\n%s data: %s" % ((conf.method if conf.method != HTTPMETHOD.GET else conf.method) or HTTPMETHOD.POST, urlencode(conf.data) if conf.data else "")

                if conf.forms and conf.method:
                    if conf.method == HTTPMETHOD.GET and targetUrl.find("?") == -1:
                        continue

                    message += "\ndo you want to test this form? [Y/n/q] "
                    test = readInput(message, default="Y")

                    if not test or test[0] in ("y", "Y"):
                        if conf.method != HTTPMETHOD.GET:
                            message = "Edit %s data [default: %s]%s: " % (conf.method, urlencode(conf.data) if conf.data else "None", " (Warning: blank fields detected)" if conf.data and extractRegexResult(EMPTY_FORM_FIELDS_REGEX, conf.data) else "")
                            conf.data = readInput(message, default=conf.data)
                            conf.data = _randomFillBlankFields(conf.data)
                            conf.data = urldecode(conf.data) if conf.data and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in conf.data else conf.data

                        else:
                            if targetUrl.find("?") > -1:
                                firstPart = targetUrl[:targetUrl.find("?")]
                                secondPart = targetUrl[targetUrl.find("?") + 1:]
                                message = "Edit GET data [default: %s]: " % secondPart
                                test = readInput(message, default=secondPart)
                                test = _randomFillBlankFields(test)
                                conf.url = "%s?%s" % (firstPart, test)

                        parseTargetUrl()  # parseTargetUrl()函数主要完成针对目标网址的解析工作，如获取协议名、路径、端口、请求参数等信息

                    elif test[0] in ("n", "N"):
                        continue
                    elif test[0] in ("q", "Q"):
                        break

                else:
                    message += "\ndo you want to test this URL? [Y/n/q]"
                    test = readInput(message, default="Y")

                    if not test or test[0] in ("y", "Y"):
                        pass
                    elif test[0] in ("n", "N"):
                        dataToStdout(os.linesep)
                        continue
                    elif test[0] in ("q", "Q"):
                        break

                    infoMsg = "testing URL '%s'" % targetUrl
                    logger.info(infoMsg)

            '''
            setupTargetEnv(),该函数主要包含3个子功能：
            1.创建保存目标执行结果的目录和文件
            2.将get或post发送的数据解析成字典形式，并保存到conf.paramDict中
            3.读取session文件（如果存在的话），并提起文件中的数据，保存到kb变量中
            '''
            setupTargetEnv()  # 设置目标系统的环境信息

            '''
            checkConnection()函数主要是判断目标URL是否能够正常连接
            '''
            if not checkConnection(suppressOutput=conf.forms) or not checkString() or not checkRegexp():
                continue

            # Determines if a web server is protected by an IPS (Intrusion Prevention System), IDS (Intrusion Detection System) or WAF (Web Application Firewall)
            checkWaf()   # 检测WAF(Web Application FireWall),检测方法是NMAP的http-waf-detect.nse，判断系统是否被防火墙所保护

            # conf.identifyWaf=True表示需要检测后台防火墙的类型,否则，表示不检测防火墙类型
            # 判断防火墙的类型
            if conf.identifyWaf:  # conf.identifyWaf表示sqlmap的参数 --identify-waf,如果指定了此参数，就会进入identifyWaf()函数中
                identifyWaf()     # 主要检测的WAF(防火墙)都在sqlmap的waf目录下面

            if conf.nullConnection:
                checkNullConnection()  # 空连接就是不用密码和用户名的IPC(Internet Process Connection) 连接，在Windows 下，它是用 Net 命令来实现的．

            if (len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None)) \
                and (kb.injection.place is None or kb.injection.parameter is None):

                if not any((conf.string, conf.notString, conf.regexp)) and PAYLOAD.TECHNIQUE.BOOLEAN in conf.tech:
                    # NOTE: this is not needed anymore, leaving only to display
                    # a warning message to the user in case the page is not stable
                    # 判断页面是否是稳定页面(何谓稳定页面--两次相同的URL请求，返回的页面信息没有发生变化，如新浪微博的页面就不是稳定的，因为每次刷新过后，页面的内容会发生变化)
                    checkStability()

                # Do a little prioritization reorder of a testable parameter list
                parameters = conf.parameters.keys()

                # Order of testing list (first to last) #测试注入点位置的几种情况
                orderList = (PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER, PLACE.URI, PLACE.POST, PLACE.GET)

                for place in orderList[::-1]:
                    if place in parameters:
                        parameters.remove(place)
                        parameters.insert(0, place)

                proceed = True
                '''
                开始测试参数是否可以注入(测试之前没有测试过的参数)
                测试GET参数，POST参数，HTTP Cookie参数，HTTP User-Agent头和HTTP Referer头来确认是否有SQL注入，
                它也可以指定用逗号分隔的列表的具体参数来测试。
                parameters存储GET/POST/HTTP Cookie/HTTP User-Agent header/HTTP Referer header等信息
                '''
                for place in parameters:  # 检测在哪些参数位置可以进行注入的
                    # Test User-Agent and Referer headers only if
                    # --level >= 3
                    skip = (place == PLACE.USER_AGENT and conf.level < 3)
                    skip |= (place == PLACE.REFERER and conf.level < 3)

                    # Test Host header only if
                    # --level >= 5
                    skip |= (place == PLACE.HOST and conf.level < 5)

                    # Test Cookie header only if --level >= 2
                    skip |= (place == PLACE.COOKIE and conf.level < 2)

                    skip |= (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.COOKIE and intersect(PLACE.COOKIE, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.HOST and intersect(PLACE.HOST, conf.skip, True) not in ([], None))

                    skip &= not (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.HOST and intersect(HOST_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.COOKIE and intersect((PLACE.COOKIE,), conf.testParameter, True))

                    if skip:
                        continue

                    if kb.testOnlyCustom and place not in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER):
                        continue

                    if place not in conf.paramDict:
                        continue

                    paramDict = conf.paramDict[place]

                    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

                    for parameter, value in paramDict.items():
                        if not proceed:
                            break

                        kb.vainRun = False
                        testSqlInj = True
                        paramKey = (conf.hostname, conf.path, place, parameter)

                        '''
                        kb.testedParams用于保存已经注入了的信息，例如：目标IP,请求路径，注入点位置信息等

                        '''
                        if paramKey in kb.testedParams:
                            testSqlInj = False

                            infoMsg = "skipping previously processed %s parameter '%s'" % (paramType, parameter)
                            logger.info(infoMsg)

                        elif parameter in conf.testParameter:
                            pass

                        elif parameter == conf.rParam:
                            testSqlInj = False

                            infoMsg = "skipping randomizing %s parameter '%s'" % (paramType, parameter)
                            logger.info(infoMsg)

                        elif parameter in conf.skip or kb.postHint and parameter.split(' ')[-1] in conf.skip:
                            testSqlInj = False

                            infoMsg = "skipping %s parameter '%s'" % (paramType, parameter)
                            logger.info(infoMsg)

                        elif parameter == conf.csrfToken:
                            testSqlInj = False

                            infoMsg = "skipping anti-CSRF token parameter '%s'" % parameter
                            logger.info(infoMsg)

                        # Ignore session-like parameters for --level < 4
                        elif conf.level < 4 and (parameter.upper() in IGNORE_PARAMETERS or parameter.upper().startswith(GOOGLE_ANALYTICS_COOKIE_PREFIX)):
                            testSqlInj = False

                            infoMsg = "ignoring %s parameter '%s'" % (paramType, parameter)
                            logger.info(infoMsg)

                        elif PAYLOAD.TECHNIQUE.BOOLEAN in conf.tech or conf.skipStatic:
                            '''
                            checkDynParam()函数会判断参数是否是动态的，比如index.php?id=1，通过更改id的值，如果参数id是动态的,则返回的页面会不相同，否则相同。
                            '''
                            check = checkDynParam(place, parameter, value)

                            if not check:
                                warnMsg = "%s parameter '%s' does not appear dynamic" % (paramType, parameter)
                                logger.warn(warnMsg)

                                if conf.skipStatic:
                                    infoMsg = "skipping static %s parameter '%s'" % (paramType, parameter)
                                    logger.info(infoMsg)

                                    testSqlInj = False
                            else:
                                infoMsg = "%s parameter '%s' is dynamic" % (paramType, parameter)
                                logger.info(infoMsg)

                        kb.testedParams.add(paramKey)

                        if testSqlInj:
                            try:
                                if place == PLACE.COOKIE:
                                    pushValue(kb.mergeCookies)
                                    kb.mergeCookies = False

                                '''
                                heuristicCheckSqlInjection()函数的主要作用可以分为以下几点:
                                1.数据库版本的识别。
                                2.绝对路径获取。
                                3.XSS的测试
                                参考网站地址：http://drops.wooyun.org/papers/10652
                                heuristic <basic> test shows that GET parameter
                                heuristic <XSS> test shows that GET parameter
                                '''
                                check = heuristicCheckSqlInjection(place, parameter)  #进行简单的测试，设置一个payload(攻击点代码)，然后解析请求结果

                                if check != HEURISTIC_TEST.POSITIVE:
                                    if conf.smart or (kb.ignoreCasted and check == HEURISTIC_TEST.CASTED):
                                        infoMsg = "skipping %s parameter '%s'" % (paramType, parameter)
                                        logger.info(infoMsg)
                                        continue

                                infoMsg = "testing for SQL injection on %s " % paramType
                                infoMsg += "parameter '%s'" % parameter
                                logger.info(infoMsg)

                                '''
                                在调用checkSqlInjection注入之前，就已经判断出数据库的类型了。
                                testSqlInj=true表示之前没有检测过，就会调用checkSqlInjection()函数
                                checkSqlInjection()函数才是真正开始测试的函数，传入的参数是注入方法名，参数名，参数值
                                '''

                                injection = checkSqlInjection(place, parameter, value)
                                proceed = not kb.endDetection
                                injectable = False

                                if getattr(injection, "place", None) is not None:
                                    if NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE in injection.notes:
                                        kb.falsePositives.append(injection)
                                    else:
                                        injectable = True

                                        kb.injections.append(injection)

                                        # In case when user wants to end detection phase (Ctrl+C)
                                        if not proceed:
                                            break

                                        msg = "%s parameter '%s' " % (injection.place, injection.parameter)
                                        msg += "is vulnerable. Do you want to keep testing the others (if any)? [y/N] "
                                        test = readInput(msg, default="N")

                                        if test[0] not in ("y", "Y"):
                                            proceed = False
                                            paramKey = (conf.hostname, conf.path, None, None)
                                            kb.testedParams.add(paramKey)

                                if not injectable:
                                    warnMsg = "%s parameter '%s' is not " % (paramType, parameter)
                                    warnMsg += "injectable"
                                    logger.warn(warnMsg)

                            finally:
                                if place == PLACE.COOKIE:
                                    kb.mergeCookies = popValue()

            if len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None):
                if kb.vainRun and not conf.multipleTargets:
                    errMsg = "no parameter(s) found for testing in the provided data "
                    errMsg += "(e.g. GET parameter 'id' in 'www.site.com/index.php?id=1')"
                    raise SqlmapNoneDataException(errMsg)
                else:
                    errMsg = "all tested parameters appear to be not injectable."

                    if conf.level < 5 or conf.risk < 3:
                        errMsg += " Try to increase '--level'/'--risk' values "
                        errMsg += "to perform more tests."

                    if isinstance(conf.tech, list) and len(conf.tech) < 5:
                        errMsg += " Rerun without providing the option '--technique'."

                    if not conf.textOnly and kb.originalPage:
                        percent = (100.0 * len(getFilteredPageContent(kb.originalPage)) / len(kb.originalPage))

                        if kb.dynamicMarkings:
                            errMsg += " You can give it a go with the switch '--text-only' "
                            errMsg += "if the target page has a low percentage "
                            errMsg += "of textual content (~%.2f%% of " % percent
                            errMsg += "page content is text)."
                        elif percent < LOW_TEXT_PERCENT and not kb.errorIsNone:
                            errMsg += " Please retry with the switch '--text-only' "
                            errMsg += "(along with --technique=BU) as this case "
                            errMsg += "looks like a perfect candidate "
                            errMsg += "(low textual content along with inability "
                            errMsg += "of comparison engine to detect at least "
                            errMsg += "one dynamic parameter)."

                    if kb.heuristicTest == HEURISTIC_TEST.POSITIVE:
                        errMsg += " As heuristic test turned out positive you are "
                        errMsg += "strongly advised to continue on with the tests. "
                        errMsg += "Please, consider usage of tampering scripts as "
                        errMsg += "your target might filter the queries."

                    if not conf.string and not conf.notString and not conf.regexp:
                        errMsg += " Also, you can try to rerun by providing "
                        errMsg += "either a valid value for option '--string' "
                        errMsg += "(or '--regexp')."
                    elif conf.string:
                        errMsg += " Also, you can try to rerun by providing a "
                        errMsg += "valid value for option '--string' as perhaps the string you "
                        errMsg += "have chosen does not match "
                        errMsg += "exclusively True responses."
                    elif conf.regexp:
                        errMsg += " Also, you can try to rerun by providing a "
                        errMsg += "valid value for option '--regexp' as perhaps the regular "
                        errMsg += "expression that you have chosen "
                        errMsg += "does not match exclusively True responses."

                    if not conf.tamper:
                        errMsg += " If you suspect that there is some kind of protection mechanism "
                        errMsg += "involved (e.g. WAF) maybe you could retry "
                        errMsg += "with an option '--tamper' (e.g. '--tamper=space2comment')"

                    raise SqlmapNotVulnerableException(errMsg.rstrip('.'))
            else:
                # Flush the flag
                kb.testMode = False

                '''
                这四个函数的作用就是保存结果保存结果、保存session、显示注入结果，包括类型，payload等。
                '''
                _saveToResultsFile()
                _saveToHashDB()
                _showInjections()
                _selectInjection()

            if kb.injection.place is not None and kb.injection.parameter is not None:
                if conf.multipleTargets:
                    message = "do you want to exploit this SQL injection? [Y/n] "
                    exploit = readInput(message, default="Y")

                    condition = not exploit or exploit[0] in ("y", "Y")
                else:
                    condition = True

                if condition:
                    action()

        except KeyboardInterrupt:
            if conf.multipleTargets:
                warnMsg = "user aborted in multiple target mode"
                logger.warn(warnMsg)

                message = "do you want to skip to the next target in list? [Y/n/q]"
                test = readInput(message, default="Y")

                if not test or test[0] in ("y", "Y"):
                    pass
                elif test[0] in ("n", "N"):
                    return False
                elif test[0] in ("q", "Q"):
                    raise SqlmapUserQuitException
            else:
                raise

        except SqlmapUserQuitException:
            raise

        except SqlmapSilentQuitException:
            raise

        except SqlmapBaseException, ex:
            errMsg = getSafeExString(ex)

            if conf.multipleTargets:
                _saveToResultsFile()

                errMsg += ", skipping to the next %s" % ("form" if conf.forms else "URL")
                logger.error(errMsg)
            else:
                logger.critical(errMsg)
                return False

        finally:
            showHttpErrorCodes()

            if kb.maxConnectionsFlag:
                warnMsg = "it appears that the target "
                warnMsg += "has a maximum connections "
                warnMsg += "constraint"
                logger.warn(warnMsg)

    if kb.dataOutputFlag and not conf.multipleTargets:
        logger.info("fetched data logged to text files under '%s'" % conf.outputPath)

    if conf.multipleTargets:
        if conf.resultsFilename:
            infoMsg = "you can find results of scanning in multiple targets "
            infoMsg += "mode inside the CSV file '%s'" % conf.resultsFilename
            logger.info(infoMsg)

    return True
